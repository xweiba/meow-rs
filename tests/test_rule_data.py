#!/usr/bin/env python3
"""Opt-in native data/profile workflow, without TUN or a Flutter process.

Runs a real core and local HTTP origin in a temporary directory. Covers
checked replacement, source fallback, duplicate/manual updates, invalid
profile retention, save/apply/read-back and updates surviving client close.
"""
import argparse
import copy
import http.server
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


def mmdb(country):
    def text(value):
        value = value.encode()
        return bytes([0x40 | len(value)]) + value
    out = b'\0\0\x11\0\0\x01' + bytes(16)
    out += b'\xe1' + text('country') + b'\xe1' + text('iso_code') + text(country)
    out += b'\xab\xcd\xefMaxMind.com\xe9'
    for key, value in [
        ('node_count', b'\xc1\x01'), ('record_size', b'\xa1\x18'),
        ('ip_version', b'\xa1\x04'), ('database_type', text('Test')),
        ('languages', b'\0\x04'), ('binary_format_major_version', b'\xa1\x02'),
        ('binary_format_minor_version', b'\xa0'), ('build_epoch', b'\x01\x02\x01'),
        ('description', b'\xe0'),
    ]:
        out += text(key) + value
    return out


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Origin(http.server.ThreadingHTTPServer):
    daemon_threads = True
    body = mmdb('XX')
    delay = 0
    requests = []


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        if self.path == '/missing':
            self.send_error(404)
            return
        time.sleep(self.server.delay)
        self.send_response(200)
        self.send_header('Content-Length', str(len(self.server.body)))
        self.end_headers()
        try:
            self.wfile.write(self.server.body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_):
        pass


def wait(check, seconds=30):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        try:
            value = check()
            if value:
                return value
        except (OSError, ValueError, urllib.error.HTTPError):
            pass
        time.sleep(.05)
    raise AssertionError('workflow timed out')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('core', type=Path)
    args = parser.parse_args()
    core = args.core.resolve()
    root = Path(__file__).resolve().parents[1]
    origin = Origin(('127.0.0.1', 0), Handler)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='meow-rule-data-') as temporary:
            data = Path(temporary)
            api, mixed = port(), port()
            base = f'http://127.0.0.1:{origin.server_port}'
            profile = json.loads((root/'crates/meow-paopao/defaults/routing-rules.json').read_text())
            profile['geodata'] = {
                'background-fetch': True, 'auto-update': False, 'proxy': 'DIRECT',
                'mmdb-path': str(data/'country.mmdb'), 'asn-path': str(data/'asn.mmdb'),
                'geosite-path': str(data/'geosite.dat'),
                'url': {'mmdb': base+'/data', 'asn': base+'/missing', 'geosite': base+'/missing'},
            }
            # All routing data still comes from the profile, but this test
            # has no reason to download full rule/GeoSite payloads.
            profile['policies'] = []
            profile['privateSites'] = []
            profile['ruleProviders'] = {}
            profile_file = data/'routing-rules.json'
            profile_file.write_text(json.dumps(profile))
            config = {
                'external-controller': f'127.0.0.1:{api}', 'secret': 'test-rule-data',
                'mixed-port': mixed, 'mode': 'rule', 'log-level': 'warning',
                'geodata': profile['geodata'], 'rules': ['MATCH,DIRECT'],
                'dns': {'enable': False},
            }
            config_file = data/'config.json'
            config_file.write_text(json.dumps(config))

            def call(path, body=None, method=None, expected=200):
                request = urllib.request.Request(f'http://127.0.0.1:{api}'+path,
                    data=None if body is None else json.dumps(body).encode(), method=method,
                    headers={'Authorization': 'Bearer test-rule-data', 'Content-Type': 'application/json'})
                try:
                    response = urllib.request.urlopen(request, timeout=30)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    raw = response.read()
                    assert response.code == expected, (path, response.code, raw[:250])
                    return json.loads(raw) if raw else None

            with (data/'core.log').open('wb') as log:
                process = subprocess.Popen([str(core), '-f', str(config_file), '-d', str(data)],
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                try:
                    wait(lambda: call('/version'))
                    assert call('/connections/history')['limit'] == 1500
                    call('/connections/history', {'limit': 7}, 'PUT', expected=204)
                    # Real successful proxied transfers must obey the cap even
                    # inside a recent burst (the old implementation kept 6x).
                    for n in range(27):
                        with socket.create_connection(('127.0.0.1', mixed)) as sock:
                            sock.settimeout(10)
                            sock.sendall(f'GET {base}/history-{n} HTTP/1.1\r\n'
                                'Host: localhost\r\nConnection: close\r\n\r\n'.encode())
                            response = bytearray()
                            while chunk := sock.recv(65536):
                                response.extend(chunk)
                            assert b'200 OK' in response
                        wait(lambda: len(call('/connections')['connections']) == 0)
                    history = call('/connections/history')
                    assert len(history['kept']) == len(history['changed']) == 7, history
                    # A live SOCKS flow belongs to the active registry; disabling
                    # history must not close it to make room for ended records.
                    with socket.create_connection(('127.0.0.1', mixed)) as sock:
                        sock.settimeout(10)
                        sock.sendall(b'\x05\x01\x00')
                        assert sock.recv(2) == b'\x05\x00'
                        sock.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'
                            + origin.server_port.to_bytes(2, 'big'))
                        assert sock.recv(32)[:2] == b'\x05\x00'
                        wait(lambda: len(call('/connections')['connections']) == 1)
                        call('/connections/history', {'limit': 0}, 'PUT', expected=204)
                        assert call('/connections/history')['kept'] == []
                        assert len(call('/connections')['connections']) == 1
                    call('/connections/history', {'limit': 1500}, 'PUT', expected=204)
                    print('PASS default 1500, strict live history cap and active-flow isolation', flush=True)
                    status = call('/rule-data')
                    assert len(status['geodata']['resources']) == 3
                    assert all(r['nextUpdate'] is None for r in status['geodata']['resources'])
                    result = call('/rule-data/update', {'id': 'mmdb'})
                    assert result['updated'] == ['mmdb'], result
                    assert (data/'country.mmdb').read_bytes() == mmdb('XX')

                    origin.body = b'<html>captive portal</html>'
                    result = call('/rule-data/update', {'id': 'mmdb'})
                    assert result['updated'] == [] and 'mmdb' in result['errors']
                    assert (data/'country.mmdb').read_bytes() == mmdb('XX')
                    print('PASS checked native update and failed refresh retain last good bytes', flush=True)

                    # Hand the resident core the same builder contract the
                    # app uses; it owns all subsequent work without Flutter.
                    fixture = {
                        'subscriptions': [], 'settings': {'tun': False},
                        'runtime': {'rulesFile': str(profile_file), 'controllerPort': api},
                    }
                    call('/paopao/input', fixture, 'PUT')
                    assert call('/paopao/rule-profile') == profile
                    previous = profile_file.read_bytes()
                    invalid = copy.deepcopy(profile)
                    invalid['version'] = 999
                    call('/paopao/rule-profile', invalid, 'PUT', expected=400)
                    assert profile_file.read_bytes() == previous
                    bad_geo = copy.deepcopy(profile)
                    bad_geo['geodata']['auto-update-interval'] = 0
                    call('/paopao/rule-profile', bad_geo, 'PUT', expected=400)
                    assert profile_file.read_bytes() == previous
                    print('PASS invalid profile/source settings do not replace file or live config', flush=True)

                    profile['geodata']['auto-update-interval'] = 12
                    profile['geodata']['url']['mmdb'] = base+'/missing'
                    profile['geodata']['sources'] = {'mmdb': [base+'/data']}
                    saved = call('/paopao/rule-profile', profile, 'PUT')
                    assert saved['reloaded'], saved
                    assert call('/paopao/rule-profile') == profile
                    assert call('/rule-data')['geodata']['intervalHours'] == 12
                    origin.body = mmdb('YY')
                    origin.requests.clear()
                    result = call('/rule-data/update', {'id': 'mmdb'})
                    assert result['updated'] == ['mmdb'], result
                    assert origin.requests[:2] == ['/missing', '/data'], origin.requests
                    assert (data/'country.mmdb').read_bytes() == mmdb('YY')
                    print('PASS profile save applies and source fallback is ordered', flush=True)

                    origin.delay = 1
                    origin.body = mmdb('ZZ')
                    # Disconnect after sending the request: owned native job
                    # must continue rather than being tied to a UI client.
                    body = b'{"id":"mmdb"}'
                    with socket.create_connection(('127.0.0.1', api)) as sock:
                        sock.sendall(b'POST /rule-data/update HTTP/1.1\r\nHost: localhost\r\n'
                            b'Authorization: Bearer test-rule-data\r\nContent-Type: application/json\r\n'
                            b'Content-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
                        wait(lambda: any(r['updating'] for r in call('/rule-data')['geodata']['resources']))
                        call('/rule-data/update', {'id': 'mmdb'}, expected=409)
                    wait(lambda: (data/'country.mmdb').read_bytes() == mmdb('ZZ'))
                    assert process.poll() is None
                    print('PASS concurrent job refused; disconnected client does not stop native update', flush=True)
                    print('PASS no core restart, TUN, system proxy, or Flutter process required', flush=True)
                except Exception:
                    print((data/'core.log').read_text(errors='replace')[-4000:])
                    raise
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    finally:
        origin.shutdown()
        origin.server_close()


if __name__ == '__main__':
    main()
