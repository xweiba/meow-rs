#!/usr/bin/env python3
"""Opt-in desktop workflow: DIRECT uses NIC DNS; main resolver stays separate.

Run with no other TUN/DNS interception active. Uses a temporary proxy port,
an intentionally wrong local main DNS server, and real domestic HTTPS/DNS.
No system settings or user profile are modified. Only its own core is stopped.
"""
import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time


def dns_wire(name):
    return struct.pack('!6H', 1234, 0x100, 1, 0, 0, 0) + b''.join(
        bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0\0\1\0\1'


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def recv_exact(s, n):
    out = b''
    while len(out) < n:
        part = s.recv(n-len(out))
        assert part, 'SOCKS closed early'
        out += part
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('core')
    args = parser.parse_args()
    core_path = str(Path(args.core).resolve())
    main_dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    main_dns.bind(('127.0.0.1', 0))
    main_dns.settimeout(.2)
    queries = []
    stop = threading.Event()

    def upstream():
        while not stop.is_set():
            try:
                wire, peer = main_dns.recvfrom(4096)
            except socket.timeout:
                continue
            queries.append(wire)
            # Echo the question with an intentionally undialable A answer.
            answer = wire[:2]+struct.pack('!5H', 0x8180, 1, 1, 0, 0)+wire[12:]
            answer += b'\xc0\x0c'+struct.pack('!HHIH', 1, 1, 60, 4)+socket.inet_aton('203.0.113.9')
            main_dns.sendto(answer, peer)

    worker = threading.Thread(target=upstream)
    worker.start()
    proxy_port, dns_port = free_port(), free_port()
    try:
        with tempfile.TemporaryDirectory(prefix='paopao-direct-dns-') as folder:
            config = {
                'mixed-port': proxy_port, 'ipv6': False, 'mode': 'rule',
                'geodata': {'background-fetch': False, 'auto-update': False},
                'dns': {'enable': True, 'listen': f'127.0.0.1:{dns_port}',
                        'nameserver': [f'127.0.0.1:{main_dns.getsockname()[1]}'],
                        'direct-nameserver': ['system']},
                'rules': ['DOMAIN,www.baidu.com,DIRECT', 'DOMAIN,dns.alidns.com,DIRECT', 'MATCH,REJECT'],
            }
            path = Path(folder)/'config.json'
            path.write_text(json.dumps(config))
            log = Path(folder)/'core.log'
            with log.open('w') as out:
                core = subprocess.Popen([core_path, '-f', str(path), '-d', folder], stdout=out, stderr=subprocess.STDOUT)
            try:
                end = time.monotonic()+15
                while True:
                    assert core.poll() is None, log.read_text()
                    try:
                        with socket.create_connection(('127.0.0.1', proxy_port), timeout=.2):
                            break
                    except OSError:
                        assert time.monotonic()<end, log.read_text()
                        time.sleep(.1)
                result = subprocess.run(['curl', '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{proxy_port}',
                    '--max-time', '20', '-sS', 'https://www.baidu.com', '-o', '/dev/null', '-w', '%{http_code}'],
                    capture_output=True, text=True, timeout=23)
                assert result.returncode==0 and result.stdout=='200', (result.stderr, log.read_text())
                assert not queries, 'DIRECT TCP queried the main DNS view'
                print('PASS DIRECT HTTPS 200 using NIC DNS; no main DNS query', flush=True)
                with socket.create_connection(('127.0.0.1', proxy_port), timeout=10) as control:
                    control.sendall(b'\5\1\0')
                    assert recv_exact(control, 2)==b'\5\0'
                    control.sendall(b'\5\3\0\1'+b'\0'*6)
                    reply=recv_exact(control, 4)
                    assert reply[:2]==b'\5\0' and reply[3]==1, reply
                    relay=socket.inet_ntoa(recv_exact(control,4)),struct.unpack('!H',recv_exact(control,2))[0]
                    if relay[0]=='0.0.0.0':relay=('127.0.0.1',relay[1])
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                        udp.settimeout(15)
                        name=b'dns.alidns.com'
                        udp.sendto(b'\0\0\0\3'+bytes([len(name)])+name+struct.pack('!H',53)+dns_wire('www.baidu.com'),relay)
                        response=udp.recv(4096)
                        assert b'\4\xd2' in response, response.hex()
                        assert not queries, 'DIRECT UDP queried the main DNS view'
                print('PASS DIRECT UDP DNS round trip; no main DNS query', flush=True)
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                    udp.settimeout(5)
                    udp.sendto(dns_wire('proxy-view.test'),('127.0.0.1',dns_port))
                    response=udp.recv(4096)
                    assert response[-4:]==socket.inet_aton('203.0.113.9'),response.hex()
                    assert queries
                print('PASS main DNS remains independent', flush=True)
                assert 'DIRECT DNS follows outbound interface' in log.read_text()
            finally:
                core.terminate()
                try:core.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    core.kill();core.wait()
    finally:
        stop.set();worker.join(timeout=2);main_dns.close()


if __name__=='__main__':
    main()
