#!/usr/bin/env python3
"""Opt-in real-core DNS/route workflow, using two local SOCKS nodes.

Each node implements remote DNS with a distinct answer and HTTP/UDP echo.
Checks node choice, cache isolation, remote hostname forwarding, local UDP
resolution on the exact selected node, rejection, and hot reload. No user
profile or system DNS settings are changed. --with-direct also requires
the host's original interface DNS, with no other DNS-capture core active.
"""
import argparse
import concurrent.futures
import contextlib
import ipaddress
import json
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request


def read(sock, n):
    data = b''
    while len(data) < n:
        part = sock.recv(n-len(data))
        if not part:
            raise EOFError()
        data += part
    return data


def address(sock, atyp):
    if atyp == 1:
        host = socket.inet_ntoa(read(sock, 4))
    elif atyp == 4:
        host = socket.inet_ntop(socket.AF_INET6, read(sock, 16))
    else:
        assert atyp == 3
        host = read(sock, read(sock, 1)[0]).decode()
    return host, struct.unpack('!H', read(sock, 2))[0]


def wire(name, kind=1):
    return struct.pack('!6H', 1234, 0x100, 1, 0, 0, 0)+b''.join(
        bytes([len(p)])+p.encode() for p in name.split('.'))+b'\0'+struct.pack('!HH',kind,1)


def answer(query, number):
    kind = struct.unpack('!H', query[-4:-2])[0]
    if kind == 1:
        data = socket.inet_aton(f'203.0.113.{number}')
    elif kind == 28:
        data = socket.inet_pton(socket.AF_INET6, f'2001:db8::{number}')
    else:
        data = bytes([len(str(number))])+str(number).encode()
    return query[:2]+struct.pack('!5H',0x8180,1,1,0,0)+query[12:]+b'\xc0\x0c'+struct.pack('!HHIH',kind,1,60,len(data))+data


class Node(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, number):
        super().__init__(('127.0.0.1',0), Handler)
        self.number = number
        self.dns = []
        self.http = []
        self.udp_targets = []


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(5)
        try:
            assert read(sock,1) == b'\5'
            read(sock,read(sock,1)[0])
            sock.sendall(b'\5\0')
            ver, command, _, atyp = read(sock,4)
            assert ver == 5
            host, port = address(sock,atyp)
            if command == 3:
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                    udp.bind(('127.0.0.1',0));udp.settimeout(3)
                    sock.sendall(b'\5\0\0\1'+socket.inet_aton('127.0.0.1')+struct.pack('!H',udp.getsockname()[1]))
                    try:
                        data, peer = udp.recvfrom(4096)
                        assert data[3] == 1
                        dest = socket.inet_ntoa(data[4:8])
                        self.server.udp_targets.append(dest)
                        udp.sendto(data[:10]+f'node-{self.server.number}'.encode(),peer)
                    except socket.timeout:
                        pass
                return
            assert command == 1
            sock.sendall(b'\5\0\0\1'+b'\0'*6)
            if port == 53:
                while True:
                    query=read(sock,struct.unpack('!H',read(sock,2))[0])
                    self.server.dns.append(query)
                    response=answer(query,self.server.number)
                    sock.sendall(struct.pack('!H',len(response))+response)
            else:
                self.server.http.append((host,port))
                sock.recv(4096)
                body=f'node-{self.server.number}'.encode()
                sock.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
        except (EOFError,OSError,AssertionError):
            pass


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


def main():
    parser=argparse.ArgumentParser();parser.add_argument('core');parser.add_argument('--with-direct',action='store_true')
    args=parser.parse_args()
    nodes=[Node(11),Node(12)]
    for node in nodes:
        threading.Thread(target=node.serve_forever,daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='paopao-egress-') as folder:
            proxy_port,dns_port,api_port=port(),port(),port()
            config={
                'mixed-port':proxy_port,'external-controller':f'127.0.0.1:{api_port}',
                'mode':'rule','log-level':'debug','ipv6':True,'geodata':{'background-fetch':True,'auto-update':False},
                'dns':{'enable':True,'listen':f'127.0.0.1:{dns_port}',
                    'nameserver':['tcp://192.0.2.53:53#Pick'],'direct-nameserver':['system'],'follow-domain-rules':True},
                'proxies':[{'name':name,'type':'socks5','server':'127.0.0.1','port':node.server_address[1],'udp':True}
                    for name,node in zip(['AA','BB'],nodes)],
                'proxy-groups':[{'name':'Pick','type':'select','proxies':['AA','BB']},
                    {'name':'Round','type':'load-balance','strategy':'round-robin','proxies':['AA','BB'],'lazy':True}],
                'rules':['DOMAIN,alpha.test,Pick','DOMAIN,beta.test,BB','DOMAIN,block.test,REJECT',
                    'DOMAIN,remote.test,Pick','DOMAIN,udp.test,Round','DOMAIN,www.baidu.com,DIRECT','MATCH,REJECT'],
            }
            path=Path(folder)/'config.json';path.write_text(json.dumps(config))
            log=Path(folder)/'core.log'
            with log.open('w') as output:
                core=subprocess.Popen([str(Path(args.core).resolve()),'-f',str(path),'-d',folder],stdout=output,stderr=subprocess.STDOUT)
            def api(path,body=None,method=None):
                req=urllib.request.Request(f'http://127.0.0.1:{api_port}'+path,
                    data=None if body is None else json.dumps(body).encode(),
                    headers={'Content-Type':'application/json'},method=method)
                with urllib.request.urlopen(req,timeout=15) as response:
                    data=response.read()
                    return json.loads(data) if data else {}
            def query(name,kind=1):
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                    sock.settimeout(8);sock.sendto(wire(name,kind),('127.0.0.1',dns_port))
                    result=sock.recv(4096)
                    assert result[:2]==b'\4\xd2'
                    return result
            try:
                end=time.monotonic()+15
                while True:
                    assert core.poll() is None,log.read_text()
                    try:
                        api('/version');break
                    except OSError:
                        assert time.monotonic()<end,log.read_text();time.sleep(.1)
                first=query('alpha.test')
                assert first[-4:]==socket.inet_aton('203.0.113.11'), (first.hex(),[len(n.dns) for n in nodes])
                assert query('beta.test')[-4:]==socket.inet_aton('203.0.113.12')
                assert query('alpha.test',28)[-16:]==socket.inet_pton(socket.AF_INET6,'2001:db8::11')
                assert query('alpha.test',16)[-3:]==b'\x0211'
                counts=[len(node.dns) for node in nodes]
                assert query('alpha.test')[-4:]==socket.inet_aton('203.0.113.11')
                assert counts==[len(node.dns) for node in nodes]
                api('/proxies/Pick',{'name':'BB'},'PUT')
                assert query('alpha.test')[-4:]==socket.inet_aton('203.0.113.12')
                print('PASS A/AAAA/TXT follow rules; node switch isolates cached answer',flush=True)
                counts=[len(node.dns) for node in nodes]
                result=query('block.test');assert result[3]&15 != 0
                assert counts==[len(node.dns) for node in nodes]
                result=subprocess.run(['curl','--noproxy','','--proxy',f'socks5h://127.0.0.1:{proxy_port}',
                    '--max-time','10','-sS','http://remote.test'],capture_output=True,text=True,timeout=12)
                assert result.returncode==0 and result.stdout=='node-12',(result.stderr,log.read_text())
                assert nodes[1].http[-1]==('remote.test',80)
                assert counts==[len(node.dns) for node in nodes]
                print('PASS rejected DNS makes no upstream request; proxy TCP forwards domain without local DNS',flush=True)
                seen=set()
                for _ in range(4):
                    with socket.create_connection(('127.0.0.1',proxy_port),timeout=5) as control:
                        control.sendall(b'\5\1\0');assert read(control,2)==b'\5\0'
                        control.sendall(b'\5\3\0\1'+b'\0'*6)
                        reply=read(control,4);assert reply[:2]==b'\5\0'
                        relay=address(control,reply[3]);relay=('127.0.0.1',relay[1])
                        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                            udp.settimeout(12);name=b'udp.test'
                            udp.sendto(b'\0\0\0\3'+bytes([len(name)])+name+struct.pack('!H',10001)+b'ping',relay)
                            result=udp.recv(4096)
                            node=nodes[0] if result.endswith(b'node-11') else nodes[1]
                            assert node.udp_targets[-1]==f'203.0.113.{node.number}',(node.udp_targets,result)
                            seen.add(node.number)
                assert seen=={11,12},seen
                print('PASS round-robin UDP resolves and sends through the same pinned node',flush=True)
                config['rules'][0]='DOMAIN,alpha.test,AA';path.write_text(json.dumps(config))
                api('/configs',{'path':str(path)},'PUT')
                assert query('alpha.test')[-4:]==socket.inet_aton('203.0.113.11')
                assert core.poll() is None
                print('PASS config hot reload selects new DNS view without core restart',flush=True)
                if args.with_direct:
                    result=query('www.baidu.com')
                    assert struct.unpack('!H',result[6:8])[0]>0 and result[3]&15==0, result.hex()
                    assert 'DIRECT DNS follows outbound interface' in log.read_text()
                    print('PASS DIRECT domain uses actual interface DNS',flush=True)
                    config['rules']=['IP-CIDR,0.0.0.0/0,AA','MATCH,REJECT']
                    path.write_text(json.dumps(config));api('/configs',{'path':str(path)},'PUT')
                    assert query('www.baidu.com')[-4:]==socket.inet_aton('203.0.113.11')
                    assert any(q[12:] == wire('www.baidu.com')[12:] for q in nodes[1].dns)
                    print('PASS IP-rule classification uses configured proxy DNS without recursion; final answer follows selected node',flush=True)
            except BaseException:
                print(log.read_text());raise
            finally:
                core.terminate()
                try:core.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    core.kill();core.wait()
    finally:
        for node in nodes:
            node.shutdown();node.server_close()


if __name__=='__main__':
    main()
