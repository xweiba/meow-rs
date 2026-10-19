#!/usr/bin/env python3
"""Opt-in Linux TUN/DNS workflow. Run as root on a disposable test host.

Verifies on-link/interface-bound UDP and TCP, no resolver-file changes,
normal stop and SIGKILL cleanup. Requires nft and /dev/net/tun; no nodes,
credentials, browser or Flutter process. Only this test's core is stopped.
"""
import argparse
import json
import os
import pwd
from pathlib import Path
import signal
import select
import socket
import struct
import subprocess
import tempfile
import time


def wait_for(check, message):
    end = time.monotonic() + 15
    while time.monotonic() < end:
        if check():
            return
        time.sleep(0.1)
    raise AssertionError(message)


def tables():
    return subprocess.check_output(["nft", "list", "tables"], text=True)


def query(server, iface, tcp=False, bound=False, name="dns-capture.invalid"):
    body = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    wire = struct.pack("!6H", 1234, 0x100, 1, 0, 0, 0) + body + struct.pack("!2H", 1, 1)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        if bound:
            # Match resolved: UNICAST_IF remains set; BINDTODEVICE is
            # used only for connect() then cleared before receiving.
            sock.setsockopt(socket.IPPROTO_IP, 50, struct.pack("!I", socket.if_nametoindex(iface)))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b"\0")
        if tcp and bound:
            sock.setblocking(False)
            try:
                sock.connect((server, 53))
            except BlockingIOError:
                pass
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"")
            sock.settimeout(4)
            assert select.select([], [sock], [], 4)[1], "DNS TCP connect timed out"
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0
        else:
            sock.connect((server, 53))
            if bound:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"")
        if tcp:
            sock.sendall(struct.pack("!H", len(wire)) + wire)
            size = bytearray()
            while len(size) < 2:
                part = sock.recv(2 - len(size))
                if not part:
                    raise AssertionError("TCP DNS closed before length prefix")
                size.extend(part)
            length = struct.unpack("!H", size)[0]
            answer = bytearray()
            while len(answer) < length:
                part = sock.recv(length - len(answer))
                if not part:
                    raise AssertionError("TCP DNS closed mid-frame")
                answer.extend(part)
        else:
            sock.send(wire)
            answer = sock.recv(65535)
    assert struct.unpack("!H", answer[:2])[0] == 1234
    assert answer[3] & 15 == 0, answer.hex()
    if name == "dns-capture.invalid":
        assert answer[-4:] == socket.inet_aton("192.0.2.123"), answer.hex()
    else:
        assert struct.unpack("!H", answer[6:8])[0] > 0, answer.hex()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("core")
    parser.add_argument("--dns", required=True, help="real on-link DNS server")
    parser.add_argument("--iface", required=True)
    parser.add_argument("--upstream", default="223.5.5.5", help="reachable real DNS upstream")
    parser.add_argument("--core-user", help="exercise a file-capability core as this existing user")
    args = parser.parse_args()
    assert os.geteuid() == 0
    assert "paopao_dns_" not in tables(), "a DNS capture already runs on this test host"
    original = Path("/etc/resolv.conf").read_bytes()
    query(args.upstream, args.iface, name="example.com")
    with tempfile.TemporaryDirectory(prefix="paopao-dns-e2e-") as folder:
        config = {
            "mode": "rule", "ipv6": False, "log-level": "debug",
            "dns": {"enable": True, "nameserver": [args.upstream]},
            "paopao-hosts": [{"type": "exact", "value": "dns-capture.invalid", "address": "192.0.2.123"}],
            "tun": {"enable": True, "device": "pp-dns-test", "auto-route": "global",
                    "inet6-address": ["fdfe:dcba:9876::1/126"],
                    "dns-hijack": ["any:53"], "follow-system-routes": True},
            "rules": ["MATCH,DIRECT"],
        }
        config_path = Path(folder) / "config.json"
        config_path.write_text(json.dumps(config))
        user = pwd.getpwnam(args.core_user) if args.core_user else None
        if user:
            os.chown(folder, user.pw_uid, user.pw_gid)
        log_path = Path(folder) / "core.log"
        for kill_signal in (signal.SIGTERM, signal.SIGKILL):
            with log_path.open("w") as log:
                core = subprocess.Popen([str(Path(args.core).resolve()), "-f", str(config_path), "-d", folder],
                                        stdout=log, stderr=subprocess.STDOUT,
                                        user=user.pw_uid if user else None,
                                        group=user.pw_gid if user else None)
                try:
                    wait_for(lambda: core.poll() is not None or "paopao_dns_" in tables(), "capture not installed")
                    assert core.poll() is None, log_path.read_text()
                    for tcp in (False, True):
                        for bound in (False, True):
                            print(f"checking tcp={tcp} interface_bound={bound}", flush=True)
                            query(args.dns, args.iface, tcp=tcp, bound=bound)
                        query("2001:db8::53", args.iface, tcp=tcp)
                    # Its own DNS upstream must escape interception, including
                    # a LAN upstream also queried by the system resolver.
                    query(args.dns, args.iface, name="example.com")
                    assert Path("/etc/resolv.conf").read_bytes() == original
                    core.send_signal(kill_signal)
                    core.wait(timeout=15)
                    wait_for(lambda: "paopao_dns_" not in tables(), "capture leaked after core exit")
                    assert Path("/etc/resolv.conf").read_bytes() == original
                    print(f"PASS UDP/TCP, bound/unbound, upstream, unchanged DNS, {kill_signal.name}")
                except BaseException:
                    print(subprocess.check_output(["nft", "list", "ruleset"], text=True))
                    print(log_path.read_text())
                    raise
                finally:
                    if core.poll() is None:
                        core.kill()
                        core.wait(timeout=15)
                    wait_for(lambda: "paopao_dns_" not in tables(), "test cleanup left capture rules")


if __name__ == "__main__":
    main()
