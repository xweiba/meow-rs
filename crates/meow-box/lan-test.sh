#!/usr/bin/env bash
# Whole-LAN check of `meow box` on two test machines (never this one):
# BOX runs the box (plus two local shadowsocks servers as the subscription's
# lines and a local file server for the subscription); CLIENT is another
# device on the LAN. Checks:
#   1. CLIENT with only its DNS on the box gets real addresses;
#   2. the page adds the subscription (Basic auth, the box's own password);
#   3. CLIENT with gateway + DNS on the box: domestic sites go direct, foreign
#      ones through a line; its DNS answers become fake-ip.
# CLIENT's route and DNS are put back and everything started is stopped by
# PID at the end.
#
#   crates/meow-box/lan-test.sh        # BOX_HOST / CLIENT_HOST to override
set -euo pipefail
box="${BOX_HOST:-root@192.168.1.242}"
client="${CLIENT_HOST:-root@192.168.1.114}"
meow="$(cd "$(dirname "$0")/../.." && pwd)/target/release/meow"
ssh "$box" '[ -f /root/box-test/pids ] && kill $(cat /root/box-test/pids) 2>/dev/null; sleep 1; rm -rf /root/box-test && mkdir -p /root/box-test'
scp -q "$meow" "$box:/root/box-test/"
pw="$(openssl rand -hex 12)"
ssh "$box" PW="$pw" bash -s <<'BOX'
set -eu
cd /root/box-test
command -v python3 >/dev/null || pacman -S --noconfirm --needed python >/dev/null 2>&1
for p in 18388 18389; do
  nohup ssserver -s 127.0.0.1:$p -m aes-128-gcm -k "$PW" -vv > ss-$p.log 2>&1 & echo $! >> pids
done
link() { printf 'ss://%s@127.0.0.1:%s#%s\n' "$(printf 'aes-128-gcm:%s' "$PW" | base64 -w0)" "$1" "$2"; }
{ link 18388 '%E9%A6%99%E6%B8%AF%2001'; link 18389 '%E6%97%A5%E6%9C%AC%2001'; } > sub.txt
nohup python3 -m http.server 18080 --bind 127.0.0.1 > http.log 2>&1 & echo $! >> pids
# A clean start: no subscription yet (box.json keeps the MAC and lease).
rm -f /var/lib/paopao-box/subscriptions.json
nohup ./meow box --iface eth0 > box.log 2>&1 & echo $! >> pids
for i in $(seq 1 180); do grep -q '已就绪 · IP [0-9.]* · 管理 http' box.log && break; sleep 0.5; done
grep '已就绪' box.log | grep -o 'IP [0-9][0-9.]*' | head -1 | cut -d' ' -f2 > box-ip
BOX
# Stop everything started on BOX by PID (on any exit).
stop() { ssh "$box" 'cd /root/box-test; kill $(cat pids) 2>/dev/null; sleep 2; echo "core panics: $(grep -ciE panic box.log)"; rm -f box.log sub.txt'; }
trap stop EXIT
boxip="$(ssh "$box" cat /root/box-test/box-ip)"
[[ -n "$boxip" ]] || { echo "FAIL box did not start"; ssh "$box" 'tail -5 /root/box-test/box.log | grep -v 密码'; exit 1; }
echo "box: $boxip"
fail=0
check() { if [[ "$2" == ok ]]; then echo "ok   $1"; else echo "FAIL $1 ($3)"; fail=1; fi; }
fake() { [[ "$1" == 198.18.* || "$1" == 198.19.* ]]; }

# 1. DNS only (no gateway yet): real addresses.
a="$(ssh "$client" "dig +short +time=5 github.com @$boxip | grep -m1 -E '^[0-9.]+\$'" || true)"
fake "$a" || [[ -z "$a" ]] && check "DNS-only device gets a real address for github.com" fail "$a" || check "DNS-only device gets a real address for github.com" ok
# 2. The page: add the subscription (password read on the box, never printed).
code="$(ssh "$box" "python3 -c 'import json;print(json.load(open(\"/var/lib/paopao-box/box.json\"))[\"password\"])'" \
  | ssh "$client" "read -r p; curl -s -o /dev/null -w '%{http_code}' -u admin:\"\$p\" -H 'Content-Type: application/json' \
      -d '{\"url\":\"http://127.0.0.1:18080/sub.txt\"}' http://$boxip/api/subscriptions")"
[[ "$code" == 200 ]] && check "page adds the subscription" ok || check "page adds the subscription" fail "HTTP $code"
sleep 4
# 3. Gateway + DNS on the box (put back on any exit).
restore() { ssh "$client" "ip route replace default via 192.168.1.1; cp /root/resolv.conf.bak /etc/resolv.conf"; }
trap 'restore; stop' EXIT
ssh "$client" "cp /etc/resolv.conf /root/resolv.conf.bak; ip route replace default via $boxip; echo nameserver $boxip > /etc/resolv.conf"
get() { ssh "$client" "curl -s -o /dev/null -m 15 -w '%{http_code}' $1" || true; }
via_line() { ssh "$box" "grep -q '$1' /root/box-test/ss-18388.log /root/box-test/ss-18389.log"; }
for s in http://www.baidu.com https://www.qq.com; do
  r="$(get "$s")"; h="${s#*//}"
  via_line "$h" && check "$s direct" fail "through a line, $r" || check "$s direct ($r)" ok
done
for s in https://github.com https://www.google.com/generate_204; do
  r="$(get "$s")"; h="${s#*//}"; h="${h%%/*}"
  via_line "$h" && check "$s through a line ($r)" ok || check "$s through a line" fail "$r"
done
a="$(ssh "$client" "dig +short +time=5 www.google.com @$boxip | grep -m1 -E '^[0-9.]+\$'" || true)"
fake "$a" && check "gateway device gets fake-ip for google ($a)" ok || check "gateway device gets fake-ip for google" fail "$a"

exit $fail
