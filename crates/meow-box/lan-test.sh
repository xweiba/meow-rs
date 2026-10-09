#!/usr/bin/env bash
# Whole-LAN check of `meow box` on two test machines (never this one):
# BOX runs the box (plus two local shadowsocks servers as the subscription's
# lines and a local file server for the subscription); CLIENT is another
# device on the LAN. Checks:
#   1. CLIENT with only its DNS on the box gets real addresses, short TTL;
#   2. the page adds the subscription (Basic auth, the box's own password);
#      the rule data (GeoIP, GeoSite) arrives and the page says so; a
#      DNS-only device's foreign names are then resolved through a line;
#   3. CLIENT switches its gateway + DNS to the box: it gets working access
#      within 15 s; domestic sites go direct (no line tunnel to their name
#      nor to any address they resolve to), a domestic address with no name
#      goes direct (GeoIP), foreign sites go through a line; its DNS
#      answers become fake-ip.
# CLIENT's route and DNS are put back and everything started is stopped by
# PID at the end.
#
#   crates/meow-box/lan-test.sh        # BOX_HOST / CLIENT_HOST to override
#   BOX_ARGS="--iface eth0 --ip 192.168.1.250/24 --gateway 192.168.1.1" crates/meow-box/lan-test.sh
#   MEOW_BIN=dist/box/meow-x86_64-unknown-linux-musl crates/meow-box/lan-test.sh   # another build
set -euo pipefail
box="${BOX_HOST:-root@192.168.1.242}"
client="${CLIENT_HOST:-root@192.168.1.114}"
meow="${MEOW_BIN:-$(cd "$(dirname "$0")/../.." && pwd)/target/release/meow}"
ssh "$box" '[ -f /root/box-test/pids ] && kill $(cat /root/box-test/pids) 2>/dev/null; sleep 1; rm -rf /root/box-test && mkdir -p /root/box-test'
scp -q "$meow" "$box:/root/box-test/meow"
# Stop everything started on BOX by PID (on any exit); box.log holds the
# password: removed.
stop() { ssh "$box" 'cd /root/box-test; kill $(cat pids) 2>/dev/null; sleep 2; echo "core panics: $(grep -ciE panic box.log)"; rm -f box.log sub.txt'; }
trap stop EXIT
pw="$(openssl rand -hex 12)"
ssh "$box" PW="$pw" BOX_ARGS="'${BOX_ARGS:---iface eth0}'" bash -s <<'BOX'
set -eu
cd /root/box-test
command -v python3 >/dev/null || pacman -S --noconfirm --needed python >/dev/null 2>&1
for p in 18388 18389; do
  nohup ssserver -s 127.0.0.1:$p -m aes-128-gcm -k "$PW" -vv > ss-$p.log 2>&1 & echo $! >> pids
done
link() { printf 'ss://%s@127.0.0.1:%s#%s\n' "$(printf 'aes-128-gcm:%s' "$PW" | base64 -w0)" "$1" "$2"; }
{ link 18388 '%E9%A6%99%E6%B8%AF%2001'; link 18389 '%E6%97%A5%E6%9C%AC%2001'; } > sub.txt
nohup python3 -m http.server 18080 --bind 127.0.0.1 > http.log 2>&1 & echo $! >> pids
# A clean start: no subscription and no rule data yet (box.json keeps the
# MAC and lease).
rm -f /var/lib/paopao-box/subscriptions.json /var/lib/paopao-box/core/Country.mmdb /var/lib/paopao-box/core/geosite.dat
nohup ./meow box $BOX_ARGS > box.log 2>&1 & echo $! >> pids
for i in $(seq 1 180); do grep -q '已就绪 · IP [0-9.]* · 管理 http' box.log && break; sleep 0.5; done
grep '已就绪' box.log | grep -o 'IP [0-9][0-9.]*' | head -1 | cut -d' ' -f2 > box-ip
BOX
boxip="$(ssh "$box" cat /root/box-test/box-ip)"
[[ -n "$boxip" ]] || { echo "FAIL box did not start"; ssh "$box" 'tail -5 /root/box-test/box.log | grep -v 密码'; exit 1; }
echo "box: $boxip"
fail=0
check() { if [[ "$2" == ok ]]; then echo "ok   $1"; else echo "FAIL $1 ($3)"; fail=1; fi; }
fake() { [[ "$1" == 198.18.* || "$1" == 198.19.* ]]; }
# The page's API from CLIENT: password read on the box, never printed.
api() {
  ssh "$box" "python3 -c 'import json;print(json.load(open(\"/var/lib/paopao-box/box.json\"))[\"password\"])'" \
    | ssh "$client" "read -r p; curl -s -m 10 -u admin:\"\$p\" $*"
}
# Whether any line's log shows a tunnel (or an attempt: foreign sites are
# blocked where the test lines run) to one of the given names/addresses.
# MARK="<bytes> <bytes>" (from `mark`) looks only at what was logged since.
via_line() {
  local pats=() m=(${MARK:-0 0})
  for x in "$@"; do pats+=(-e "<-> $x:" -e "connect $x:"); done
  ssh "$box" "cd /root/box-test; { tail -c +$((m[0] + 1)) ss-18388.log; tail -c +$((m[1] + 1)) ss-18389.log; } | grep -qF ${pats[*]@Q}"
}
# What the lines logged since MARK (targets only), for a failure's report.
line_targets() {
  local m=(${MARK:-0 0})
  ssh "$box" "cd /root/box-test; { tail -c +$((m[0] + 1)) ss-18388.log; tail -c +$((m[1] + 1)) ss-18389.log; } | grep -oE '(<->|connect) [^ ]+' | sort -u | tr '\n' ' '"
}
mark() { ssh "$box" "stat -c %s /root/box-test/ss-18388.log /root/box-test/ss-18389.log | tr '\n' ' '"; }
lines_count() { ssh "$box" "cat /root/box-test/ss-18388.log /root/box-test/ss-18389.log | grep -c 'established tcp tunnel'" || true; }

# 1. DNS only (no gateway yet): real addresses, short TTL.
ans="$(ssh "$client" "dig +noall +answer +time=5 github.com A @$boxip" || true)"
a="$(awk '$4=="A"{print $5; exit}' <<<"$ans")"; ttl="$(awk '$4=="A"{print $2; exit}' <<<"$ans")"
if [[ -z "$a" ]] || fake "$a"; then check "DNS-only device gets a real address for github.com" fail "$a"; else check "DNS-only device gets a real address for github.com" ok; fi
[[ -n "$ttl" && "$ttl" -le 10 ]] && check "real answers carry a short TTL ($ttl s)" ok || check "real answers carry a short TTL" fail "$ttl"

# 2. The page: add the subscription.
code="$(api "-o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{\"url\":\"http://127.0.0.1:18080/sub.txt\"}' http://$boxip/api/subscriptions")"
[[ "$code" == 200 ]] && check "page adds the subscription" ok || check "page adds the subscription" fail "HTTP $code"
# The rule data arrives (downloaded by the box) and the page says so.
ready=""
for i in $(seq 1 60); do
  ready="$(api "http://$boxip/api/status" | grep -o '"ready":[a-z]*' | head -1)"
  [[ "$ready" == '"ready":true' ]] && break; sleep 2
done
[[ "$ready" == '"ready":true' ]] && check "rule data (GeoIP + GeoSite) is here, page shows it" ok || check "rule data arrives" fail "$ready"
# A DNS-only device's foreign name: asked through a line now.
m="$(mark)"
a="$(ssh "$client" "dig +short +time=5 api.github.com A @$boxip | grep -m1 -E '^[0-9.]+\$'" || true)"
if [[ -n "$a" ]] && ! fake "$a" && MARK="$m" via_line 8.8.8.8 1.1.1.1; then
  check "DNS-only device: foreign name resolved through a line ($a)" ok
else check "DNS-only device: foreign name resolved through a line" fail "$a"; fi
# Addresses the sites resolve to (box answer, the core's domestic resolver,
# the box host's resolver): the core may hand a line an address instead of
# the name, so a line's log is searched for both.
declare -A ips
for h in www.baidu.com www.qq.com github.com www.google.com; do
  ips[$h]="$( { ssh "$client" "dig +short $h A @$boxip; dig +short $h A @223.5.5.5"; ssh "$box" "getent ahostsv4 $h | cut -d' ' -f1"; } \
    | grep -E '^[0-9]+(\.[0-9]+){3}$' | sort -u | tr '\n' ' ')"
done
baidu_ip="$(ssh "$client" "dig +short www.baidu.com A @223.5.5.5" | grep -m1 -E '^[0-9]+(\.[0-9]+){3}$' || true)"

# 3. Gateway + DNS on the box (put back on any exit).
# CLIENT's DNS: /etc/resolv.conf, and systemd-resolved's link servers when
# it runs (curl resolves through it; its link DNS comes from DHCP and
# would bypass the box).
nic="$(ssh "$client" "ip route show default | grep -o 'dev [^ ]*' | head -1 | cut -d' ' -f2")"
restore() { ssh "$client" "ip route del default via $boxip 2>/dev/null; ip route show default | grep -q . || ip route add default via 192.168.1.1; cp /root/resolv.conf.bak /etc/resolv.conf; if systemctl is-active -q systemd-resolved; then resolvectl revert $nic; resolvectl flush-caches; fi"; }
trap 'restore; stop' EXIT
ssh "$client" "cp /etc/resolv.conf /root/resolv.conf.bak; ip route replace default via $boxip; echo nameserver $boxip > /etc/resolv.conf; if systemctl is-active -q systemd-resolved; then resolvectl dns $nic $boxip; resolvectl domain $nic '~.'; resolvectl flush-caches; fi"
# A device that has just switched: a foreign site works within 15 s.
t0=$SECONDS; r=""
while (( SECONDS - t0 < 15 )); do
  r="$(ssh "$client" "curl -s -o /dev/null -m 5 -w '%{http_code}' https://github.com" || true)"
  [[ "$r" =~ ^[23] ]] && break; sleep 1
done
[[ "$r" =~ ^[23] ]] && check "just-switched device reaches github.com in $((SECONDS - t0)) s ($r)" ok || check "just-switched device reaches github.com within 15 s" fail "$r"
get() { ssh "$client" "curl -s -o /dev/null -m 15 -w '%{http_code}' $1" || true; }
for s in http://www.baidu.com https://www.qq.com; do
  r="$(get "$s")"; h="${s#*//}"
  read -ra addr <<<"${ips[$h]}"
  if via_line "$h" "${addr[@]}"; then check "$s direct" fail "through a line, $r"
  elif [[ "$r" == 000 ]]; then check "$s direct" fail "no answer"
  else check "$s direct ($r, ${#addr[@]} addresses checked)" ok; fi
done
# A domestic address with no name: GEOIP,CN.
if [[ -n "$baidu_ip" ]]; then
  r="$(get "http://$baidu_ip/")"
  via_line "$baidu_ip" && check "domestic address $baidu_ip direct (GeoIP)" fail "through a line, $r" || check "domestic address $baidu_ip direct (GeoIP, $r)" ok
else check "domestic address direct (GeoIP)" fail "no address for www.baidu.com"; fi
for s in https://github.com https://www.google.com/generate_204; do
  m="$(mark)"; r="$(get "$s")"; h="${s#*//}"; h="${h%%/*}"
  read -ra addr <<<"${ips[$h]}"
  MARK="$m" via_line "$h" "${addr[@]}" && check "$s through a line ($r)" ok \
    || check "$s through a line" fail "$r; lines saw: $(MARK="$m" line_targets); expected $h or ${addr[*]}"
done
a="$(ssh "$client" "dig +short +time=5 www.google.com @$boxip | grep -m1 -E '^[0-9.]+\$'" || true)"
fake "$a" && check "gateway device gets fake-ip for google ($a)" ok || check "gateway device gets fake-ip for google" fail "$a"
echo "line tunnels: $(lines_count)"

exit $fail
