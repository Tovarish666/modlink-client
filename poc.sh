#!/usr/bin/env bash
# modlink-client poc — проверка маршрутизации через один модем
# sudo bash poc.sh N host:port:login:pass
# пример: sudo bash poc.sh 4 94.19.178.214:13010:spb1m004:917KV14T

set -euo pipefail

# ── аргументы ──────────────────────────────────────────────────────────────
N="${1:?использование: $0 N host:port:login:pass}"
PROXY="${2:?использование: $0 N host:port:login:pass}"
IFS=: read -r P_HOST P_PORT LOGIN PASS <<< "$PROXY"

# ── параметры ──────────────────────────────────────────────────────────────
NS="ns_${N}"
HOST_IF="eth${N}"
TUN_IF="tun${N}"
NET="192.168.${N}"
IP_MOD="${NET}.100"    # сюда биндится mproxy
IP_GW="${NET}.254"     # наш конец в ns
TABLE="$((100 + N))"
CFG="/tmp/pv_poc_${N}.json"
SB_LOG="/tmp/pv_poc_${N}.log"
WAN=$(ip route show default | grep -oP 'dev \K\S+' | head -1)
GW=$(ip route show default  | grep -oP 'via \K\S+' | head -1)
SB_PID=""

# ── cleanup ────────────────────────────────────────────────────────────────
cleanup() {
  echo ""
  echo "── cleanup ──"
  [ -n "$SB_PID" ] && kill "$SB_PID" 2>/dev/null || true
  ip netns del "$NS"                                            2>/dev/null || true
  ip link del "$HOST_IF"                                        2>/dev/null || true
  ip rule del from "$IP_MOD" table "$TABLE"                     2>/dev/null || true
  ip route flush table "$TABLE"                                 2>/dev/null || true
  ip route del "${P_HOST}/32" via "$GW" dev "$WAN"              2>/dev/null || true
  iptables -t nat -D POSTROUTING -s "${NET}.0/24" -o "$WAN" -j MASQUERADE 2>/dev/null || true
  rm -f "$CFG" "$SB_LOG"
  echo "    готово"
}
trap cleanup EXIT INT TERM

# ── старт ──────────────────────────────────────────────────────────────────
echo "=== modlink-client PoC: модем ${N} ==="
echo "    прокси : ${P_HOST}:${P_PORT}  логин=${LOGIN}"
echo "    iface  : ${HOST_IF}  ip=${IP_MOD}/24"
echo "    netns  : ${NS}"
echo "    WAN    : ${WAN}  gw=${GW}"
echo ""

echo "[1] netns"
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up

echo "[2] veth ${HOST_IF} (хост) <-> peer (в ${NS})"
ip link add "$HOST_IF" type veth peer name peer netns "$NS"
ip addr add "${IP_MOD}/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NS" ip addr add "${IP_GW}/24" dev peer
ip netns exec "$NS" ip link set peer up

echo "[3] sysctl"
sysctl -qw "net.ipv4.conf.${HOST_IF}.rp_filter=2"
sysctl -qw "net.ipv4.ip_forward=1"

echo "[4] MASQUERADE ${NET}.0/24 -> ${WAN}  (ns выходит наружу для bypass)"
iptables -t nat -A POSTROUTING -s "${NET}.0/24" -o "$WAN" -j MASQUERADE

echo "[5] bypass на хосте: ${P_HOST} -> ${GW} dev ${WAN}"
ip route add "${P_HOST}/32" via "$GW" dev "$WAN" 2>/dev/null || echo "    (маршрут уже есть)"

echo "[6] bypass в ns: ${P_HOST} -> через veth -> хост -> WAN"
ip netns exec "$NS" ip route add "${P_HOST}/32" via "$IP_MOD"

echo "[7] policy routing: from ${IP_MOD} table ${TABLE}"
grep -qxF "${TABLE}	pvlab_${N}" /etc/iproute2/rt_tables \
  || printf '%s\tpvlab_%s\n' "$TABLE" "$N" >> /etc/iproute2/rt_tables
ip rule add from "$IP_MOD" table "$TABLE"
ip route add default via "$IP_GW" dev "$HOST_IF" table "$TABLE"

echo "[8] sing-box конфиг -> ${CFG}"
cat > "$CFG" << EOF
{
  "log": {"level": "info", "timestamp": true, "output": "${SB_LOG}"},
  "inbounds": [{
    "type": "tun",
    "tag": "tun-in",
    "interface_name": "${TUN_IF}",
    "address": ["10.0.${N}.1/30"],
    "mtu": 1500,
    "auto_route": false,
    "stack": "system"
  }],
  "outbounds": [{
    "type": "http",
    "tag": "proxy",
    "server": "${P_HOST}",
    "server_port": ${P_PORT},
    "username": "${LOGIN}",
    "password": "${PASS}"
  }],
  "route": {
    "rules": [{"network": "udp", "action": "reject", "method": "default"}],
    "final": "proxy"
  }
}
EOF
chmod 600 "$CFG"

echo "[9] sing-box в ${NS} (лог: ${SB_LOG})"
ip netns exec "$NS" sing-box run -c "$CFG" > "$SB_LOG" 2>&1 &
SB_PID=$!
echo "    PID: ${SB_PID}"

echo -n "[10] ждём ${TUN_IF} "
for i in $(seq 1 50); do
  if ip netns exec "$NS" ip link show "$TUN_IF" &>/dev/null; then
    echo "OK (${i}×200ms)"
    break
  fi
  sleep 0.2
  printf "."
  if [ "$i" -eq 50 ]; then
    echo " TIMEOUT"
    echo "── лог sing-box ──"
    cat "$SB_LOG" 2>/dev/null
    exit 1
  fi
done

echo "[11] default route в ns -> ${TUN_IF}"
ip netns exec "$NS" ip route add default dev "$TUN_IF"

# ── тест ───────────────────────────────────────────────────────────────────
echo ""
echo "=== ТЕСТ ==="

echo -n "  curl 2ip.ru через ${IP_MOD} ... "
IP_OUT=$(curl -s --max-time 15 --interface "$IP_MOD" "https://2ip.ru/ip/" 2>&1 || echo "ERROR")

if [[ "$IP_OUT" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "OK"
  echo "  ✓ внешний IP: ${IP_OUT}"
  echo "  (если совпадает с ${P_HOST} — трафик идёт напрямую, не через модем)"
else
  echo "FAIL"
  echo "  ✗ ответ: ${IP_OUT}"
  echo ""
  echo "── последние строки sing-box ──"
  tail -20 "$SB_LOG" 2>/dev/null || true
fi

echo ""
echo "── ручные проверки (пока скрипт не завершён) ──"
echo "  изнутри ns:  ip netns exec ${NS} curl -s --interface ${IP_GW} https://2ip.ru/ip/"
echo "  снаружи ns:  curl -s --interface ${IP_MOD} https://2ip.ru/ip/"
echo "  маршруты ns: ip netns exec ${NS} ip route"
echo "  лог sb:      tail -f ${SB_LOG}"
echo ""
echo "Enter → cleanup и выход"
read -r
