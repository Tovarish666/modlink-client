#!/usr/bin/env bash
# modlink-client — deploy на Ubuntu 22.04 / 24.04
# Использование:
#   sudo bash deploy.sh
#   sudo bash deploy.sh 'https://docs.google.com/...csv'   # сразу sync из Sheets
set -euo pipefail

[ "$(id -u)" = "0" ] || { echo "нужен root: sudo bash deploy.sh"; exit 1; }

SHEETS_URL="${1:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "[1/5] пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 iproute2 iptables curl ca-certificates >/dev/null

echo "[2/5] sing-box"
if ! command -v sing-box >/dev/null 2>&1; then
  curl -fsSL https://sing-box.app/install.sh | bash
fi
# дефолтный сервис sing-box не нужен — используем шаблон per-netns
systemctl disable --now sing-box.service 2>/dev/null || true
echo "  $(sing-box version | head -1)"

echo "[3/5] modlink-client"
install -m 0755 "$HERE/modlink-client.py" /usr/local/bin/modlink-client
mkdir -p /etc/modlink-client/singbox
echo "  /usr/local/bin/modlink-client"

echo "[4/5] sysctl"
cat > /etc/sysctl.d/99-modlink-client.conf << 'EOF'
# modlink-client: source-routing + forwarding
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF
sysctl -p /etc/sysctl.d/99-modlink-client.conf >/dev/null 2>&1 || true
echo "  ip_forward=1  rp_filter=2"

echo "[5/5] конфиг"
if [ -n "$SHEETS_URL" ]; then
  echo "$SHEETS_URL" > /etc/modlink-client/sheets-url
  chmod 600 /etc/modlink-client/sheets-url
  echo "  sheets-url сохранён"
  modlink-client sync --url "$SHEETS_URL"
elif [ ! -f /etc/modlink-client/modems.conf ]; then
  cat > /etc/modlink-client/modems.conf << 'EOF'
# Формат: N host:port:login:pass   (SOCKS5-порты)
# Пример: 1 94.19.178.214:13001:spb1m001:password
#
# Для автозаполнения из Google Sheets:
#   modlink-client sync --url 'CSV_URL'
EOF
  chmod 600 /etc/modlink-client/modems.conf
  echo "  создан шаблон /etc/modlink-client/modems.conf"
else
  echo "  /etc/modlink-client/modems.conf уже есть — не трогаю"
fi

echo ""
echo "══════════════════════════════════════════"
echo "ГОТОВО. Дальше:"
if [ -z "$SHEETS_URL" ]; then
  echo "  1) modlink-client sync --url 'CSV_URL'  # загрузить из Sheets"
fi
echo "  modlink-client up all              # dry-run (план)"
echo "  modlink-client up all --apply      # поднять все"
echo "  modlink-client status"
echo "  modlink-client status --wan        # + внешние IP"
echo "  modlink-client down all --apply    # снести все"
echo "══════════════════════════════════════════"
