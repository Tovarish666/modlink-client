#!/usr/bin/env python3
"""
modlink-client — создаёт ethN-интерфейсы из удалённых SOCKS5-прокси
для mobileproxy.space (Ubuntu/Debian).

Команды:
  up   N|all [--apply]   поднять модем(ы)
  down N|all [--apply]   снести модем(ы)
  status [--wan]         таблица состояния; --wan добавляет внешний IP
  sync  [--url URL]      обновить modems.conf из Google Sheets CSV
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

# ── параметры (менять осознанно) ──────────────────────────────────────────────
TABLE_BASE  = 100          # таблица модема N = TABLE_BASE + N
HOST_OCTET  = 100          # 192.168.N.100 — mproxy биндится сюда
NS_OCTET    = 254          # 192.168.N.254 — наш конец в netns
RP_FILTER   = "2"          # loose — нужен для source-routing
TUN_MTU     = 1500
SB_STACK    = "system"     # system легче gvisor для N инстансов
WAN_IP_URL  = "https://api.ipify.org"

CONF_DIR    = "/etc/modlink-client"
MODEMS_CONF = f"{CONF_DIR}/modems.conf"
SHEETS_FILE = f"{CONF_DIR}/sheets-url"
SINGBOX_DIR = f"{CONF_DIR}/singbox"
SINGBOX_BIN = shutil.which("sing-box") or "/usr/local/bin/sing-box"
SB_UNIT     = "/etc/systemd/system/modlink-singbox@.service"

DRY_RUN = True


# ── модель ───────────────────────────────────────────────────────────────────
@dataclass
class Modem:
    n: int
    proxy_host: str
    proxy_port: int
    login: str
    password: str

    @property
    def net(self)     -> str: return f"192.168.{self.n}"
    @property
    def host_if(self) -> str: return f"eth{self.n}"
    @property
    def ns(self)      -> str: return f"ns_{self.n}"
    @property
    def tun(self)     -> str: return f"tun{self.n}"
    @property
    def table(self)   -> int: return TABLE_BASE + self.n
    @property
    def ip_mod(self)  -> str: return f"{self.net}.{HOST_OCTET}"   # .100
    @property
    def ip_gw(self)   -> str: return f"{self.net}.{NS_OCTET}"     # .254


# ── shell-helpers ─────────────────────────────────────────────────────────────
def run(cmd: str, ns: str | None = None, check: bool = True) -> int:
    """Мутирующая команда. В dry-run только печатает."""
    if ns:
        cmd = f"ip netns exec {ns} {cmd}"
    if DRY_RUN:
        print(f"  [dry] {cmd}")
        return 0
    r = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    if check and r.returncode != 0:
        sys.stderr.write(f"  ! rc={r.returncode}: {cmd}\n  {r.stderr.strip()}\n")
    return r.returncode


def sh(cmd: str, ns: str | None = None, timeout: int = 15) -> subprocess.CompletedProcess:
    """Read-only команда: выполняется всегда."""
    if ns:
        cmd = f"ip netns exec {ns} {cmd}"
    try:
        return subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")


def _default_route_field(field: str) -> str:
    r = sh("ip route show default")
    words = r.stdout.split()
    for i, w in enumerate(words):
        if w == field and i + 1 < len(words):
            return words[i + 1]
    return ""


def wan_iface() -> str: return _default_route_field("dev") or "eth0"
def wan_gw()    -> str: return _default_route_field("via") or ""


def wait_iface(ns: str, name: str, timeout: int = 15) -> bool:
    if DRY_RUN:
        print(f"  [dry] wait {name} in {ns}")
        return True
    for _ in range(timeout * 5):
        if sh(f"ip link show {name}", ns=ns, timeout=3).returncode == 0:
            return True
        time.sleep(0.2)
    return False


# ── сетевые утилиты ───────────────────────────────────────────────────────────
def ensure_rt_table(table_id: int, name: str) -> None:
    run(f"grep -qxF '{table_id}\t{name}' /etc/iproute2/rt_tables "
        f"|| printf '%s\\t%s\\n' {table_id} {name} >> /etc/iproute2/rt_tables")


def fence_iface(iface: str) -> None:
    """Запрещает systemd-networkd / NetworkManager трогать ethN."""
    if DRY_RUN:
        print(f"  [dry] fence {iface} (networkd + NM unmanaged)")
        return
    os.makedirs("/etc/systemd/network", exist_ok=True)
    with open(f"/etc/systemd/network/10-mlc-{iface}.network", "w") as f:
        f.write(f"[Match]\nName={iface}\n\n[Link]\nUnmanaged=yes\n")
    if shutil.which("nmcli"):
        conf = "/etc/NetworkManager/conf.d/99-mlc-unmanaged.conf"
        ifaces: set[str] = set()
        if os.path.exists(conf):
            for tok in open(conf).read().split("unmanaged-devices", 1)[-1].split("=", 1)[-1].split(";"):
                t = tok.strip()
                if t.startswith("interface-name:"):
                    ifaces.add(t.split(":", 1)[1])
        ifaces.add(iface)
        os.makedirs("/etc/NetworkManager/conf.d", exist_ok=True)
        with open(conf, "w") as f:
            f.write("[keyfile]\nunmanaged-devices="
                    + ";".join(f"interface-name:{i}" for i in sorted(ifaces)) + "\n")
        sh("nmcli connection reload 2>/dev/null || true", timeout=5)
    sh("networkctl reload 2>/dev/null || true", timeout=5)


# ── sing-box ──────────────────────────────────────────────────────────────────
def _singbox_config(m: Modem) -> dict:
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{
            "type": "tun", "tag": "tun-in",
            "interface_name": m.tun,
            "address": [f"10.0.{m.n}.1/30"],
            "mtu": TUN_MTU,
            "auto_route": False,
            "stack": SB_STACK,
        }],
        "outbounds": [{
            "type": "socks", "tag": "proxy",
            "server": m.proxy_host, "server_port": m.proxy_port,
            "version": "5",
            "username": m.login, "password": m.password,
        }],
        "route": {
            # UDP → reject: без этого QUIC-флуд убивает прокси
            "rules": [{"network": "udp", "action": "reject", "method": "default"}],
            "final": "proxy",
        },
    }


def ensure_singbox_unit() -> None:
    unit = (
        "[Unit]\nDescription=modlink-client sing-box modem %i\n"
        "After=network-online.target\n\n"
        "[Service]\n"
        f"NetworkNamespacePath=/run/netns/ns_%i\n"
        f"ExecStart={SINGBOX_BIN} run -c {SINGBOX_DIR}/%i.json\n"
        "Restart=always\nRestartSec=3\n\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    if DRY_RUN:
        print(f"  [dry] write {SB_UNIT} + daemon-reload")
        return
    with open(SB_UNIT, "w") as f:
        f.write(unit)
    run("systemctl daemon-reload")


def start_transport(m: Modem) -> None:
    cfg_path = f"{SINGBOX_DIR}/{m.n}.json"
    if DRY_RUN:
        print(f"  [dry] write {cfg_path}")
    else:
        os.makedirs(SINGBOX_DIR, exist_ok=True)
        with open(cfg_path, "w") as f:
            json.dump(_singbox_config(m), f, indent=2)
        os.chmod(cfg_path, 0o600)
    ensure_singbox_unit()
    run(f"systemctl start modlink-singbox@{m.n}")
    if not wait_iface(m.ns, m.tun, timeout=15):
        raise RuntimeError(
            f"{m.tun} не появился — sing-box завис.\n"
            f"  Проверь: journalctl -u modlink-singbox@{m.n} -n 30"
        )


def stop_transport(m: Modem) -> None:
    run(f"systemctl stop modlink-singbox@{m.n}",    check=False)
    run(f"systemctl disable modlink-singbox@{m.n}", check=False)
    run(f"rm -f {SINGBOX_DIR}/{m.n}.json",          check=False)


# ── up / down ─────────────────────────────────────────────────────────────────
def bring_up(m: Modem) -> None:
    print(f"\n── up {m.host_if}  {m.proxy_host}:{m.proxy_port} ──")
    wan = wan_iface()
    gw  = wan_gw()

    # netns
    run(f"ip netns add {m.ns}")
    run("ip link set lo up", ns=m.ns)

    # veth: ethN (хост) <-> peer (в ns)
    run(f"ip link add {m.host_if} type veth peer name peer netns {m.ns}")
    fence_iface(m.host_if)
    run(f"ip addr add {m.ip_mod}/24 dev {m.host_if}")
    run(f"ip link set {m.host_if} up")
    run(f"ip addr add {m.ip_gw}/24 dev peer", ns=m.ns)
    run("ip link set peer up",                ns=m.ns)

    # sysctl
    run(f"sysctl -qw net.ipv4.conf.{m.host_if}.rp_filter={RP_FILTER}")
    run( "sysctl -qw net.ipv4.ip_forward=1")

    # NAT: трафик из ns → WAN (нужен для bypass-маршрута sing-box → прокси)
    run(f"iptables -t nat -C POSTROUTING -s {m.net}.0/24 -o {wan} -j MASQUERADE 2>/dev/null"
        f" || iptables -t nat -A POSTROUTING -s {m.net}.0/24 -o {wan} -j MASQUERADE")

    # bypass на хосте: прокси-сервер → WAN напрямую
    if gw:
        run(f"ip route add {m.proxy_host}/32 via {gw} dev {wan} 2>/dev/null || true")

    # bypass в ns: ПЕРЕД стартом sing-box, иначе он не достучится до прокси
    run(f"ip route add {m.proxy_host}/32 via {m.ip_mod}", ns=m.ns)

    # policy routing: from 192.168.N.100 → table → через veth в ns
    ensure_rt_table(m.table, f"mlc{m.n}")
    run(f"ip rule add from {m.ip_mod} table {m.table}")
    run(f"ip route add default via {m.ip_gw} dev {m.host_if} table {m.table}")

    # sing-box в ns (стартует, ждём TUN)
    start_transport(m)

    # дефолтный маршрут в ns → TUN (всё остальное идёт в тоннель)
    run(f"ip route add default dev {m.tun}", ns=m.ns)

    status_line = "(dry-run)" if DRY_RUN else f"ip={m.ip_mod}  tun={m.tun}"
    print(f"   {m.host_if} {status_line}")


def tear_down(m: Modem) -> None:
    print(f"\n── down {m.host_if} ──")
    wan = wan_iface()
    stop_transport(m)
    run(f"ip netns del {m.ns}",                                                check=False)
    run(f"ip link del {m.host_if}",                                            check=False)
    run(f"ip rule del from {m.ip_mod} table {m.table}",                        check=False)
    run(f"ip route flush table {m.table}",                                     check=False)
    run(f"iptables -t nat -D POSTROUTING -s {m.net}.0/24 -o {wan} -j MASQUERADE", check=False)
    run(f"rm -f /etc/systemd/network/10-mlc-{m.host_if}.network",             check=False)
    # bypass-маршрут к прокси НЕ удаляем — другие модемы могут использовать тот же хост


# ── status ────────────────────────────────────────────────────────────────────
def _wan_ip(m: Modem) -> str:
    r = sh(f"curl -s --max-time 12 --interface {m.ip_mod} {WAN_IP_URL}", timeout=15)
    ip = r.stdout.strip()
    return ip if ip else "—"


def cmd_status(wan: bool = False) -> None:
    modems = load_modems()
    if not modems:
        print(f"нет модемов в {MODEMS_CONF}")
        return

    rows = []
    for n in sorted(modems):
        m = modems[n]
        ns_ok = sh(f"ip netns list | grep -qw {m.ns}").returncode == 0
        sb    = sh(f"systemctl is-active modlink-singbox@{n}").stdout.strip() or "—"
        tun   = "up" if (ns_ok and sh(f"ip link show {m.tun}", ns=m.ns, timeout=3).returncode == 0) else "—"
        rows.append((m, ns_ok, sb, tun))

    wan_ips: dict[int, str] = {}
    if wan:
        live = [m for m, ok, *_ in rows if ok]
        with ThreadPoolExecutor(max_workers=10) as pool:
            futs = {pool.submit(_wan_ip, m): m.n for m in live}
            for f in as_completed(futs):
                wan_ips[futs[f]] = f.result()

    cols = f"{'N':>3}  {'proxy':28}  {'ns':4}  {'sing-box':10}  tun"
    if wan:
        cols += "  wan-ip"
    print(cols)
    print("─" * (60 if not wan else 80))
    for m, ok, sb, tun in rows:
        line = (f"{m.n:>3}  {m.proxy_host}:{m.proxy_port:<6}  "
                f"{'up' if ok else 'down':4}  {sb:10}  {tun}")
        if wan:
            line += f"  {wan_ips.get(m.n, '—')}"
        print(line)


# ── sync ──────────────────────────────────────────────────────────────────────
def cmd_sync(url: str | None = None) -> None:
    if not url:
        if os.path.exists(SHEETS_FILE):
            url = open(SHEETS_FILE).read().strip()
        else:
            sys.exit(
                f"URL не задан. Передай --url '...' или создай {SHEETS_FILE}\n"
                f"  echo 'URL' > {SHEETS_FILE}"
            )
    print(f"sync ← {url}")
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            raw = resp.read().decode()
    except Exception as e:
        sys.exit(f"ошибка загрузки: {e}")

    lines = raw.strip().splitlines()
    if not lines:
        sys.exit("CSV пустой")

    header = [c.strip().lower() for c in lines[0].split(",")]
    try:
        col_n, col_p = header.index("n"), header.index("proxy")
    except ValueError:
        sys.exit(f"CSV должен содержать колонки 'n' и 'proxy'. Найдено: {header}")

    entries: list[str] = []
    for row in lines[1:]:
        parts = row.strip().split(",")
        if len(parts) <= max(col_n, col_p):
            continue
        n_s = parts[col_n].strip()
        px  = parts[col_p].strip()
        if n_s.isdigit() and px:
            entries.append(f"{n_s} {px}")

    if not entries:
        sys.exit("не удалось распарсить ни одного модема")

    os.makedirs(CONF_DIR, exist_ok=True)
    with open(MODEMS_CONF, "w") as f:
        f.write("# Автообновление: modlink-client sync\n")
        f.write("# Формат: N host:port:login:pass\n\n")
        f.write("\n".join(entries) + "\n")
    os.chmod(MODEMS_CONF, 0o600)
    print(f"  записано {len(entries)} модемов → {MODEMS_CONF}")


# ── conf ──────────────────────────────────────────────────────────────────────
def load_modems() -> dict[int, Modem]:
    if not os.path.exists(MODEMS_CONF):
        return {}
    modems: dict[int, Modem] = {}
    for ln, raw in enumerate(open(MODEMS_CONF), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit():
            sys.stderr.write(f"  ! строка {ln}: формат 'N host:port:login:pass'\n")
            continue
        n = int(parts[0])
        sp = parts[1].split(":", 3)
        if len(sp) != 4 or not sp[1].isdigit():
            sys.stderr.write(f"  ! строка {ln}: нужно host:port:login:pass\n")
            continue
        if not 1 <= n <= 254:
            sys.stderr.write(f"  ! строка {ln}: N={n} вне 1..254\n")
            continue
        if n in modems:
            sys.stderr.write(f"  ! строка {ln}: N={n} дублируется\n")
        modems[n] = Modem(n, sp[0].strip(), int(sp[1]), sp[2].strip(), sp[3].strip())
    return modems


def get_modem(n: int) -> Modem:
    m = load_modems().get(n)
    if not m:
        sys.exit(f"модем {n} не найден в {MODEMS_CONF}")
    return m


# ── CLI ───────────────────────────────────────────────────────────────────────
def main() -> None:
    global DRY_RUN
    p = argparse.ArgumentParser(
        prog="modlink-client",
        description="ethN-интерфейсы из SOCKS5-прокси для mobileproxy.space",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    for cmd in ("up", "down"):
        sp = sub.add_parser(cmd)
        sp.add_argument("target", help="N  или  all")
        sp.add_argument("--apply", action="store_true", help="реально выполнять (иначе dry-run)")

    st = sub.add_parser("status")
    st.add_argument("--wan", action="store_true", help="добавить колонку wan-ip (медленно)")

    sy = sub.add_parser("sync")
    sy.add_argument("--url", help="URL Google Sheets CSV (переопределить sheets-url)")

    a = p.parse_args()

    if a.cmd == "status":
        cmd_status(wan=a.wan)
        return
    if a.cmd == "sync":
        cmd_sync(url=getattr(a, "url", None))
        return

    DRY_RUN = not a.apply
    fn = bring_up if a.cmd == "up" else tear_down

    if a.target == "all":
        modems = load_modems()
        if not modems:
            sys.exit(f"нет модемов в {MODEMS_CONF}")
        for n in sorted(modems):
            fn(modems[n])
    else:
        if not a.target.isdigit():
            sys.exit("target: число или 'all'")
        fn(get_modem(int(a.target)))


if __name__ == "__main__":
    main()
