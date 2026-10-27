#!/bin/bash
# ══════════════════════════════════════════════════════════════
#  tcpdump -> FIFO cho live_infer.py
#  Chay 1 lan, giu terminal nay mo trong suot phien.
#  FIFO nam trong ./pcap_container/ — NGANG CAP voi script nay,
#  khong phu thuoc thu muc dang dung khi goi.
# ══════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd)"

IFACE="${IFACE:-eth0}"                     # doi bang: IFACE=wlan0 ./capture.sh
PCAP_DIR="$SCRIPT_DIR/pcap_container"
PIPE="$PCAP_DIR/ids_pipe.pcap"             # PHAI khop PIPE_PATH trong live_infer.py

# ── Loai KENH QUAN LY (vd laptop dieu khien tu xa) khoi luong giam sat ──
# Thuc hanh chuan cua NIDS: tach traffic van hanh khoi traffic can giam sat.
# KHONG anh huong kha nang phat hien tan cong tu may khac (Kali/VM co IP rieng)
# vi chi loai dung (cac) host duoc khai bao.
# Lay IP bang:  arp -a   hoac   ip neigh
# Ghi de khi goi:  EXCLUDE_HOSTS="192.168.1.50 192.168.1.60" ./capture.sh
EXCLUDE_HOSTS="${EXCLUDE_HOSTS:-}"

BPF_FILTER=""
for ip in $EXCLUDE_HOSTS; do
    if [ -z "$BPF_FILTER" ]; then
        BPF_FILTER="not host $ip"
    else
        BPF_FILTER="$BPF_FILTER and not host $ip"
    fi
done

echo "══════════════════════════════════════════════════════════"
echo " capture.sh — nguon goi cho live_infer.py"
echo "══════════════════════════════════════════════════════════"
echo "  thu muc   : $SCRIPT_DIR"
echo "  interface : $IFACE"
echo "  FIFO      : $PIPE"
if [ -n "$BPF_FILTER" ]; then
    echo "  loai tru  : $EXCLUDE_HOSTS"
    echo "  BPF       : $BPF_FILTER"
else
    echo "  loai tru  : (chua cau hinh — vd: EXCLUDE_HOSTS=\"192.168.1.50\" ./capture.sh)"
fi

# ── tcpdump ──
if ! command -v tcpdump >/dev/null 2>&1; then
    echo "  LOI: khong tim thay tcpdump. Cai bang:" >&2
    echo "       sudo apt update && sudo apt install -y tcpdump" >&2
    exit 1
fi
TCPDUMP_BIN="$(readlink -f "$(command -v tcpdump)")"

# ── interface ──
if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "  LOI: khong co interface '$IFACE'. Hien co:" >&2
    ip -br link show | awk '{print "       " $1}' >&2
    exit 1
fi

mkdir -p "$PCAP_DIR"

# ── quyen bat goi (idempotent, chi hoi sudo lan dau) ──
if ! getcap "$TCPDUMP_BIN" 2>/dev/null | grep -q cap_net_raw; then
    echo "  Cap cap_net_raw cho tcpdump (can sudo mot lan)..."
    sudo setcap cap_net_raw,cap_net_admin=eip "$TCPDUMP_BIN"
fi

# ── path ton tai nhung khong phai FIFO (vd .pcap cu) -> xoa ──
if [ -e "$PIPE" ] && [ ! -p "$PIPE" ]; then
    echo "  '$PIPE' khong phai FIFO -> xoa."
    rm -f "$PIPE"
fi
if [ ! -p "$PIPE" ]; then
    echo "  Tao FIFO: $PIPE"
    mkfifo "$PIPE"
fi

echo ""
echo "  Terminal KHAC chay:"
echo "      python3 \"$SCRIPT_DIR/live_infer.py\""
echo "      ids> run 1 --iface $IFACE"
echo ""
echo "  Bat dau tcpdump (Ctrl+C de dung)..."
# tcpdump se TREO o day toi khi live_infer mo doc dau kia FIFO.
# Do la hanh vi binh thuong cua named pipe, khong phai loi.
# -U : flush tung goi ngay (BAT BUOC; thieu co nay Python doc tre hang loat)
# -w : ghi ra FIFO thay vi file thuong
if [ -n "$BPF_FILTER" ]; then
    exec tcpdump -i "$IFACE" -w "$PIPE" -U "$BPF_FILTER"
else
    exec tcpdump -i "$IFACE" -w "$PIPE" -U
fi
