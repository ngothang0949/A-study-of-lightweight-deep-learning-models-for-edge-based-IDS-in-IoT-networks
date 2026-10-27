#!/usr/bin/env python3
"""
bench_pi.py — DO HIEU SUAT tren Raspberry Pi 4 (Edge Gateway)

Do bo chi so Realguard Table 6 (Exec Rate) + Table 7 (CPU/RAM), VA them ba chi so
chat luong ACC / Macro-F1 / Macro-AUC de doi chieu voi ban chay Kaggle.

Vi sao van do chat luong o day du suy luan la deterministic: no dong vai tro
KIEM CHUNG. Neu ACC/Macro-F1/Macro-AUC tren Pi trung khop voi Kaggle thi moi
chac chan hai ben dung cung extractor, cung scaler, cung shape input — luc do
con so Exec Rate moi co y nghia so sanh. Lech nhau la dau hieu sai cau hinh.

CAU TRUC THU MUC (script nam NGANG CAP voi 2 thu muc nay):

    ./bench_pi.py
    ./unb pcaps/             *.pcap / *.pcapng
    ./tflite models/         *.tflite   (chap nhan ca 'tflite_models', 'models')
    ./scaler_standard*.pkl   \\ tu tim de quy o moi noi trong thu muc script
    ./feature_columns*.json  /

CHAY:
    python3 bench_pi.py                      # mac dinh: TAT CA cua so, 3 lan lap
    python3 bench_pi.py --pilot              # chay nhanh 1 model de uoc luong thoi gian
    python3 bench_pi.py --max-windows 50000 --repeats 5   # lay mau (chi de uoc luong)
    python3 bench_pi.py --threads 4          # PHAI trung voi lan chay PC de so sanh

LUU Y QUAN TRONG:
    --threads phai dat Y HET gia tri TFLITE_THREADS cua lan chay PC, neu khong
    bang so sanh PC vs Pi se khong con y nghia.
"""
import argparse, glob, json, os, pickle, platform, re, socket, sys, threading, time
from collections import Counter

import numpy as np

try:
    import dpkt
except ImportError:
    sys.exit('Thieu dpkt.  Cai:  pip3 install dpkt')
try:
    import psutil
except ImportError:
    sys.exit('Thieu psutil.  Cai:  pip3 install psutil')

# ── TFLite runtime: uu tien ban nhe cho ARM ─────────────────────────────────
try:
    from tflite_runtime.interpreter import Interpreter as TFLiteInterpreter
    TFLITE_SRC = 'tflite_runtime'
except ImportError:
    try:
        from ai_edge_litert.interpreter import Interpreter as TFLiteInterpreter
        TFLITE_SRC = 'ai_edge_litert'
    except ImportError:
        try:
            import tensorflow as tf
            TFLiteInterpreter = tf.lite.Interpreter
            TFLITE_SRC = 'tensorflow.lite'
        except ImportError:
            sys.exit('Khong co TFLite runtime.  Cai:  pip3 install tflite-runtime')

HERE = os.path.dirname(os.path.abspath(__file__))


# ============================================================================
# EXTRACTOR v5.1 — COPY NGUYEN VAN TU NOTEBOOK PC
# ============================================================================
# ═══════════════ EXTRACTOR v5.1 — COPY NGUYEN VAN ═══════════════
# _per_packet / _aggregate / _ip_stats GIU NGUYEN 100% tu ban v5.1 da kiem chung
# (mode protocol_type, std ddof=1, *_count_ratio, iat raw).
# THAY DOI DUY NHAT o cell nay: windows_from_pcap() yield THEM ts_start/ts_end
# (lay tu chinh buffer da dung de _aggregate) -> de do DO TRE PHAT HIEN theo
# GIAY THAT o buoc decision strategy. Khong dong den cong thuc dac trung nao.
FEATURE_ORDER = ['header_length','protocol_type','time_to_live','rate',
 'fin_flag_number','syn_flag_number','rst_flag_number','psh_flag_number',
 'ack_flag_number','ece_flag_number','cwr_flag_number',
 'http','https','dns','telnet','smtp','ssh','irc','tcp','udp','dhcp','arp',
 'icmp','igmp','ipv','llc','min','max','avg','std','tot_size','iat','variance',
 'ack_count_ratio','syn_count_ratio','fin_count_ratio','rst_count_ratio']
NUM_FEATURES = len(FEATURE_ORDER)
assert NUM_FEATURES == 37

WINDOW = 10          # bi ghi de boi --window trong main()
import socket as _socket

def _l4_flags(sport, dport):
    def has(p): return int(sport == p or dport == p)
    return {'http':has(80),'https':has(443),'dns':has(53),'telnet':has(23),
            'smtp':has(25),'ssh':has(22),'irc':has(21)}

def _dhcp(sport, dport):
    return int((sport==67 and dport==68) or (sport==68 and dport==67))

def _flags(tcp):
    f = tcp.flags
    return {'fin':int(f&0x01!=0),'syn':int(f&0x02!=0),'rst':int(f&0x04!=0),
            'psh':int(f&0x08!=0),'ack':int(f&0x10!=0),'urg':int(f&0x20!=0),
            'ece':int(f&0x40!=0),'cwr':int(f&0x80!=0)}

def _per_packet(ts, buf, prev_ts):
    """Trich per-packet. Tra dict, hoac None neu goi bi BO.
       src_ip/dst_ip CHI de bao cao dinh danh — KHONG dua vao vector 37 feature."""
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except Exception:
        return None
    is_ip  = (eth.type == dpkt.ethernet.ETH_TYPE_IP)
    is_arp = (eth.type == dpkt.ethernet.ETH_TYPE_ARP)
    if not (is_ip or is_arp):
        return None
    d = {'ts': ts, 'iat': 0.0 if prev_ts is None else ts - prev_ts,
         'tot_size': len(buf), 'src_ip': None, 'dst_ip': None}
    for k in ['header_length','protocol_type','time_to_live','arp','icmp','igmp',
              'tcp','udp','http','https','dns','telnet','smtp','ssh','irc','dhcp',
              'fin','syn','rst','psh','ack','urg','ece','cwr','ipv','llc']:
        d[k] = 0
    if is_arp:
        d['arp'] = 1
        arp = eth.data
        try:
            d['src_ip'] = _socket.inet_ntoa(arp.spa)
            d['dst_ip'] = _socket.inet_ntoa(arp.tpa)
        except Exception:
            pass
        return d
    ip = eth.data
    if not isinstance(ip, dpkt.ip.IP):
        return None
    d['ipv'] = 1
    d['llc'] = 1
    d['protocol_type'] = ip.p
    d['time_to_live']  = ip.ttl
    try:
        d['src_ip'] = _socket.inet_ntoa(ip.src)
        d['dst_ip'] = _socket.inet_ntoa(ip.dst)
    except Exception:
        pass
    l4 = ip.data
    if isinstance(l4, dpkt.tcp.TCP):
        d['tcp'] = 1
        d['header_length'] = l4.__hdr_len__ + len(l4.opts)
        d.update(_flags(l4))
        d.update(_l4_flags(l4.sport, l4.dport))
    elif isinstance(l4, dpkt.udp.UDP):
        d['udp'] = 1
        d['header_length'] = 8
        d.update(_l4_flags(l4.sport, l4.dport))
        d['dhcp'] = _dhcp(l4.sport, l4.dport)
    elif isinstance(l4, dpkt.icmp.ICMP):
        d['icmp'] = 1
    elif isinstance(l4, dpkt.igmp.IGMP):
        d['igmp'] = 1
    return d


def _aggregate(window):
    n = len(window)
    sizes = np.array([p['tot_size'] for p in window], dtype='float64')
    mn, mx = sizes.min(), sizes.max()
    avg = sizes.mean()
    std = float(np.std(sizes, ddof=1)) if n > 1 else 0.0
    variance = float(np.var(sizes, ddof=1)) if n > 1 else 0.0
    ts = [p['ts'] for p in window]
    dur = max(ts) - min(ts)
    rate = n / dur if dur > 0 else 0.0
    _cnt = Counter(int(p['protocol_type']) for p in window)
    _best = max(_cnt.values())
    proto_mode = float(min(k for k, v in _cnt.items() if v == _best))
    def m(k): return float(np.mean([p[k] for p in window]))
    def cnt(k): return sum(p[k] for p in window)
    row = {
        'header_length': m('header_length'), 'protocol_type': proto_mode,
        'time_to_live': m('time_to_live'), 'rate': rate,
        'fin_flag_number': m('fin'), 'syn_flag_number': m('syn'),
        'rst_flag_number': m('rst'), 'psh_flag_number': m('psh'),
        'ack_flag_number': m('ack'), 'ece_flag_number': m('ece'), 'cwr_flag_number': m('cwr'),
        'http': m('http'), 'https': m('https'), 'dns': m('dns'), 'telnet': m('telnet'),
        'smtp': m('smtp'), 'ssh': m('ssh'), 'irc': m('irc'), 'tcp': m('tcp'), 'udp': m('udp'),
        'dhcp': m('dhcp'), 'arp': m('arp'), 'icmp': m('icmp'), 'igmp': m('igmp'),
        'ipv': m('ipv'), 'llc': m('llc'),
        'min': mn, 'max': mx, 'avg': avg, 'std': std, 'tot_size': m('tot_size'),
        'iat': m('iat'), 'variance': variance,
        'ack_count_ratio': min(cnt('ack') / n, 1.0),
        'syn_count_ratio': min(cnt('syn') / n, 1.0),
        'fin_count_ratio': min(cnt('fin') / n, 1.0),
        'rst_count_ratio': min(cnt('rst') / n, 1.0),
    }
    return [row[k] for k in FEATURE_ORDER]


def _ip_stats(window):
    """Thong ke dinh danh IP cua 1 cua so — CHI de bao cao, KHONG dua vao model.
       Tinh tren CUNG buffer da dung de _aggregate() -> khong match/suy nguoc gi ca."""
    n = len(window)
    src_ips = [p['src_ip'] for p in window if p['src_ip']]
    cnt = Counter(src_ips)
    n_unique = len(cnt)
    if cnt:
        top_ip, top_c = cnt.most_common(1)[0]
        top_pct = 100.0 * top_c / n
    else:
        top_ip, top_pct = None, 0.0
    return {'n_unique_src': n_unique, 'top_src_ip': top_ip,
            'top_src_pct': top_pct, 'src_counter': cnt}


def windows_from_pcap(path, window=None):
    """Doc 1 file pcap TINH, yield (win_idx, vec37, ip_stats, ts_start, ts_end).

    ts_start/ts_end = timestamp goi DAU va goi CUOI cua chinh cua so do
    -> cho phep tinh do tre phat hien theo GIAY THAT (khong chi dem so cua so).
    Tham so `window` de trong = dung WINDOW toan cuc (=10); truyen vao de quet W sau nay.
    """
    W = window or WINDOW
    buf, prev_ts, win_idx = [], None, 0
    with open(path, 'rb') as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0); reader = dpkt.pcapng.Reader(f)
        for ts, pkt in reader:
            pp = _per_packet(ts, pkt, prev_ts)
            if pp is None:
                continue
            prev_ts = ts
            buf.append(pp)
            if len(buf) == W:
                vec = _aggregate(buf)
                ips = _ip_stats(buf)
                ts_start = buf[0]['ts']
                ts_end   = buf[-1]['ts']
                win_idx += 1
                yield win_idx, vec, ips, ts_start, ts_end
                buf = []

# ══════════════════════════════════════════════════════════════════════════════
# NHAN THAT + CHI SO CHAT LUONG
# ══════════════════════════════════════════════════════════════════════════════
LABEL_NAMES = {0:'Benign', 1:'DDoS', 2:'DoS', 3:'BruteForce',
               4:'Spoofing', 5:'Recon', 6:'Web-Based', 7:'Mirai'}
NUM_CLASSES = len(LABEL_NAMES)

# Co so: paper CICIoT2023 (Figure 7) — moi experiment chay 1 loai tan cong, va
# TOAN BO traffic bat duoc trong experiment do duoc gan nhan la tan cong do.
# => nhan la thuoc tinh cua FILE, khong phu thuoc cach cat cua so
# => moi cua so trong 1 file deu mang cung 1 nhan, dung o MOI gia tri W.
#
# Quy tac khop: chuan hoa ten file (thuong hoa, bo _ - va khoang trang) roi do
# tuan tu theo bang duoi. THU TU QUAN TRONG: 'ddos' phai duoc do TRUOC 'dos',
# neu khong 'ddosicmpflood' se bi bat nham thanh DoS.

def _norm(s):
    return re.sub(r'[^a-z0-9]', '', s.lower())

# (chuoi_can_tim, nhan) — do theo DUNG thu tu nay, khop cai dau tien thi dung.
LABEL_RULES = [
    # --- Mirai (do truoc vi ten chua 'flood' de nham voi DDoS) ---
    ('miraigreeth',   7), ('miraigreip',    7), ('miraiudpplain', 7), ('mirai', 7),
    # --- DDoS (PHAI truoc DoS) ---
    ('ddos', 1),
    # --- DoS ---
    ('dos',  2),
    # --- Recon ---
    ('recon', 5), ('vulnerabilityscan', 5), ('osscan', 5), ('portscan', 5),
    ('pingsweep', 5), ('hostdiscovery', 5),
    # --- Spoofing ---
    ('mitmarpspoofing', 4), ('arpspoofing', 4), ('dnsspoofing', 4), ('spoofing', 4),
    # --- Brute force ---
    ('dictionarybruteforce', 3), ('bruteforce', 3),
    # --- Web-based ---
    ('sqlinjection', 6), ('commandinjection', 6), ('backdoormalware', 6),
    ('uploadingattack', 6), ('browserhijacking', 6), ('xss', 6),
    # --- Benign (de cuoi: 'benign' khong dung voi bat ky nhan tan cong nao) ---
    ('benigntraffic', 0), ('benign', 0),
]

def label_from_filename(fname):
    """Tra ve (nhan_int, ten_nhan) hoac (None, None) neu KHONG khop luat nao."""
    key = _norm(os.path.basename(fname))
    for pat, lab in LABEL_RULES:
        if pat in key:
            return lab, LABEL_NAMES[lab]
    return None, None


# ── Liet ke pcap + kiem tra nhan TRUOC khi chay (fail fast) ──


def _rankdata(a):
    """Hang trung binh khi co gia tri trung — tuong duong scipy.stats.rankdata."""
    order = np.argsort(a, kind='mergesort')
    ranks = np.empty(len(a), dtype='float64')
    ranks[order] = np.arange(1, len(a) + 1)
    sa = a[order]
    i = 0
    while i < len(sa):
        j = i
        while j + 1 < len(sa) and sa[j + 1] == sa[i]:
            j += 1
        if j > i:
            ranks[order[i:j + 1]] = (i + j + 2) / 2.0
        i = j + 1
    return ranks


def auc_ovr(y_bin, score):
    """AUC one-vs-rest bang Mann-Whitney U — KHONG can sklearn (Pi thuong thieu).
       AUC = (tong hang cua lop duong - n+(n++1)/2) / (n+ * n-)"""
    npos = int(y_bin.sum()); nneg = len(y_bin) - npos
    if npos == 0 or nneg == 0:
        return float('nan')
    r = _rankdata(np.asarray(score, dtype='float64'))
    return (r[y_bin == 1].sum() - npos * (npos + 1) / 2.0) / (npos * nneg)


def quality_metrics(y_true, y_pred, probs):
    """Tra (acc, macro_f1, macro_auc, cm). Macro chi tinh tren lop CO MAT."""
    k = NUM_CLASSES
    cm = np.bincount(y_true.astype(np.int64) * k + y_pred.astype(np.int64),
                     minlength=k * k).reshape(k, k)
    tot = cm.sum()
    f1 = np.full(k, np.nan); auc = np.full(k, np.nan); sup = np.zeros(k, dtype=np.int64)
    for c in range(k):
        TP = cm[c, c]; FN = cm[c, :].sum() - TP; FP = cm[:, c].sum() - TP
        sup[c] = TP + FN
        ppv = TP / (TP + FP) if (TP + FP) else np.nan
        tpr = TP / (TP + FN) if (TP + FN) else np.nan
        if ppv == ppv and tpr == tpr and (ppv + tpr) > 0:
            f1[c] = 2 * ppv * tpr / (ppv + tpr)
        yb = (y_true == c).astype(np.int8)
        if 0 < yb.sum() < len(yb):
            auc[c] = auc_ovr(yb, probs[:, c])
    ok = sup > 0
    return (float(np.trace(cm) / tot) if tot else float('nan'),
            float(np.nanmean(f1[ok])), float(np.nanmean(auc[ok])), cm)


# ══════════════════════════════════════════════════════════════════════════════
# TIEN ICH
# ══════════════════════════════════════════════════════════════════════════════
class ResourceSampler:
    """Lay mau CPU%/RAM lien tuc bang thread rieng (khong do 1 diem).

    Mac dinh (khong truyen pids) = chi theo doi TIEN TRINH PYTHON HIEN TAI,
    dung nguyen nhu ban cu (vi du: do rieng phan trich xuat + suy luan).

    Truyen pids=[pid1, pid2, ...] de CONG DON CPU%/RAM cua NHIEU tien trinh
    cu the lai voi nhau (vi du: live_infer.py + tcpdump) -> do dung "pipeline
    day du" ma KHONG lan bat ky tien trinh nao khac dang chay tren may (khac
    voi do CPU toan he thong bang psutil.cpu_percent(), von gom ca cac tien
    trinh khong lien quan).
    """
    def __init__(self, interval=0.5, pids=None):
        self.interval = interval
        pids = pids if pids else [os.getpid()]
        self.procs = []
        for pid in pids:
            try:
                pr = psutil.Process(pid)
                pr.cpu_percent(interval=None)      # moi hoa dong ho CPU
                self.procs.append(pr)
            except psutil.NoSuchProcess:
                pass
        self.cpu, self.ram = [], []
        self._stop = threading.Event()
        self._th = None
    def _sample(self):
        c = r = 0.0
        for pr in list(self.procs):
            try:
                c += pr.cpu_percent(interval=None)
                r += pr.memory_info().rss / 1024**2
            except psutil.NoSuchProcess:
                self.procs.remove(pr)   # tien trinh da thoat giua chung (vd tcpdump bi Ctrl+C truoc)
        return c, r
    def _loop(self):
        while not self._stop.wait(self.interval):
            c, r = self._sample()
            self.cpu.append(c); self.ram.append(r)
    def __enter__(self):
        self._th = threading.Thread(target=self._loop, daemon=True)
        self._th.start()
        return self
    def __exit__(self, *a):
        self._stop.set()
        self._th.join(timeout=2)
        if not self.cpu:
            c, r = self._sample()
            self.cpu.append(c); self.ram.append(r)
    def stats(self):
        f = lambda v: (float(np.mean(v)), float(np.max(v))) if v else (0.0, 0.0)
        cpu_avg, cpu_max = f(self.cpu)
        ram_avg, ram_max = f(self.ram)
        nc = psutil.cpu_count(logical=True) or 1
        # cpu_percent() cua psutil tinh theo MOT nhan: 100% = bao hoa 1 nhan
        # (cong don qua nhieu tien trinh van theo thang nay). Chia cho so
        # nhan de doi ra thang "toan may" (0-100%), de so sanh voi btop.
        return {'cpu_avg': cpu_avg, 'cpu_max': cpu_max,
                'cpu_avg_sys': cpu_avg / nc, 'cpu_max_sys': cpu_max / nc,
                'ram_avg_mb': ram_avg, 'ram_peak_mb': ram_max,
                'n_procs': len(self.procs)}


def find_pid_by_cmdline(*substrs):
    """Tim PID dau tien co cmdline chua TAT CA cac chuoi con trong substrs.
       Dung de tim dung tien trinh tcpdump dang ghi vao FIFO cua chinh minh
       (khop them duong dan FIFO -> tranh bat nham tcpdump khac dang chay)."""
    for p in psutil.process_iter(['pid', 'cmdline']):
        try:
            cmd = ' '.join(p.info['cmdline'] or [])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if all(s in cmd for s in substrs):
            return p.info['pid']
    return None


def find_dir(cands):
    for c in cands:
        p = os.path.join(HERE, c)
        if os.path.isdir(p):
            return p
    return None


def find_file(pattern):
    hits = sorted(glob.glob(os.path.join(HERE, '**', pattern), recursive=True))
    return hits[0] if hits else None


def tag_from_path(path):
    t = os.path.basename(path).rsplit('.', 1)[0]
    for pre in ('student_', 'model_'):
        if t.startswith(pre):
            t = t[len(pre):]
    for suf in ('_int8', '_fp32', '_float32', '_dynamic'):
        if t.endswith(suf):
            t = t[:-len(suf)]
    return t or os.path.basename(path)


def softmax(v):
    e = np.exp(v - np.max(v))
    return e / e.sum()


def load_model(path, threads):
    try:
        interp = TFLiteInterpreter(model_path=path, num_threads=threads)
    except TypeError:
        interp = TFLiteInterpreter(model_path=path)
    interp.allocate_tensors()
    return {'interp': interp,
            'in_det': interp.get_input_details()[0],
            'out_det': interp.get_output_details()[0]}


def predict_scaled(m, x_scaled):
    """GIU NGUYEN logic tu notebook PC -> ket qua du doan khong doi."""
    in_det, out_det, interp = m['in_det'], m['out_det'], m['interp']
    # Model CNN/LSTM nhan input 3D (1,37,1) hoac (1,1,37); DNN nhan 2D (1,37).
    # Nan lai cho khop dung shape ma interpreter khai bao.
    _want = tuple(int(d) for d in in_det['shape'])
    if x_scaled.shape != _want:
        x_scaled = x_scaled.reshape(_want)
    if in_det['dtype'] in (np.int8, np.uint8):
        s, z = in_det['quantization']
        if s > 0:
            xq = np.clip(np.round(x_scaled / s + z), -128, 127).astype(in_det['dtype'])
            interp.set_tensor(in_det['index'], xq)
        else:
            interp.set_tensor(in_det['index'], x_scaled.astype(in_det['dtype']))
    else:
        interp.set_tensor(in_det['index'], x_scaled.astype(in_det['dtype']))
    interp.invoke()
    y = interp.get_tensor(out_det['index'])
    if out_det['dtype'] in (np.int8, np.uint8):
        s, z = out_det['quantization']
        if s > 0:
            y = (y.astype('float32') - z) * s
    probs = y[0].astype('float64')
    if np.any(probs < 0) or not np.isclose(probs.sum(), 1.0, atol=0.05):
        probs = softmax(probs)
    else:
        probs = probs / probs.sum()
    return int(np.argmax(probs)), probs


class NumpyScaler:
    """Duong lui khi Pi khong cai duoc scikit-learn.
       StandardScaler.transform == (x - mean_) / scale_  -> ket qua y het."""
    def __init__(self, mean, scale):
        self.mean_ = np.asarray(mean, dtype='float64')
        self.scale_ = np.asarray(scale, dtype='float64')
        self.n_features_in_ = len(self.mean_)
    def transform(self, X):
        return (np.asarray(X, dtype='float64') - self.mean_) / self.scale_


def load_scaler(scaler_path, params_path):
    """Uu tien unpickle (giong het PC). Neu thieu sklearn -> dung scaler_params.json."""
    if scaler_path:
        try:
            sc = pickle.load(open(scaler_path, 'rb'))
            return sc, f'pickle ({type(sc).__name__})'
        except Exception:
            pass
    if params_path:
        d = json.load(open(params_path))
        return NumpyScaler(d['mean'], d['scale']), 'scaler_params.json (numpy)'
    sys.exit('ERR khong nap duoc scaler (thieu sklearn -> tao scaler_params.json '
             'tu PC: {"mean": sc.mean_.tolist(), "scale": sc.scale_.tolist()})')


# ══════════════════════════════════════════════════════════════════════════════
# GIAI DOAN 1 — TRICH XUAT (doc pcap MOT LAN cho ca N model)
# ══════════════════════════════════════════════════════════════════════════════
def extract_windows(pcap_paths, window, max_windows):
    """Lay cua so trai deu tren cac file. Tra (X_raw, y_true, t_extract_total).
       y_true suy tu TEN FILE (moi file = 1 loai tan cong, theo CICIoT2023)."""
    labeled = [(p, label_from_filename(p)[0]) for p in pcap_paths]
    usable  = [(p, y) for p, y in labeled if y is not None]
    skipped = [os.path.basename(p) for p, y in labeled if y is None]
    if skipped:
        print(f'  [!] bo qua {len(skipped)} file khong suy duoc nhan: '
              f'{", ".join(skipped[:4])}{" ..." if len(skipped) > 4 else ""}')
    if not usable:
        sys.exit('ERR khong file nao suy duoc nhan — kiem tra LABEL_RULES')

    # max_windows = 0 -> lay TAT CA cua so (giu nguyen phan bo lop nhu ban Kaggle).
    # max_windows > 0 -> chia deu cho moi file: nhanh, nhung phan bo lop bi CAN
    #   BANG GIA TAO va chi lay phan DAU moi file -> chi so chat luong se KHONG
    #   khop ban Kaggle. Chi dung khi can uoc luong thoi gian.
    unlimited = (max_windows is None or max_windows <= 0)
    per_file = None if unlimited else max(1, int(np.ceil(max_windows / len(usable))))

    # Gom theo KHOI numpy thay vi list Python. Mot hang list[37 float] ton
    # ~1264 byte (moi so la mot doi tuong Python rieng) trong khi numpy chi ton
    # 148 byte. Voi ~1.2 trieu cua so, khac biet nay la ~1.3 GB va chinh no la
    # dinh RAM cua ca chuong trinh — cao hon nhieu lan bo nho that su cua model.
    BLK = 65536
    blocks, ys_blocks = [], []
    buf  = np.empty((BLK, NUM_FEATURES), dtype='float32')
    ybuf = np.empty(BLK, dtype='int16')
    k = total = 0
    t_total = 0.0

    for path, y in usable:
        if not unlimited and total >= max_windows:
            break
        take = None if unlimited else min(per_file, max_windows - total)
        n = 0
        t0 = time.perf_counter()
        for win_idx, vec, ips, ts_s, ts_e in windows_from_pcap(path, window):
            buf[k] = vec; ybuf[k] = y
            k += 1; n += 1; total += 1
            if k == BLK:
                blocks.append(buf.copy()); ys_blocks.append(ybuf.copy()); k = 0
            if take is not None and n >= take:
                break
        t_total += time.perf_counter() - t0

    if k:
        blocks.append(buf[:k].copy()); ys_blocks.append(ybuf[:k].copy())
    if not blocks:
        sys.exit('ERR khong trich duoc cua so nao')
    del buf, ybuf
    return (np.concatenate(blocks), np.concatenate(ys_blocks), t_total)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(
        description='Do hieu suat (Exec Rate / CPU / RAM) tren Raspberry Pi 4.')
    ap.add_argument('--pcaps-dir',  default=None, help="mac dinh: './unb pcaps'")
    ap.add_argument('--models-dir', default=None, help="mac dinh: './tflite models'")
    ap.add_argument('--model-glob', default='*.tflite')
    ap.add_argument('--max-windows', type=int, default=0,
                    help='so cua so dung de do. 0 = TAT CA (mac dinh, de chi so '
                         'chat luong khop ban Kaggle). >0 = lay mau chia deu moi '
                         'file: nhanh nhung chat luong KHONG con doi chieu duoc.')
    ap.add_argument('--repeats', type=int, default=3,
                    help='so lan lap -> lay mean +- std (mac dinh 3)')
    ap.add_argument('--warmup', type=int, default=300,
                    help='so lan invoke bo qua truoc khi bam gio (don vi: CUA SO)')
    ap.add_argument('--threads', type=int, default=1,
                    help='num_threads cua TFLite — PHAI trung voi lan chay PC')
    ap.add_argument('--window', type=int, default=10, help='goi/cua so (tumbling)')
    ap.add_argument('--pilot', action='store_true',
                    help='chay nhanh 1 model, 3000 cua so, 1 lan lap — de uoc luong')
    ap.add_argument('--no-preds', action='store_true',
                    help='khong ghi file du doan (mac dinh CO ghi de doi chieu voi PC)')
    ap.add_argument('--extra', action='store_true',
                    help='in them chi so NGOAI pham vi Realguard (phan vi do tre, bottleneck)')
    ap.add_argument('--out-dir', default=None, help='mac dinh: ./results_pi')
    args = ap.parse_args()

    if args.pilot:
        args.max_windows = 3000 if args.max_windows <= 0 else min(args.max_windows, 3000)
        args.repeats = 1

    global WINDOW
    WINDOW = args.window

    pcaps_dir  = args.pcaps_dir  or find_dir(['unb pcaps', 'unb_pcaps',
                                          'pcaps', 'pcap'])
    models_dir = args.models_dir or find_dir(['tflite models', 'tflite_models',
                                              'tflite-models', 'models'])
    out_dir    = args.out_dir or os.path.join(HERE, 'results_pi')
    os.makedirs(out_dir, exist_ok=True)
    if not pcaps_dir:
        sys.exit("Khong thay thu muc './unb pcaps'")
    if not models_dir:
        sys.exit("Khong thay thu muc './tflite models'")

    pcap_paths = sorted(glob.glob(os.path.join(pcaps_dir, '**', '*.pcap'), recursive=True) +
                        glob.glob(os.path.join(pcaps_dir, '**', '*.pcapng'), recursive=True))
    model_paths = sorted(glob.glob(os.path.join(models_dir, '**', args.model_glob),
                                   recursive=True))
    if not pcap_paths:
        sys.exit(f'Khong co file pcap trong {pcaps_dir}')
    if not model_paths:
        sys.exit(f'Khong co file khop {args.model_glob} trong {models_dir}')
    if args.pilot:
        model_paths = model_paths[-1:]      # 1 model de uoc luong thoi gian

    scaler_path = find_file('scaler_standard*.pkl')
    params_path = find_file('scaler_params*.json')
    feat_path   = find_file('feature_columns*.json')

    run_tag = time.strftime('%Y%m%d_%H%M%S')
    uname = platform.uname()
    ncpu = psutil.cpu_count(logical=True) or 1

    print(f'host={socket.gethostname()} {uname.machine} {uname.system} {uname.release} '
          f'| cpu={ncpu} ram={psutil.virtual_memory().total/1e9:.1f}GB')
    _mw = 'TAT CA' if args.max_windows <= 0 else f'{args.max_windows:,} (lay mau)'
    print(f'runtime={TFLITE_SRC} threads={args.threads} W={WINDOW} '
          f'max_win={_mw} repeats={args.repeats} warmup={args.warmup}')
    if args.max_windows > 0 and not args.pilot:
        print('  [!] Dang LAY MAU chia deu moi file -> phan bo lop bi can bang gia '
              'tao,\n      chi so o bang [A] se KHONG khop ban Kaggle. '
              'Dung --max-windows 0 de doi chieu.')
    print(f'pcaps={len(pcap_paths)} models={len(model_paths)}'
          + ('  [PILOT]' if args.pilot else ''))

    scaler, how = load_scaler(scaler_path, params_path)
    n_in = getattr(scaler, 'n_features_in_', None)
    if n_in != NUM_FEATURES:
        sys.exit(f'ERR scaler={n_in} cot, extractor={NUM_FEATURES} cot')
    if feat_path:
        cols = json.load(open(feat_path))
        if isinstance(cols, dict):
            cols = cols.get('columns', list(cols.values())[0])
        if list(cols) != list(FEATURE_ORDER):
            sys.exit('ERR feature_columns.json khong khop FEATURE_ORDER')
    print(f'scaler={how} features={NUM_FEATURES} ok')

    # ── GIAI DOAN 1: trich xuat ──
    print(f'\n[1] EXTRACT')
    with ResourceSampler(0.5) as rs_ext:
        X_raw, y_all, t_extract_total = extract_windows(
            pcap_paths, WINDOW, args.max_windows)
    n_win = len(X_raw)

    # Do chi phi chuan hoa TRUOC (tren ban goc, tung cua so mot — dung cach
    # pipeline streaming that su chay).
    probe = min(2000, n_win)
    t0 = time.perf_counter()
    for i in range(probe):
        _ = scaler.transform(X_raw[i:i+1])
    t_scale_per_win = (time.perf_counter() - t0) / probe
    t_extract_per_win = t_extract_total / n_win

    # Chuan hoa THEO KHOI, ghi de tai cho. scaler.transform() tra ve float64
    # nen goi mot lan tren ca mang se tao ban sao ~350 MB o 1.2 trieu cua so.
    # Lam theo khoi 65536 hang thi ban sao tam chi ~19 MB, va phep tinh van
    # thuc hien o float64 y het ban chay Kaggle -> chi so o bang [A] trung khop
    # tuyet doi, khong lech do khac do chinh xac dau phay dong.
    X = X_raw                              # ghi de tai cho, khong cap phat moi
    _BLK = 65536
    for _i in range(0, n_win, _BLK):
        X[_i:_i+_BLK] = scaler.transform(X_raw[_i:_i+_BLK]).astype('float32')
    del X_raw
    ext_res = rs_ext.stats()
    print(f'    windows={n_win:,}  t_extract={t_extract_per_win*1000:.4f}ms/win  '
          f't_scale={t_scale_per_win*1000:.4f}ms/win  total={t_extract_total:.1f}s')
    _vc = np.bincount(y_all, minlength=NUM_CLASSES)
    print('    lop: ' + '  '.join(f'{LABEL_NAMES[c]}={_vc[c]:,}'
                                  for c in range(NUM_CLASSES) if _vc[c]))

    # ── GIAI DOAN 2: suy luan ──
    print(f'\n[2] INFER  ({len(model_paths)} models x {n_win:,} windows, batch=1)')
    rows, extra_rows = [], []
    seen = {}
    for mi, mpath in enumerate(model_paths, 1):
        tag = tag_from_path(mpath)
        seen[tag] = seen.get(tag, 0) + 1
        if seen[tag] > 1:
            tag = f'{tag}_{seen[tag]}'
        _rss0 = psutil.Process(os.getpid()).memory_info().rss
        m = load_model(mpath, args.threads)
        _rss_model = (psutil.Process(os.getpid()).memory_info().rss - _rss0) / 1024**2
        size_kb = os.path.getsize(mpath) / 1024.0

        for i in range(min(args.warmup, n_win)):
            predict_scaled(m, X[i:i+1])

        # ── LUOT 1: CHAT LUONG — KHONG bam gio ────────────────────────────
        # Luu y_pred + probs lam ton them ~0.8 us/cua so va ~25 MB bo nho.
        # De hai thu do KHONG lam ban Exec Rate va Peak RAM, luot nay tach
        # rieng va probs duoc GIAI PHONG truoc khi bat dau do thoi gian.
        y_pred = np.empty(n_win, dtype='int16')
        probs  = np.empty((n_win, NUM_CLASSES), dtype='float32')
        for i in range(n_win):
            pred, pr = predict_scaled(m, X[i:i+1])
            y_pred[i] = pred; probs[i] = pr
        acc, mf1, mauc, cm = quality_metrics(y_all, y_pred, probs)
        del probs, y_pred

        # ── LUOT 2: THOI GIAN + TAI NGUYEN — khong luu gi ─────────────────
        infer_times, lat_last = [], None
        with ResourceSampler(0.5) as rs:
            for r in range(args.repeats):
                lat = np.empty(n_win, dtype='float64')
                t_run0 = time.perf_counter()
                for i in range(n_win):
                    t0 = time.perf_counter()
                    predict_scaled(m, X[i:i+1])
                    lat[i] = time.perf_counter() - t0
                infer_times.append(time.perf_counter() - t_run0)
                lat_last = lat
        res = rs.stats()

        infer_per_win = float(np.mean(infer_times)) / n_win
        full_per_win  = t_extract_per_win + t_scale_per_win + infer_per_win
        exec_win_s    = 1.0 / full_per_win
        rates = [1.0 / (t_extract_per_win + t_scale_per_win + t / n_win)
                 for t in infer_times]

        rows.append({
            'model': tag,
            'acc_pct':       round(100 * acc,  4),
            'macro_f1_pct':  round(100 * mf1,  4),
            'macro_auc_pct': round(100 * mauc, 4),
            'exec_win_s':      round(exec_win_s, 1),
            'exec_pkt_s_eq':   round(exec_win_s * WINDOW, 1),
            'exec_std':        round(float(np.std(rates)), 1),
            'lat_full_ms':     round(full_per_win * 1000, 4),
            'lat_infer_ms':    round(infer_per_win * 1000, 4),
            'cpu_1core_pct':   round(res['cpu_avg'], 1),
            'cpu_sys_pct':     round(res['cpu_avg_sys'], 1),
            'ram_avg_mb':      round(res['ram_avg_mb'], 1),
            'ram_peak_mb':     round(res['ram_peak_mb'], 1),
            'ram_model_mb':    round(_rss_model, 1),
            'size_kb':         round(size_kb, 1),
        })
        if args.extra:
            l = lat_last * 1000
            extra_rows.append({
                'model': tag,
                'p50_ms': round(float(np.percentile(l, 50)), 4),
                'p95_ms': round(float(np.percentile(l, 95)), 4),
                'p99_ms': round(float(np.percentile(l, 99)), 4),
                'max_ms': round(float(l.max()), 4),
                'pct_extract': round(100 * t_extract_per_win / full_per_win, 1),
                'pct_scale':   round(100 * t_scale_per_win   / full_per_win, 1),
                'pct_infer':   round(100 * infer_per_win     / full_per_win, 1),
            })
        print(f'    {mi:>2}/{len(model_paths)} {tag:<22} '
              f'acc {100*acc:6.2f} f1 {100*mf1:6.2f} auc {100*mauc:6.2f} | '
              f'{exec_win_s:7,.0f} win/s {exec_win_s*WINDOW:8,.0f} pkt/s | '
              f'cpu {res["cpu_avg_sys"]:4.1f}% ram {res["ram_peak_mb"]:5.0f}MB')
        del m

    # ── BANG ──
    def show(title, cols, data):
        print('\n' + title)
        w = {c: max(len(c), *(len(f'{r[c]:,}' if isinstance(r[c], (int, float))
                              else str(r[c])) for r in data)) for c in cols}
        line = '  '.join(c.rjust(w[c]) for c in cols)
        print(line); print('-' * len(line))
        for r in data:
            print('  '.join((f'{r[c]:,}' if isinstance(r[c], (int, float))
                             else str(r[c])).rjust(w[c]) for c in cols))

    data = sorted(rows, key=lambda r: -r['exec_win_s'])
    show('[A] CHAT LUONG  (doi chieu voi ban chay Kaggle)',
         ['model', 'acc_pct', 'macro_f1_pct', 'macro_auc_pct'],
         sorted(rows, key=lambda r: -r['macro_f1_pct']))
    show('[B1] EXEC RATE + LATENCY  (full pipeline)',
         ['model', 'exec_win_s', 'exec_pkt_s_eq', 'exec_std',
          'lat_full_ms', 'lat_infer_ms'], data)
    show('[B2] RESOURCE',
         ['model', 'cpu_1core_pct', 'cpu_sys_pct', 'ram_avg_mb', 'ram_peak_mb',
          'ram_model_mb', 'size_kb'], data)
    if args.extra and extra_rows:
        show('[EXTRA] latency percentiles + bottleneck share',
             ['model', 'p50_ms', 'p95_ms', 'p99_ms', 'max_ms',
              'pct_extract', 'pct_scale', 'pct_infer'],
             sorted(extra_rows, key=lambda r: r['p95_ms']))

    print(f'\nshared: t_extract={t_extract_per_win*1000:.4f}ms/win '
          f't_scale={t_scale_per_win*1000:.4f}ms/win | '
          f'pkt_s_eq = win_s x {WINDOW} | cpu_sys = cpu_1core / {ncpu}')

    # ── XUAT FILE ──
    import csv as _csv
    def write_csv(name, data_rows):
        p = os.path.join(out_dir, name)
        with open(p, 'w', newline='') as f:
            w = _csv.DictWriter(f, fieldnames=list(data_rows[0].keys()))
            w.writeheader(); w.writerows(data_rows)
        return p

    written = [write_csv(f'B_runtime_PI_{run_tag}.csv', data)]
    if args.extra and extra_rows:
        written.append(write_csv(f'EXTRA_runtime_PI_{run_tag}.csv', extra_rows))

    env = {'run_tag': run_tag, 'platform': 'raspberry_pi_edge_gateway',
           'hostname': socket.gethostname(), 'machine': uname.machine,
           'system': f'{uname.system} {uname.release}', 'cpu_logical': ncpu,
           'ram_total_gb': round(psutil.virtual_memory().total/1e9, 2),
           'tflite_src': TFLITE_SRC, 'tflite_threads': args.threads,
           'window': WINDOW, 'n_windows': int(n_win), 'n_models': len(model_paths),
           'warmup_windows': args.warmup, 'repeats': args.repeats,
           'sampling': ('all' if args.max_windows <= 0 else
                        f'per_file_{args.max_windows}'),
           'scaler_source': how, 'pilot': bool(args.pilot),
           'n_classes_present': int((np.bincount(y_all,
               minlength=NUM_CLASSES) > 0).sum()),
           't_extract_total_s': round(t_extract_total, 2),
           't_extract_per_win_ms': round(t_extract_per_win*1000, 5),
           't_scale_per_win_ms': round(t_scale_per_win*1000, 5),
           'extract_cpu_1core': round(ext_res['cpu_avg'], 1),
           'extract_cpu_sys': round(ext_res['cpu_avg_sys'], 1),
           'extract_ram_peak_mb': round(ext_res['ram_peak_mb'], 1)}
    p = os.path.join(out_dir, f'ENV_PI_{run_tag}.json')
    json.dump(env, open(p, 'w'), indent=2); written.append(p)

    print('\nout: ' + out_dir)
    for p in written:
        print(f'  {os.path.basename(p)}')

    if args.pilot:
        ipw = data[0]['lat_infer_ms'] / 1000.0
        nm = len(glob.glob(os.path.join(models_dir, '**', args.model_glob), recursive=True))
        MAXW, REPS = 30000, 3
        t_ext = t_extract_per_win * MAXW
        t_inf = ipw * MAXW * REPS * nm
        print(f'\nEST full run ({nm} models x {MAXW:,} win x {REPS}): '
              f'extract {t_ext/60:.1f}min + infer {t_inf/60:.1f}min '
              f'= {(t_ext+t_inf)/60:.1f}min')
        print(f'  python3 bench_pi.py --max-windows {MAXW} --repeats {REPS} '
              f'--threads {args.threads}')


if __name__ == '__main__':
    main()
