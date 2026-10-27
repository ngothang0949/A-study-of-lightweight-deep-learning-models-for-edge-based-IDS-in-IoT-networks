#!/usr/bin/env python3
"""
live_infer.py — Console IDS thoi gian thuc (RPi4 / aarch64)
============================================================
Giao dien kieu msfconsole: chay khong tham so -> hien huong dan + danh sach
model, roi go lenh `run ...`.

    python3 live_infer.py
    ids> run 1 --iface eth0
    ids> run 2 --pcap "unb pcaps"

Dat NGANG CAP voi bench_pi.py — extractor, scaler va ham suy luan deu IMPORT
truc tiep tu bench_pi.py, khong copy. Nho vay vector 37 dac trung o day va o
ban do hieu qua tren Kaggle la MOT, khong the lech nhau.

Moi cua so = 10 goi tin (tumbling). Du 10 goi -> tao vector -> suy luan -> in
ngay. KHONG gom nhieu cua so, KHONG vote theo lo.
"""
import argparse, glob, json, os, re, shlex, signal, socket, sys, time
from collections import Counter, deque
from datetime import datetime

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    import bench_pi as B
except ImportError as e:
    sys.exit(f'ERR khong import duoc bench_pi.py ({e}).\n'
             f'    Dat live_infer.py CUNG THU MUC voi bench_pi.py.')
try:
    import dpkt
except ImportError:
    sys.exit('ERR thieu dpkt  ->  pip3 install dpkt')

LABEL_NAMES = B.LABEL_NAMES
NUM_CLASSES = B.NUM_CLASSES
WINDOW      = 10
PIPE_PATH   = os.path.join(HERE, 'pcap_container', 'ids_pipe.pcap')
PIPE_TIMEOUT = 60          # doi capture.sh tao FIFO (giay)

def _ctx_of(raw):
    """Lay src_ip tu goi tho. Ham RIENG, khong dung _per_packet — giu nguyen
       ven cac ham trich xuat da kiem chung."""
    try:
        eth = dpkt.ethernet.Ethernet(raw)
        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP):
            return None
        return socket.inet_ntoa(ip.src)
    except Exception:
        return None

def wait_for_pipe(path, timeout=PIPE_TIMEOUT):
    t0 = time.time()
    shown = False
    while time.time() - t0 < timeout:
        if os.path.exists(path):
            return True
        if not shown:
            print(f'  [cho] Chua thay FIFO: {path}')
            print(f'  [cho] Mo terminal KHAC va chay:  bash {os.path.join(HERE, "capture.sh")}')
            print(f'  [cho] Doi toi da {timeout}s...')
            shown = True
        time.sleep(0.5)
    return False


def windows_from_fifo(pipe_path, want_ctx):
    """Doc FIFO tcpdump dang ghi. Yield (idx, vec37, ctx) ngay khi du 10 goi."""
    if not wait_for_pipe(pipe_path):
        sys.exit(f'ERR het {PIPE_TIMEOUT}s ma khong thay FIFO. Da chay capture.sh chua?')
    print(f'  [live] Mo FIFO {pipe_path} — doi tcpdump ghi header pcap...')
    with open(pipe_path, 'rb') as f:
        reader = dpkt.pcap.Reader(f)
        print('  [live] Da nhan header — bat dau doc goi song.\n')
        buf, ctx, prev_ts, idx, t_ext = [], [], None, 0, 0.0
        for ts, raw in reader:
            _t = time.perf_counter()
            pp = B._per_packet(ts, raw, prev_ts)
            t_ext += time.perf_counter() - _t
            if pp is None:
                continue
            prev_ts = ts
            buf.append(pp)
            if want_ctx:
                ctx.append(_ctx_of(raw))
            if len(buf) == WINDOW:
                idx += 1
                _t = time.perf_counter()
                vec = B._aggregate(buf)
                t_ext += time.perf_counter() - _t
                yield idx, vec, (ctx[:] if want_ctx else None), buf[-1]['ts'], t_ext
                buf, ctx, t_ext = [], [], 0.0


def windows_from_pcaps(pcap_dir, want_ctx, limit=0):
    """Doc lan luot moi *.pcap trong thu muc, cung quy tac cua so tumbling."""
    files = sorted(glob.glob(os.path.join(pcap_dir, '**', '*.pcap'), recursive=True) +
                   glob.glob(os.path.join(pcap_dir, '**', '*.pcapng'), recursive=True))
    if not files:
        sys.exit(f'ERR khong co file pcap trong {pcap_dir}')
    idx = 0
    for p in files:
        with open(p, 'rb') as f:
            try:
                reader = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0); reader = dpkt.pcapng.Reader(f)
            buf, ctx, prev_ts, t_ext = [], [], None, 0.0
            for ts, raw in reader:
                _t = time.perf_counter()
                pp = B._per_packet(ts, raw, prev_ts)
                t_ext += time.perf_counter() - _t
                if pp is None:
                    continue
                prev_ts = ts
                buf.append(pp)
                if want_ctx:
                    ctx.append(_ctx_of(raw))
                if len(buf) == WINDOW:
                    idx += 1
                    _t = time.perf_counter()
                    vec = B._aggregate(buf)
                    t_ext += time.perf_counter() - _t
                    yield idx, vec, (ctx[:] if want_ctx else None), buf[-1]['ts'], t_ext
                    buf, ctx, t_ext = [], [], 0.0
                    if limit and idx >= limit:
                        return

def discover_models(models_dir=None, pattern='*.tflite'):
    d = models_dir or B.find_dir(['tflite models', 'tflite_models',
                                  'tflite-models', 'models'])
    if not d:
        sys.exit("ERR khong thay thu muc './tflite models'")
    paths = sorted(glob.glob(os.path.join(d, '**', pattern), recursive=True))
    if not paths:
        sys.exit(f'ERR khong co {pattern} trong {d}')
    out, seen = [], {}
    for p in paths:
        t = B.tag_from_path(p)
        seen[t] = seen.get(t, 0) + 1
        if seen[t] > 1:
            t = f'{t}_{seen[t]}'
        out.append({'tag': t, 'path': p, 'size_kb': os.path.getsize(p) / 1024.0})
    return d, out


def load_shared(threads):
    scaler, how = B.load_scaler(B.find_file('scaler_standard*.pkl'),
                                B.find_file('scaler_params*.json'))
    if getattr(scaler, 'n_features_in_', None) != B.NUM_FEATURES:
        sys.exit(f'ERR scaler khong khop {B.NUM_FEATURES} cot')
    fp = B.find_file('feature_columns*.json')
    if fp:
        cols = json.load(open(fp))
        if isinstance(cols, dict):
            cols = cols.get('columns', list(cols.values())[0])
        if list(cols) != list(B.FEATURE_ORDER):
            sys.exit('ERR feature_columns.json khong khop FEATURE_ORDER')
    return scaler, how

def do_run(a, MODELS, models_dir):
    if bool(a.iface) == bool(a.pcap):
        print('  [!] Phai chon DUNG MOT trong hai: --iface <ten> HOAC --pcap <thu muc>')
        return
    if not (1 <= a.model <= len(MODELS)):
        print(f'  [!] so model phai trong khoang 1..{len(MODELS)} (go `models` de xem lai)')
        return
    if a.context and not a.iface:
        print('  [i] --context chi co y nghia voi --iface (can timestamp goi song); bo qua.')
    want_ctx = a.context and bool(a.iface)

    m = dict(MODELS[a.model - 1])   # 1 model duy nhat
    scaler, how = load_shared(a.threads)
    print(f'  scaler   : {how}')
    print(f'  model    : #{a.model} {m["tag"]}  | threads={a.threads} | W={WINDOW} goi/cua so')

    m.update(B.load_model(m['path'], a.threads))
    m['t_infer'] = 0.0
    m['n'] = 0
    print(f'  nguon    : ' + (f'iface {a.iface} (qua FIFO capture.sh)' if a.iface
                              else f'pcap {a.pcap}'))

    # ── Tim tien trinh tcpdump (chi can khi --iface) de do "pipeline day du" ──
    tcpdump_pid = None
    if a.iface:
        tcpdump_pid = B.find_pid_by_cmdline('tcpdump', os.path.basename(PIPE_PATH))
        if tcpdump_pid is None:
            print('  [!] Khong tim thay tien trinh tcpdump dang ghi FIFO nay -> '
                  'se KHONG do duoc "pipeline day du" (chi do rieng phan Python).')
        else:
            print(f'  tcpdump  : pid={tcpdump_pid} (gop vao do "pipeline day du")')
    print('  Ctrl+C de dung va xem tong ket.\n')

    if a.iface:
        src = windows_from_fifo(PIPE_PATH, want_ctx)
    else:
        d = a.pcap if os.path.isabs(a.pcap) else os.path.join(HERE, a.pcap)
        if not os.path.isdir(d):
            print(f'  [!] Khong thay thu muc: {d}'); return
        _nf = len(glob.glob(os.path.join(d, '**', '*.pcap'), recursive=True) +
                  glob.glob(os.path.join(d, '**', '*.pcapng'), recursive=True))
        print(f'  [pcap] {_nf} file trong {d}\n')
        src = windows_from_pcaps(d, want_ctx, a.limit)

    hdr = ' '.join(f'{LABEL_NAMES[c][:6]:>6}' for c in range(NUM_CLASSES))
    if a.iface:
        print(f'{"win":>7} | {hdr} | {"du doan":>10} {"infer_ms":>9} '
              f'{"lat_pipe":>9} {"lat_e2e":>9}')
        print('-' * (14 + len(hdr) + 40))
        print('          infer_ms = thoi gian suy luan cua model (1 lan invoke)')
        print('          lat_pipe = trich xuat + chuan hoa + suy luan (KHONG gom tcpdump)')
        print('          lat_e2e  = tu luc goi cuoi cua so duoc BAT (tcpdump) '
              'toi luc co ket qua (do truc tiep bang timestamp goi that)')
    else:
        print(f'{"win":>7} | {hdr} | {"du doan":>10} {"infer_ms":>9} {"lat_pipe":>9}')
        print('-' * (14 + len(hdr) + 30))
        print('          infer_ms = thoi gian suy luan cua model (1 lan invoke)')
        print('          lat_pipe = trich xuat + chuan hoa + suy luan '
              '(doc PCAP tinh, khong co tcpdump)')
    print()

    n_win = 0
    t_scale_tot = t_ext_tot = t_e2e_tot = 0.0
    t_wall0 = time.perf_counter()
    ctr_ip = Counter()
    last_ts = None
    stop = {'v': False}
    rs_pipe = B.ResourceSampler(0.5)
    rs_pipe.__enter__()
    rs_full = None
    if a.iface and tcpdump_pid is not None:
        rs_full = B.ResourceSampler(0.5, pids=[os.getpid(), tcpdump_pid])
        rs_full.__enter__()

    def _sig(s_, f_):
        stop['v'] = True
    old = signal.signal(signal.SIGINT, _sig)

    try:
        for idx, vec, ctx, ts, t_ext in src:
            if stop['v']:
                break
            n_win += 1
            last_ts = ts
            t_ext_tot += t_ext
            x_raw = np.asarray(vec, dtype='float32').reshape(1, -1)
            t0 = time.perf_counter()
            x = np.asarray(scaler.transform(x_raw), dtype='float32')
            t_sc = time.perf_counter() - t0
            t_scale_tot += t_sc

            t0 = time.perf_counter()
            pred, probs = B.predict_scaled(m, x)
            dt = time.perf_counter() - t0
            m['t_infer'] += dt; m['n'] += 1

            show = (n_win % a.every == 0)
            if show:
                pct = ' '.join(f'{100*p:6.1f}' for p in probs)
                lat_pipe = t_ext + t_sc + dt      # DO TRUC TIEP: tong 3 muc do rieng
                if a.iface:
                    lat_e2e = time.time() - ts    # DO TRUC TIEP: timestamp goi that (tcpdump) -> bay gio
                    t_e2e_tot += lat_e2e
                    print(f'{idx:>7} | {pct} | {LABEL_NAMES[pred]:>10} '
                          f'{dt*1000:>9.4f} {lat_pipe*1000:>9.4f} {lat_e2e*1000:>9.4f}',
                          flush=True)
                else:
                    print(f'{idx:>7} | {pct} | {LABEL_NAMES[pred]:>10} '
                          f'{dt*1000:>9.4f} {lat_pipe*1000:>9.4f}', flush=True)
            elif a.iface:
                t_e2e_tot += time.time() - ts

            if want_ctx and ctx:
                for s_ in ctx:
                    if s_: ctr_ip[s_] += 1
                if show:
                    tops = ', '.join(f'{k}({v})' for k, v in ctr_ip.most_common(3))
                    tstr = datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3]
                    print(f'          ctx @{tstr}  src: {tops}', flush=True)
    except (KeyboardInterrupt, StopIteration):
        pass
    finally:
        signal.signal(signal.SIGINT, old)
        rs_pipe.__exit__(None, None, None)
        if rs_full is not None:
            rs_full.__exit__(None, None, None)
    res_pipe = rs_pipe.stats()
    res_full = rs_full.stats() if rs_full is not None else None

    elapsed = time.perf_counter() - t_wall0
    if n_win == 0:
        print('\n  [!] Khong bat duoc cua so nao.')
        return

    # ── Tong ket ─────────────────────────────────────────────────────────────
    # Tat ca deu la gia tri DO TRUC TIEP (perf_counter / timestamp goi that),
    # roi lay trung binh cong tren cac mau da do — KHONG suy nguoc tu 1 con so
    # tinh san khac.
    t_scale_win = t_scale_tot / n_win
    t_ext_win   = t_ext_tot / n_win
    infer_win   = m['t_infer'] / m['n']
    lat_pipe_win = t_ext_win + t_scale_win + infer_win
    print(f'\n{"="*60}')
    print(f'TONG KET  model={m["tag"]}  windows={n_win:,}  goi~{n_win*WINDOW:,}  '
          f'{elapsed:.1f}s')
    print('='*60)
    print(f'  infer_ms  (suy luan / cua so)              : {infer_win*1000:9.4f}')
    print(f'  lat_pipe_ms (trich xuat+chuan hoa+suy luan): {lat_pipe_win*1000:9.4f}')
    if a.iface:
        e2e_win = t_e2e_tot / n_win
        print(f'  lat_e2e_ms  (tcpdump bat goi -> co ket qua): {e2e_win*1000:9.4f}')
    print(f'  thong luong thuc do                        : {n_win/elapsed:9,.1f} cua so/s '
          f'({n_win*WINDOW/elapsed:,.0f} goi/s)')

    ncpu = B.psutil.cpu_count(logical=True) or 1
    print(f'''
TAI NGUYEN — PIPELINE RIENG (trich xuat -> chuan hoa -> suy luan, tien trinh live_infer.py)
  CPU  trung binh {res_pipe['cpu_avg_sys']:5.1f}% / dinh {res_pipe['cpu_max_sys']:5.1f}%   (thang toan may {ncpu} nhan)
  RAM  trung binh {res_pipe['ram_avg_mb']:7.1f} MB / dinh {res_pipe['ram_peak_mb']:7.1f} MB''')
    if res_full is not None:
        print(f'''
TAI NGUYEN — PIPELINE DAY DU (tcpdump bat goi + live_infer.py, KHONG gom tien trinh khac)
  CPU  trung binh {res_full['cpu_avg_sys']:5.1f}% / dinh {res_full['cpu_max_sys']:5.1f}%   (thang toan may {ncpu} nhan, {res_full['n_procs']} tien trinh)
  RAM  trung binh {res_full['ram_avg_mb']:7.1f} MB / dinh {res_full['ram_peak_mb']:7.1f} MB''')
    elif a.iface:
        print('\n  [!] Khong co so lieu "pipeline day du" (khong tim thay tcpdump).')

    if want_ctx and ctr_ip:
        print(f'\nNGU CANH TICH LUY (den {datetime.fromtimestamp(last_ts).strftime("%H:%M:%S")}):')
        print('  top src ip : ' + ', '.join(f'{k} ({v} goi)'
                                            for k, v in ctr_ip.most_common(5)))

HELP = """
LENH
  run <so_model> <tham so>   chay suy luan VOI DUNG 1 MODEL
  models                     in lai danh sach model
  help                       hien tro giup nay
  exit / quit                thoat

THAM SO CUA `run`   (bat buoc chon DUNG MOT nguon: --iface hoac --pcap)
  <so_model>          BAT BUOC, dung dau tien, vd: run 15 --iface eth0
  --iface <ten>       bat goi song qua FIFO cua capture.sh, vd: --iface eth0
  --pcap <thu muc>    chay tren pcap co san,        vd: --pcap "unb pcaps"
  --context           in top src ip kem timestamp (chi dung voi --iface)
  --every <n>         chi in 1 dong moi n cua so (mac dinh 1)
  --limit <n>         dung sau n cua so (0 = khong gioi han, chi voi --pcap)
  --threads <n>       num_threads TFLite (mac dinh 1, nen trung bench_pi.py)

VI DU
  run 1 --iface eth0
  run 3 --iface eth0 --context
  run 2 --pcap "unb pcaps" --every 50
  run 2 --pcap "unb pcaps" --limit 2000
"""


def build_parser():
    p = argparse.ArgumentParser(prog='run', add_help=False)
    p.add_argument('model', type=int, help='so thu tu model (xem lenh `models`)')
    p.add_argument('--iface', default=None)
    p.add_argument('--pcap', default=None)
    p.add_argument('--context', action='store_true')
    p.add_argument('--every', type=int, default=1)
    p.add_argument('--limit', type=int, default=0)
    p.add_argument('--threads', type=int, default=1)
    return p


def show_models(MODELS, models_dir):
    print(f'\nMODEL ({len(MODELS)}) trong {models_dir}:')
    print(f'  {"#":>3}  {"tag":<32}{"KB":>9}')
    print('  ' + '-' * 46)
    for i, m in enumerate(MODELS, 1):
        print(f'  {i:>3}  {m["tag"]:<32}{m["size_kb"]:>9.1f}')


def main():
    models_dir, MODELS = discover_models()
    print(BANNER)
    show_models(MODELS, models_dir)
    print(HELP)
    print(f'  [i] Truoc khi chay --iface, mo terminal KHAC va chay:')
    print(f'      bash {os.path.join(HERE, "capture.sh")}')
    print(f'      (live_infer se doi FIFO toi da {PIPE_TIMEOUT}s)\n')

    parser = build_parser()
    while True:
        try:
            raw = input('ids> ').strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if not raw:
            continue
        parts = shlex.split(raw)
        cmd, rest = parts[0].lower(), parts[1:]
        if cmd in ('exit', 'quit'):
            break
        if cmd == 'help':
            print(HELP); continue
        if cmd == 'models':
            show_models(MODELS, models_dir); continue
        if cmd != 'run':
            print(f'  [!] Lenh la: run | models | help | exit'); continue
        try:
            a = parser.parse_args(rest)
        except SystemExit:
            print('  [!] Tham so sai. Go `help` de xem.'); continue
        try:
            do_run(a, MODELS, models_dir)
        except SystemExit as e:
            print(f'  [!] {e}')
        except Exception as e:
            print(f'  [!] Loi: {e.__class__.__name__}: {e}')
    print('Thoat.')


if __name__ == '__main__':
    main()
