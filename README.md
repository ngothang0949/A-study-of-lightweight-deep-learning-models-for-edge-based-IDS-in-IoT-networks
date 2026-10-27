# Lightweight Deep Learning for Edge Intrusion Detection in IoT Networks

**[English](#english) | [Tiếng Việt](#tiếng-việt)**

---

# English

**Graduation thesis – Information Security**
**Topic:** Research on lightweight deep learning models for an edge intrusion detection system in IoT networks – Subsystem 1

- **Student:** Ngo Duc Thang (ID: B2203737)
- **Supervisor:** Dr. Tran Thi To Quyen

## Contents

- [1. Introduction](#1-introduction)
- [2. Files in this repo](#2-files-in-this-repo)
- [3. Student training notebooks](#3-student-training-notebooks)
- [4. Convert models to TFLite](#4-convert-models-to-tflite)
- [5. Benchmark on Raspberry Pi 4](#5-benchmark-on-raspberry-pi-4)
- [6. Live detection](#6-live-detection)
- [7. Requirements](#7-requirements)
- [8. Notes](#8-notes)

## 1. Introduction

IoT devices are growing fast, but they are often weak in security. Big deep learning models are hard to run on edge devices. So this thesis uses **knowledge distillation** to make small student models that learn from big teacher models.

What I did in this repo:

- Preprocess CICIoT2023 into **37 features** (window of 10 packets).
- Train student models (CNN, DNN, SSL-CL-DNN) with **Hinton KD**, **RAID-KL** and **FitNets**.
- Convert models from PyTorch (`.pth`) to TFLite.
- Measure accuracy, speed, CPU and RAM on a real **Raspberry Pi 4**.
- Run a simple live detection demo with `tcpdump`.

Task: multi-class classification with **8 labels**: Benign, DDoS, DoS, BruteForce, Spoofing, Recon, Web-Based, Mirai.

The files below are not numbered. Each one does a separate job. A suggested flow is at the end of section 2.

## 2. Files in this repo

**Data preprocessing**

- `37ft-preprocessing` – Preprocess the data down to 37 features, as proposed in the appendix of the thesis. This is the dataset used for training.
- `39ft-preprocessing` – My try to rebuild the feature extraction code that the authors published on the official CIC UNB website, which gives 39 features. It is used to compare with the 37 feature version.
- `300k-packets-pcap-capping` – Cut the first 300k continuous packets from the chosen PCAP files (except benign traffic). These files are used to test accuracy and performance on the edge device.

**Training students (6 notebooks)**

- `hinton-kd-and-raid-kl-cnn-on-kaggle-trainning`
- `hinton-kd-and-raid-kl-dnn-on-kaggle-trainning`
- `hinton-kd-and-raid-kl-ssl-cl-dnn-on-kaggle-trainning`
- `fitnets-cnn-on-kaggle-trainning`
- `fitnets-dnn-on-kaggle-trainning`
- `fitnets-ssl-cl-dnn-on-kaggle-trainning`

Details are in [section 3](#3-student-training-notebooks).

**Convert and test on edge**

- `pth-to-tflite-models-on-kaggle-converting` – Convert PyTorch `.pth` models to TensorFlow Lite FP32. This format fits IoT edge devices better. Details in [section 4](#4-convert-models-to-tflite).
- `bench_pi.py` – Load all TFLite models and test them on all the PCAP data, directly on Raspberry Pi 4. It measures effectiveness and performance. Details in [section 5](#5-benchmark-on-raspberry-pi-4).

**Live detection**

- `capture.sh` – Use `tcpdump` to push live traffic into a pipe (FIFO) for online attack detection.
- `live_infer.py` – Program that reads the pipe (or PCAP files) and detects attacks with the model you choose. Details in [section 6](#6-live-detection).

**Suggested flow**

1. Preprocess data (`37ft-preprocessing`, optional `39ft-preprocessing`).
2. Train teachers (done in another part of the thesis) and train students (6 notebooks).
3. Convert to TFLite.
4. Cut PCAP files (`300k-packets-pcap-capping`).
5. Run `bench_pi.py` on the Pi.
6. Try `capture.sh` + `live_infer.py`.

## 3. Student training notebooks

All 6 notebooks run on Kaggle. They read the same input dataset: `train_standard_p3.2.parquet`, `val_standard_p3.2.parquet`, `test_standard_p3.2.parquet` and `class_weights_p3.2.json`. Class weights are clipped at max 3.0. The random seed is 42. The best weights (lowest validation loss) are saved, and checkpoints are saved every 5 epochs so training can resume.

Edit `INPUT_DIR` and `TEACHER_DIR` (or `TEACHER_PTH`) at the top of each notebook to match your own Kaggle datasets.

Every notebook ends with the test set evaluation, plots (loss curves, confusion matrices, macro-F1 bars) and config export.

### 3.1. `hinton-kd-and-raid-kl-*` (3 students in one run)

Each notebook trains **3 students at the same time** on the same batches, from the same teacher:

- **Hinton KD** (vanilla KD) – T = 3, alpha = 0.5.
- **RAID-KL, fixed temperature** – tau = 7, alpha = 0.5, lambda = 0.3.
- **RAID-KL, adaptive temperature** – tau changes per batch in [2, 7], alpha = 0.5, lambda = 0.3. Tau is computed from the cosine similarity between student and teacher features: lower similarity gives higher tau.

So each notebook outputs **3 models**. Names are shown below.

**`hinton-kd-and-raid-kl-cnn-on-kaggle-trainning`**

- Teacher: CNN1D (Keras file `best_model_cnn1d_128_128_256.keras`, converted to PyTorch inside the notebook). Filters `[128, 128, 256]`.
- Student: CNN1D with filters `[32, 32, 64]`, kernel 3, dropout 0.1, ReLU, BatchNorm (11,752 parameters).
- Training: 50 epochs, batch size 512, learning rate 0.00005, weight decay 0.01.
- Output models:
  - `student_cnn_vanilla_kd_classw3_37ft.pth`
  - `student_cnn_fix_t_classw3_37ft.pth`
  - `student_cnn_adapt_t_classw3_37ft.pth`

**`hinton-kd-and-raid-kl-dnn-on-kaggle-trainning`**

- Teacher: DNN (Keras file `dnn_after_optuna_37ft.keras`, converted to PyTorch). Hidden layers `[256, 256, 256]`.
- Student: DNN with hidden layers `[64, 64, 64]`, dropout 0.1, ReLU, BatchNorm (11,656 parameters).
- Training: 50 epochs, batch size 512, learning rate 0.001685, Adam, no weight decay.
- Output models:
  - `student_dnn_vanilla_kd_classw3_37ft.pth`
  - `student_dnn_fix_t_classw3_37ft.pth`
  - `student_dnn_adapt_t_classw3_37ft.pth`

**`hinton-kd-and-raid-kl-ssl-cl-dnn-on-kaggle-trainning`**

- Teacher: SSL-CL-DNN (`teacher_ssl_cl_dnn_after_optuna_37ft.pth`). Encoder `37→512→512→256→256`, classification head `256→256→8`.
- Student: SSL-CL-DNN with encoder `37→128→64→64` and classification head `64→32→8` (19,624 parameters).
- Training: 50 epochs, batch size 128, learning rate 0.0001487, AdamW with weight decay 0.01. Only the supervised fine-tuning stage is distilled. The student does not pretrain again.
- Output models:
  - `student_ssl_cl_dnn_vanilla_kd_classw3_37ft.pth`
  - `student_ssl_cl_dnn_fix_t_classw3_37ft.pth`
  - `student_ssl_cl_dnn_adapt_t_classw3_37ft.pth`

### 3.2. `fitnets-*` (1 student per notebook)

FitNets trains in **2 stages**, one after another:

1. **Hint training** – 50 epochs. The student middle layer is passed through a regressor and matched with the teacher hint layer (MSE loss).
2. **KD training** – 50 epochs. Tau = 3. Lambda goes down linearly from 4 to 1.

Total is 100 epochs. Batch size and learning rate are the same as in section 3.1.

**`fitnets-cnn-on-kaggle-trainning`**

- Same teacher and student as the CNN notebook above.
- Hint is taken after block 2 (teacher 128 channels, student 32 channels).
- Batch size 512, learning rate 0.00005, no weight decay.
- Output model: `student_cnn_fitnets_classw3_37ft.pth`

**`fitnets-dnn-on-kaggle-trainning`**

- Same teacher and student as the DNN notebook above.
- Hint is taken after the middle block (block 2 of 3).
- Batch size 512, learning rate 0.001685, no weight decay.
- Output model: `student_dnn_fitnets__classw3_37ft.pth` (note the double underscore in the code)

**`fitnets-ssl-cl-dnn-on-kaggle-trainning`**

- Same teacher and student as the SSL-CL-DNN notebook above.
- Hint dimension is 512 (teacher) and guided dimension is 64 (student).
- Batch size 128, learning rate 0.0001487, weight decay 0.01.
- Output model: `student_ssl_cl_dnn_fitnets_37ft.pth`

**Total:** 3 notebooks × 3 models + 3 notebooks × 1 model = **12 students**.

## 4. Convert models to TFLite

Notebook: `pth-to-tflite-models-on-kaggle-converting`

What it does:

- Reads the `.pth` files (3 teachers + 12 students = 15 models) from `PTH_DIR`.
- Rebuilds each model in Keras, then converts it to TFLite. It checks the result against a numpy reference.
- Exports `*_fp32.tflite` for each model. The notebook also exports `*_int8.tflite` (dynamic range), but the thesis uses FP32.
- Tests every `.tflite` again on the test set.
- Saves reports, confusion matrices, charts and `summary_all.csv` in `tflite_out/`.

How to use:

1. Upload all `.pth` files to a Kaggle dataset.
2. Set `PTH_DIR` (and `INPUT_DIR`) in cell 1. The file names in `PTH_LIST` must match your files. Missing files are skipped.
3. Run all cells.
4. Download the `.tflite` files from `tflite_out/models/`.

## 5. Benchmark on Raspberry Pi 4

Program: `bench_pi.py`

It loads **all** TFLite models and runs them on **all** PCAP files, directly on the Pi. For every model it reports Accuracy, Macro-F1, Macro-AUC, speed (windows/s, packets/s), latency, CPU and RAM.

The accuracy numbers are a check. If they match the Kaggle results, the feature extractor, scaler and input shape on the Pi are the same as on the PC.

Folder layout (put the script next to these):

```
bench_pi.py
unb pcaps/                 # *.pcap, *.pcapng (labels are taken from the file names)
tflite models/             # *.tflite
scaler_standard*.pkl       # or scaler_params*.json
feature_columns*.json
```

Install:

```bash
pip3 install numpy dpkt psutil tflite-runtime
# scikit-learn is optional if scaler_params.json is provided
```

Run:

```bash
python3 bench_pi.py                       # all windows, 3 repeats
python3 bench_pi.py --pilot               # quick test with 1 model, to estimate time
python3 bench_pi.py --threads 4           # must be the same as the PC run
python3 bench_pi.py --model-glob "*_fp32.tflite"   # only FP32 models
python3 bench_pi.py --max-windows 50000 --repeats 5  # sampling (estimate only)
```

Main options: `--pcaps-dir`, `--models-dir`, `--window` (default 10 packets), `--repeats` (default 3), `--warmup` (default 300), `--threads` (default 1), `--extra`, `--no-preds`, `--out-dir`.

Output goes to `results_pi/`:

- `B_runtime_PI_<time>.csv` – results for each model.
- `ENV_PI_<time>.json` – device and run settings.
- `EXTRA_runtime_PI_<time>.csv` – extra latency numbers (only with `--extra`).
- Prediction files for comparing with the PC (unless `--no-preds`).

## 6. Live detection

Two programs work together. Keep `capture.sh`, `live_infer.py` and `bench_pi.py` in the **same folder**. `live_infer.py` imports the extractor and scaler from `bench_pi.py`, and the folders `tflite models/` and the scaler files must be there too.

**Terminal 1 – capture traffic:**

```bash
bash capture.sh                                   # default interface: eth0
IFACE=wlan0 bash capture.sh                       # other interface
EXCLUDE_HOSTS="192.168.1.50" bash capture.sh      # ignore your own control laptop
```

- It needs `tcpdump` (`sudo apt install -y tcpdump`). The first run asks for `sudo` once to set the capture permission.
- It creates a FIFO at `pcap_container/ids_pipe.pcap`.
- It will wait (hang) until `live_infer.py` opens the other end. This is normal.
- Keep this terminal open.

**Terminal 2 – detect:**

```bash
python3 live_infer.py
```

You get a small console. Type `models` to see the model list, then:

```
ids> run 1 --iface eth0                       # live traffic with model #1
ids> run 3 --iface eth0 --context             # also show top source IPs
ids> run 2 --pcap "unb pcaps" --every 50      # replay PCAP files, print 1 line per 50 windows
ids> run 2 --pcap "unb pcaps" --limit 2000    # stop after 2000 windows
```

Other commands: `models`, `help`, `exit`. Press `Ctrl+C` to stop a run and see the summary. You must pick exactly one source: `--iface` or `--pcap`.

Each line shows the probability of 8 classes, the predicted label, `infer_ms` (model only), `lat_pipe` (extract + scale + infer) and `lat_e2e` (from the packet captured by tcpdump to the result). The summary shows average latency, throughput, CPU and RAM.

## 7. Requirements

- **Kaggle notebooks:** PyTorch, TensorFlow/Keras, pandas, pyarrow, scikit-learn, matplotlib, seaborn.
- **Raspberry Pi 4:** Python 3, `numpy`, `dpkt`, `psutil`, `tflite-runtime` (or `ai-edge-litert` / `tensorflow`), `tcpdump`.

## 8. Notes

- Paths such as `/kaggle/input/datasets/rsnngo/...` are mine. Please change them.
- Use the same `--threads` value on PC and Pi, or the comparison is not fair.
- Do not run `capture.sh` on the same interface you use to control the Pi remotely, unless you set `EXCLUDE_HOSTS`.
- This is a benchmark of the classification module on a real device. It is not a full IDS.

---

# Tiếng Việt

**Luận văn tốt nghiệp – Ngành An toàn thông tin**
**Đề tài:** Nghiên cứu mô hình học sâu gọn nhẹ cho hệ thống phát hiện xâm nhập tại biên trong mạng IoT – Phân hệ 1

- **Sinh viên:** Ngô Đức Thắng (MSSV: B2203737)
- **Giảng viên hướng dẫn:** TS. Trần Thị Tố Quyên

## Mục lục

- [1. Giới thiệu](#1-giới-thiệu)
- [2. Các file trong repo](#2-các-file-trong-repo)
- [3. Các notebook huấn luyện mô hình học sinh](#3-các-notebook-huấn-luyện-mô-hình-học-sinh)
- [4. Chuyển mô hình sang TFLite](#4-chuyển-mô-hình-sang-tflite)
- [5. Đo hiệu suất trên Raspberry Pi 4](#5-đo-hiệu-suất-trên-raspberry-pi-4)
- [6. Phát hiện tấn công trực tuyến](#6-phát-hiện-tấn-công-trực-tuyến)
- [7. Yêu cầu](#7-yêu-cầu)
- [8. Lưu ý](#8-lưu-ý)

## 1. Giới thiệu

Số thiết bị IoT tăng rất nhanh nhưng bảo mật còn yếu. Các mô hình học sâu lớn thì khó chạy trên thiết bị biên. Vì vậy đề tài dùng **chưng cất tri thức** để tạo ra các mô hình học sinh nhỏ, học lại từ các mô hình giáo viên lớn.

Trong repo này em đã làm:

- Tiền xử lý CICIoT2023 còn **37 đặc trưng** (cửa sổ 10 gói tin).
- Huấn luyện mô hình học sinh (CNN, DNN, SSL-CL-DNN) bằng **Hinton KD**, **RAID-KL** và **FitNets**.
- Chuyển mô hình từ PyTorch (`.pth`) sang TFLite.
- Đo độ chính xác, tốc độ, CPU và RAM trên **Raspberry Pi 4** thật.
- Chạy thử phát hiện tấn công trực tuyến bằng `tcpdump`.

Bài toán: phân loại đa lớp **8 nhãn**: Benign, DDoS, DoS, BruteForce, Spoofing, Recon, Web-Based, Mirai.

Các file bên dưới không đánh số thứ tự. Mỗi file làm một việc riêng. Luồng thực hiện gợi ý nằm ở cuối mục 2.

## 2. Các file trong repo

**Tiền xử lý dữ liệu**

- `37ft-preprocessing` – Tiền xử lý dữ liệu còn 37 đặc trưng theo đề xuất ở phụ lục luận văn. Đây là tập dữ liệu dùng để huấn luyện.
- `39ft-preprocessing` – Cố gắng tái hiện lại mã nguồn trích xuất của tác giả đăng trên trang chính thức của CIC UNB, cho ra 39 đặc trưng. Dùng để đối chiếu với bản 37 đặc trưng.
- `300k-packets-pcap-capping` – Cắt 300k gói tin liên tục đầu tiên của các file PCAP được chọn (trừ lưu lượng benign). Các file này dùng để đánh giá hiệu quả và hiệu suất trên thiết bị biên.

**Huấn luyện mô hình học sinh (6 notebook)**

- `hinton-kd-and-raid-kl-cnn-on-kaggle-trainning`
- `hinton-kd-and-raid-kl-dnn-on-kaggle-trainning`
- `hinton-kd-and-raid-kl-ssl-cl-dnn-on-kaggle-trainning`
- `fitnets-cnn-on-kaggle-trainning`
- `fitnets-dnn-on-kaggle-trainning`
- `fitnets-ssl-cl-dnn-on-kaggle-trainning`

Chi tiết ở [mục 3](#3-các-notebook-huấn-luyện-mô-hình-học-sinh).

**Chuyển đổi và kiểm thử trên thiết bị biên**

- `pth-to-tflite-models-on-kaggle-converting` – Chuyển mô hình từ `.pth` của PyTorch sang TensorFlow Lite FP32, phù hợp hơn với thiết bị biên IoT. Chi tiết ở [mục 4](#4-chuyển-mô-hình-sang-tflite).
- `bench_pi.py` – Nạp tất cả mô hình và đánh giá trên toàn bộ dữ liệu PCAP ngay trên Raspberry Pi 4 để đo hiệu quả và hiệu suất. Chi tiết ở [mục 5](#5-đo-hiệu-suất-trên-raspberry-pi-4).

**Phát hiện trực tuyến**

- `capture.sh` – Dùng `tcpdump` đưa lưu lượng mạng ra một pipe (FIFO) để phát hiện tấn công trực tuyến.
- `live_infer.py` – Chương trình đọc pipe (hoặc file PCAP) và phát hiện tấn công bằng mô hình được chọn. Chi tiết ở [mục 6](#6-phát-hiện-tấn-công-trực-tuyến).

**Luồng thực hiện gợi ý**

1. Tiền xử lý dữ liệu (`37ft-preprocessing`, có thể thêm `39ft-preprocessing`).
2. Huấn luyện giáo viên (làm ở phần khác của đề tài) và huấn luyện học sinh (6 notebook).
3. Chuyển sang TFLite.
4. Cắt file PCAP (`300k-packets-pcap-capping`).
5. Chạy `bench_pi.py` trên Pi.
6. Thử `capture.sh` + `live_infer.py`.

## 3. Các notebook huấn luyện mô hình học sinh

Cả 6 notebook chạy trên Kaggle. Chúng dùng chung dữ liệu đầu vào: `train_standard_p3.2.parquet`, `val_standard_p3.2.parquet`, `test_standard_p3.2.parquet` và `class_weights_p3.2.json`. Trọng số lớp bị chặn tối đa 3.0. Random seed là 42. Trọng số tốt nhất (val loss thấp nhất) được lưu lại, checkpoint lưu mỗi 5 epoch để chạy tiếp được khi bị ngắt.

Cần sửa `INPUT_DIR` và `TEACHER_DIR` (hoặc `TEACHER_PTH`) ở đầu mỗi notebook cho đúng với dataset Kaggle của bạn.

Cuối mỗi notebook sẽ đánh giá trên tập test, vẽ biểu đồ (đường mất mát, ma trận nhầm lẫn, cột macro-F1) và xuất file cấu hình.

### 3.1. `hinton-kd-and-raid-kl-*` (3 mô hình trong một lần chạy)

Mỗi notebook huấn luyện **3 mô hình học sinh cùng lúc** trên cùng các lô dữ liệu, từ cùng một giáo viên:

- **Hinton KD** (KD truyền thống) – T = 3, alpha = 0.5.
- **RAID-KL nhiệt độ cố định** – tau = 7, alpha = 0.5, lambda = 0.3.
- **RAID-KL nhiệt độ thích ứng** – tau thay đổi theo từng lô trong khoảng [2, 7], alpha = 0.5, lambda = 0.3. Tau được tính từ độ tương đồng cosine giữa đặc trưng trung gian của học sinh và giáo viên: độ tương đồng càng thấp thì tau càng lớn.

Vì vậy mỗi notebook cho ra **3 mô hình**. Tên các mô hình ở dưới.

**`hinton-kd-and-raid-kl-cnn-on-kaggle-trainning`**

- Giáo viên: CNN1D (file Keras `best_model_cnn1d_128_128_256.keras`, tự chuyển sang PyTorch trong notebook). Số filter `[128, 128, 256]`.
- Học sinh: CNN1D với filter `[32, 32, 64]`, kernel 3, dropout 0.1, ReLU, BatchNorm (11,752 tham số).
- Huấn luyện: 50 epoch, batch size 512, learning rate 0.00005, weight decay 0.01.
- Các mô hình đầu ra:
  - `student_cnn_vanilla_kd_classw3_37ft.pth`
  - `student_cnn_fix_t_classw3_37ft.pth`
  - `student_cnn_adapt_t_classw3_37ft.pth`

**`hinton-kd-and-raid-kl-dnn-on-kaggle-trainning`**

- Giáo viên: DNN (file Keras `dnn_after_optuna_37ft.keras`, tự chuyển sang PyTorch). Các tầng ẩn `[256, 256, 256]`.
- Học sinh: DNN với các tầng ẩn `[64, 64, 64]`, dropout 0.1, ReLU, BatchNorm (11,656 tham số).
- Huấn luyện: 50 epoch, batch size 512, learning rate 0.001685, Adam, không dùng weight decay.
- Các mô hình đầu ra:
  - `student_dnn_vanilla_kd_classw3_37ft.pth`
  - `student_dnn_fix_t_classw3_37ft.pth`
  - `student_dnn_adapt_t_classw3_37ft.pth`

**`hinton-kd-and-raid-kl-ssl-cl-dnn-on-kaggle-trainning`**

- Giáo viên: SSL-CL-DNN (`teacher_ssl_cl_dnn_after_optuna_37ft.pth`). Encoder `37→512→512→256→256`, đầu phân loại `256→256→8`.
- Học sinh: SSL-CL-DNN với encoder `37→128→64→64` và đầu phân loại `64→32→8` (19,624 tham số).
- Huấn luyện: 50 epoch, batch size 128, learning rate 0.0001487, AdamW với weight decay 0.01. Chỉ chưng cất ở giai đoạn tinh chỉnh có giám sát. Học sinh không tiền huấn luyện lại.
- Các mô hình đầu ra:
  - `student_ssl_cl_dnn_vanilla_kd_classw3_37ft.pth`
  - `student_ssl_cl_dnn_fix_t_classw3_37ft.pth`
  - `student_ssl_cl_dnn_adapt_t_classw3_37ft.pth`

### 3.2. `fitnets-*` (mỗi notebook 1 mô hình)

FitNets huấn luyện qua **2 giai đoạn** nối tiếp nhau:

1. **Khớp gợi ý tầng ẩn (hint training)** – 50 epoch. Tầng giữa của học sinh đi qua một regressor rồi được khớp với tầng gợi ý của giáo viên (mất mát MSE).
2. **Chưng cất tri thức (KD training)** – 50 epoch. Tau = 3. Lambda giảm tuyến tính từ 4 về 1.

Tổng cộng 100 epoch. Batch size và learning rate giống mục 3.1.

**`fitnets-cnn-on-kaggle-trainning`**

- Giáo viên và học sinh giống notebook CNN ở trên.
- Gợi ý lấy sau block 2 (giáo viên 128 kênh, học sinh 32 kênh).
- Batch size 512, learning rate 0.00005, không dùng weight decay.
- Mô hình đầu ra: `student_cnn_fitnets_classw3_37ft.pth`

**`fitnets-dnn-on-kaggle-trainning`**

- Giáo viên và học sinh giống notebook DNN ở trên.
- Gợi ý lấy sau block giữa (block 2 trong 3 block).
- Batch size 512, learning rate 0.001685, không dùng weight decay.
- Mô hình đầu ra: `student_dnn_fitnets__classw3_37ft.pth` (trong code có hai dấu gạch dưới liền nhau)

**`fitnets-ssl-cl-dnn-on-kaggle-trainning`**

- Giáo viên và học sinh giống notebook SSL-CL-DNN ở trên.
- Chiều gợi ý là 512 (giáo viên) và chiều guided là 64 (học sinh).
- Batch size 128, learning rate 0.0001487, weight decay 0.01.
- Mô hình đầu ra: `student_ssl_cl_dnn_fitnets_37ft.pth`

**Tổng cộng:** 3 notebook × 3 mô hình + 3 notebook × 1 mô hình = **12 mô hình học sinh**.

## 4. Chuyển mô hình sang TFLite

Notebook: `pth-to-tflite-models-on-kaggle-converting`

Notebook này làm các việc sau:

- Đọc các file `.pth` (3 giáo viên + 12 học sinh = 15 mô hình) từ `PTH_DIR`.
- Dựng lại từng mô hình bằng Keras rồi chuyển sang TFLite. Có kiểm tra kết quả với bản numpy tham chiếu.
- Xuất `*_fp32.tflite` cho mỗi mô hình. Notebook cũng xuất thêm `*_int8.tflite` (dynamic range) nhưng luận văn dùng bản FP32.
- Đánh giá lại từng file `.tflite` trên tập test.
- Lưu báo cáo, ma trận nhầm lẫn, biểu đồ và `summary_all.csv` trong `tflite_out/`.

Cách dùng:

1. Tải toàn bộ file `.pth` lên một dataset Kaggle.
2. Sửa `PTH_DIR` (và `INPUT_DIR`) ở cell 1. Tên file trong `PTH_LIST` phải khớp với file của bạn. File nào thiếu sẽ bị bỏ qua.
3. Chạy tất cả cell.
4. Tải các file `.tflite` về từ `tflite_out/models/`.

## 5. Đo hiệu suất trên Raspberry Pi 4

Chương trình: `bench_pi.py`

Chương trình nạp **tất cả** mô hình TFLite và chạy trên **toàn bộ** file PCAP, ngay trên Pi. Với mỗi mô hình, chương trình báo cáo Accuracy, Macro-F1, Macro-AUC, tốc độ (cửa sổ/giây, gói/giây), độ trễ, CPU và RAM.

Các chỉ số chất lượng dùng để kiểm chứng. Nếu khớp với kết quả trên Kaggle thì bộ trích xuất đặc trưng, scaler và kích thước đầu vào trên Pi giống với trên PC.

Cấu trúc thư mục (đặt script cạnh các mục này):

```
bench_pi.py
unb pcaps/                 # *.pcap, *.pcapng (nhãn lấy từ tên file)
tflite models/             # *.tflite
scaler_standard*.pkl       # hoặc scaler_params*.json
feature_columns*.json
```

Cài đặt:

```bash
pip3 install numpy dpkt psutil tflite-runtime
# scikit-learn không bắt buộc nếu có scaler_params.json
```

Chạy:

```bash
python3 bench_pi.py                       # toàn bộ cửa sổ, lặp 3 lần
python3 bench_pi.py --pilot               # chạy nhanh 1 mô hình để ước lượng thời gian
python3 bench_pi.py --threads 4           # phải trùng với lần chạy trên PC
python3 bench_pi.py --model-glob "*_fp32.tflite"   # chỉ chạy mô hình FP32
python3 bench_pi.py --max-windows 50000 --repeats 5  # lấy mẫu (chỉ để ước lượng)
```

Các tùy chọn chính: `--pcaps-dir`, `--models-dir`, `--window` (mặc định 10 gói), `--repeats` (mặc định 3), `--warmup` (mặc định 300), `--threads` (mặc định 1), `--extra`, `--no-preds`, `--out-dir`.

Kết quả lưu trong `results_pi/`:

- `B_runtime_PI_<thời gian>.csv` – kết quả của từng mô hình.
- `ENV_PI_<thời gian>.json` – thông tin thiết bị và cấu hình lần chạy.
- `EXTRA_runtime_PI_<thời gian>.csv` – các số đo độ trễ bổ sung (chỉ có khi dùng `--extra`).
- File dự đoán để đối chiếu với PC (trừ khi dùng `--no-preds`).

## 6. Phát hiện tấn công trực tuyến

Hai chương trình chạy cùng nhau. Đặt `capture.sh`, `live_infer.py` và `bench_pi.py` trong **cùng một thư mục**. `live_infer.py` import bộ trích xuất và scaler từ `bench_pi.py`, nên thư mục `tflite models/` và các file scaler cũng phải nằm ở đó.

**Terminal 1 – bắt gói tin:**

```bash
bash capture.sh                                   # mặc định dùng interface eth0
IFACE=wlan0 bash capture.sh                       # đổi interface
EXCLUDE_HOSTS="192.168.1.50" bash capture.sh      # loại máy laptop dùng để điều khiển
```

- Cần có `tcpdump` (`sudo apt install -y tcpdump`). Lần chạy đầu sẽ hỏi `sudo` một lần để cấp quyền bắt gói.
- Chương trình tạo FIFO tại `pcap_container/ids_pipe.pcap`.
- Nó sẽ đứng chờ (treo) tới khi `live_infer.py` mở đầu đọc. Đây là chuyện bình thường.
- Giữ terminal này mở.

**Terminal 2 – phát hiện:**

```bash
python3 live_infer.py
```

Chương trình mở một console nhỏ. Gõ `models` để xem danh sách mô hình, sau đó:

```
ids> run 1 --iface eth0                       # lưu lượng trực tiếp, dùng mô hình số 1
ids> run 3 --iface eth0 --context             # in thêm top IP nguồn
ids> run 2 --pcap "unb pcaps" --every 50      # chạy lại file PCAP, 50 cửa sổ in 1 dòng
ids> run 2 --pcap "unb pcaps" --limit 2000    # dừng sau 2000 cửa sổ
```

Các lệnh khác: `models`, `help`, `exit`. Nhấn `Ctrl+C` để dừng và xem tổng kết. Phải chọn đúng một nguồn: `--iface` hoặc `--pcap`.

Mỗi dòng in ra xác suất của 8 lớp, nhãn dự đoán, `infer_ms` (chỉ mô hình), `lat_pipe` (trích xuất + chuẩn hóa + suy luận) và `lat_e2e` (từ lúc tcpdump bắt gói đến lúc có kết quả). Phần tổng kết có độ trễ trung bình, thông lượng, CPU và RAM.

## 7. Yêu cầu

- **Notebook trên Kaggle:** PyTorch, TensorFlow/Keras, pandas, pyarrow, scikit-learn, matplotlib, seaborn.
- **Raspberry Pi 4:** Python 3, `numpy`, `dpkt`, `psutil`, `tflite-runtime` (hoặc `ai-edge-litert` / `tensorflow`), `tcpdump`.

## 8. Lưu ý

- Các đường dẫn như `/kaggle/input/datasets/rsnngo/...` là của em. Hãy đổi lại cho đúng với bạn.
- Dùng cùng giá trị `--threads` trên PC và Pi, nếu không phép so sánh sẽ không công bằng.
- Không chạy `capture.sh` trên interface đang dùng để điều khiển Pi từ xa, trừ khi đã đặt `EXCLUDE_HOSTS`.
- Đây là bài đo module phân loại trên thiết bị thật. Nó không phải là một hệ thống IDS hoàn chỉnh.
