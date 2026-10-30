# FPC `10a5:a921` 指纹在 Linux 上跑通

2026-10-30，一台 HONOR MagicBook（`FMI-XX`）上的 FPC 指纹传感器从「能枚举、按了没反应、日志一直报错」变成「正常按压即可注册、验证，并可用于锁屏和 sudo」。

仓库记录的是**怎么做到的**：每一次定位、每一个补丁、每一组实测数字。驱动本体是 libfprint 1.94.6 + 未合并的 MR 396（`fpcmoh`），补丁全部在本仓库 `patches/`。

硬件与系统：

| 项 | 值 |
|---|---|
| 机器 | HONOR `FMI-XX`（主板 `FMI-XX-PCB`，`product_version M1020`） |
| 传感器 | `10a5:a921` FPC Sensor Controller，hwid `0x331`，type 7，64×176，8 bpp，`bcdDevice 0.39` |
| 系统 | Linux Mint 22.3 (Zena)，内核 7.0.0-38-generic |
| 栈 | libfprint 1.94.6 + MR 396 + `patches/`，fprintd 1.94.3 |

## 起点与终点

起点：`lsusb` 能看到设备，libfprint 报 `No driver found for USB device`；加上 id 之后能读到 USB 流，但 `fpc_enclave_process_data()` 每条记录都返回 `-6`，一个样本也攒不出来。

终点（实测，非推断）：

```
Device reported enroll progress, reported 11 of 11 have been completed
fpc_store_template_db: blob_size 14508
ENROLL RESULT: SUCCESS
VERIFY RESULT: MATCH
```

| 按压 | 结果 |
|---|---|
| 右手食指，`fprintd-verify -f right-index-finger` | `verify-match` |
| 右手中指，第一次 | `verify-no-match` |
| 右手中指，第二次 | `verify-match` |
| 左手食指（未注册） | `verify-no-match` |

## 一共有九个坑

前六个让驱动根本走不到取图；后三个只有传输层通了才会露出来。

| # | 差异 | 不修的后果 | 补丁 |
|---|---|---|---|
| 1 | `id_table` 里没有 `10a5:a921` | `No driver found for USB device` | `0011` |
| 2 | 事件头和 16 位字段是小端 | 长度成 `0x0a000000`，状态机卡住 | `0012`、`0013` |
| 3 | SSM 每条记录推进两次 | 隔一条吃两条，随后超时 | `0014` |
| 4 | 主机密钥要用 Windows 的方式下发 | 握手根本不开始 | `0015` |
| 5 | **传感器是 TLS 服务端** | `fpc_enclave_tls_init_handshake status -1`，EP 0x81 无数据 | `0016` |
| 6 | 每次采集后还有一条 12 字节尾记录 | 每个样本后致命错误，注册中断 | `0017` |
| 7 | a921 没打开图像消息重排 | 每个样本都被判不可用，进度停在 0/11 | `0018` |
| 8 | 尾记录可能晚于 post-drain 超时到达 | `len 12 err!`，整次操作失败 | `0019` |
| 9 | 无图像的记录必然回 `-6` | 每次按压两条 warning，看起来像坏了 | `0021` |

`0020` 是定位第 7 条时加的 `FPC_IMG_DIAG=1` 追踪，默认零开销。

两个最容易走偏的点：

- **TLS 方向反了。** `libfpcbep.so` 内置的 mbedtls 只有服务端；a921 自己也是服务端，等着主机发 ClientHello。所以用 `LD_PRELOAD` 的 `tools/fpc_tlsclient.c` 接住 blob 的 `mbedtls_ssl_*` 调用，用 OpenSSL 跑 TLS 1.2 PSK 客户端（cipher `0x00a8`，identity `Disum PSK`），并把 blob 的 TLS 状态字写 16。
- **指纹按不满整帧。** 正常按压只成像第 0..119 行，其余是 `0xff`，厂商 matcher 判定 `LOW_COVERAGE`，而在 Windows 上同一个按法是通过的。shim 在 `FPC_IMG_FILL=mirror` 时把接触带镜像补进空尾（第 `y≥119` 行取第 `236-y` 行），matcher 才给出 `PROGRESS`。

## 怎么找到的（方法，而不是结论）

1. **先让错误可读。** 驱动原来把 `fpc_enclave_process_data()` 的返回值丢掉，等于所有失败都一样。先把返回值、事件 id、长度打出来，`-6` 就不再是黑盒。
2. **抓帧，别猜。** shim 在 `FPC_DUMP_DIR` 下把所有 >1000 字节的应用消息落成 `img-NNN.raw`（11288 字节：24 字节前缀 + 11264 字节像素）。覆盖率问题是看图看出来的：尾部整片 `0xff`。
3. **离线重放 matcher。** `tools/fpc-offline-harness.c` 把录好的帧按不同变换（翻转、反转、拉伸、镜像补尾）直接喂给 `libfpcbep.so`，跳过 USB 和 TLS。补尾方案是在这里比出来的：identity 全 4，噪声/常量 6，镜像补尾全 1。
4. **一次只改一个变量。** a921 的差异是叠加的：小端没修完就看到 TLS 失败，TLS 通了才看到消息布局，布局对了才看到覆盖率。按顺序单个验证，避免把两个 bug 的症状混在一起。
5. **认账：fprintd 的 claim 会漏。** 客户端在 `Claim` 期间超时后，fprintd 1.94.3 会留着 claim，下一个客户端（包括 Mint 的指纹 App）拿不到设备且不报错。`systemctl restart fprintd` 即可，一次只开一个客户端。

细节、消息布局、TLS 字段偏移、每次测量的原始输出都在 **[docs/A921.md](docs/A921.md)**。

## 装到桌面上

`sudo ./install.sh` 只动三样东西：`/opt/fpc-a921/lib`、一条 udev 规则、一个 fprintd drop-in。发行版的 libfprint 保持原样，只有 fprintd 看到打过补丁的构建：

```
Environment=LD_LIBRARY_PATH=/opt/fpc-a921/lib
Environment=LD_PRELOAD=/opt/fpc-a921/lib/libfpc_tlsclient.so
Environment=FPC_IMG_FILL=mirror
```

Mint 侧只需要 `/etc/pam.d/common-auth` 里的两行：

```
auth  [authinfo_unavail=1 default=ignore] pam_fingwit.so
auth  [success=2 default=ignore]          pam_fprintd.so max-tries=3 timeout=15
```

`max-tries` 是失败几次才回落到密码；默认 1 会让一次没按准就直接跳 PIN。锁屏和登录都走 lightdm，sudo 也吃同一套栈。

一个还没消除的粗糙处：Mint 锁屏是 slick-greeter 2.2.6，没有指纹界面。PAM 在匹配时已经成功（日志里 `gkr-pam: no password is available for user`，即没输密码就过了），但 greeter 不会自己提交会话，需要按一下回车。这是 greeter 的限制；换成 PAM 成功即解锁的锁屏（如 `xfce4-screensaver`，下载约 260 kB / 安装 1.3 MB）可以绕开，前提是你在意这次回车。

## 复现

```bash
./get-blob.sh          # 取专有 matcher libfpcbep.so（md5 f7136fd774d5208e629bbeaa4974543a）
./build.sh             # libfprint 1.94.6 + MR 396 + patches/*.patch
sudo ./install.sh      # 装到 /opt/fpc-a921/lib，写 udev 与 fprintd drop-in
fprintd-enroll         # 正常按压，约 11 个样本
```

若每次都是 `finger-not-centered`，先确认镜像补齐生效：

```bash
systemctl show fprintd -p Environment | tr ' ' '\n' | grep IMG_FILL
```

卸载：`sudo ./uninstall.sh`。

## 仓库里有什么

```
patches/            0001-0021，逐个可单独审阅的驱动改动
docs/A921.md        完整的 a921 接入记录（英文，含每次测量）
docs/INVESTIGATION.md、DEVICE.md、TROUBLESHOOTING.md   a900 工程继承的文档
tools/fpc_tlsclient.c       TLS 客户端 shim（LD_PRELOAD 进 fprintd）
tools/fpc-offline-harness.c 离线喂帧给 matcher 的 harness
tools/fpc-feed-preload.c    harness 用的假 mbedtls_ssl_read
tools/fp-enroll-verify.c    不走 fprintd、直接调 libfprint API 的注册+验证小程序
build.sh / install.sh / uninstall.sh / get-blob.sh
```

**不包含**：`libfpcbep.so`（厂商专有 matcher）和 `win-driver/`（Windows 驱动包）。两者都不会提交，`get-blob.sh` 负责按需获取。

## 来源与许可

驱动来自 libfprint 上游（tag v1.94.6）与 [MR 396](https://gitlab.freedesktop.org/libfprint/libfprint/-/merge_requests/396)；a900 的工程骨架与本仓库的脚本源自 [cityji/honor-magickbookpro-fingerprint-driver](https://github.com/cityji/honor-magickbookpro-fingerprint-driver)（其 README 保留在 [docs/UPSTREAM-README.md](docs/UPSTREAM-README.md)，链接以仓库根为准）。许可证沿用上游，见 [LICENSE](LICENSE)。
