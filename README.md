# FPC `10a5:a921` 指纹在 Linux 上跑通

2026-10-30，一台 HONOR MagicBook 上的 FPC 指纹从「能枚举、按了没反应、日志一直报错」变成「正常按压即可注册、验证，并可用于锁屏解锁」。

驱动本体是 libfprint 1.94.6 + 未合并的 MR 396（`fpcmoh`），a921 的改动全部在 `patches/`。这里记的是**怎么判断、怎么改对的**；逐条证据与验证命令见 [docs/A921.md](docs/A921.md)。

| 项 | 值 |
|---|---|
| 机器 | HONOR `FMI-XX`（`FMI-XX-PCB`，`product_version M1020`） |
| 传感器 | `10a5:a921`，hwid `0x331`，type 7，64×176，8 bpp，`bcdDevice 0.39` |
| 系统 | Linux Mint 22.3 (Zena)，内核 7.0.0-38-generic |
| 栈 | libfprint 1.94.6 + MR 396 + `patches/`，fprintd 1.94.3 |

## 结果

```
Device reported enroll progress, reported 11 of 11 have been completed
fpc_store_template_db: blob_size 14508
ENROLL RESULT: SUCCESS
VERIFY RESULT: MATCH
```

| 按压 | 结果 |
|---|---|
| 右手食指 | `verify-match` |
| 右手中指（第一次 / 第二次） | `verify-no-match` / `verify-match` |
| 左手食指（未注册） | `verify-no-match` |

## 九个坑

前六个让驱动走不到取图；后三个只有传输层通了才会露出来。

| # | 差异 | 不修的后果 | 补丁 |
|---|---|---|---|
| 1 | `id_table` 里没有 `10a5:a921` | `No driver found for USB device` | `0011` |
| 2 | 事件头和 16 位字段是小端 | 长度成 `0x0a000000`，状态机卡住 | `0012`、`0013` |
| 3 | SSM 每条记录推进两次 | 隔一条吃两条，随后超时 | `0014` |
| 4 | 主机密钥要用 Windows 的方式下发 | 握手根本不开始 | `0015` |
| 5 | **传感器是 TLS 服务端** | 握手返回 `-1`，EP 0x81 无数据 | `0016` |
| 6 | 每次采集后还有一条 12 字节尾记录 | 每个样本后致命错误，注册中断 | `0017` |
| 7 | a921 没打开图像消息重排 | 每个样本都被判不可用，进度停在 0/11 | `0018` |
| 8 | 尾记录可能晚于 post-drain 超时到达 | `len 12 err!`，整次操作失败 | `0019` |
| 9 | 无图像的记录必然回 `-6` | 每次按压两条 warning，看起来像坏了 | `0021` |

`0020` 是排查第 7 条时加的 `FPC_IMG_DIAG=1` 追踪，默认零开销。

三个最容易判断错的地方：

- **TLS 方向反了。** `libfpcbep.so` 的 mbedtls 只有服务端，a921 自己也是服务端，等着主机发 ClientHello。`tools/fpc_tlsclient.c` 用 `LD_PRELOAD` 接住 blob 的 `mbedtls_ssl_*`，用 OpenSSL 跑 TLS 1.2 PSK 客户端（cipher `0x00a8`，identity `Disum PSK`），成功后把 blob 的状态字（base + `0x196100`）写 16。
- **图像消息前缀是 24，不是 34。** 11288 = 24 + 11264，matcher 却从 34 取像素。做法与 a900 的 `0009` 相同：偏移 24 处插 10 字节空档，总长 11298。
- **正常按压只成像 0..119 行。** 其余是 `0xff`，matcher 判 `LOW_COVERAGE`，而 Windows 下同一按法是通过的。shim 在 `FPC_IMG_FILL=mirror` 时把接触带镜像补进尾部（第 `y ≥ 119` 行取第 `236 − y` 行），注册才走得完。

## 怎么找到的

1. **先让失败可读。** 驱动原来丢掉 `fpc_enclave_process_data()` 的返回值，所有失败长得一样。把返回值、事件 id、长度打出来后，`-6` 才有意义。
2. **抓帧，不猜。** shim 在 `FPC_DUMP_DIR` 下落盘每条 >1000 字节的应用消息（`img-NNN.raw`，11288 字节），覆盖率问题是看图看出来的。
3. **离线重放 matcher。** `tools/fpc-offline-harness.c` 把录好的帧按不同变换直接喂 `libfpcbep.so`，跳过 USB 和 TLS。补尾方案是在这里比出来的：原样全 4，噪声/纯色 6，镜像补尾全 1。
4. **一次只改一个变量。** 小端没修完看不到 TLS 失败；TLS 通了才看到消息布局；布局对了才看到覆盖率。顺序颠倒会把两个 bug 的症状混在一起。
5. **改动必须进补丁。** `build.sh` 会重置源码树，只存在于工作树的改动会在下次重建时悄悄消失。

## 安装与复现

```bash
./get-blob.sh          # 取专有 matcher libfpcbep.so（md5 f7136fd774d5208e629bbeaa4974543a）
./build.sh             # libfprint 1.94.6 + MR 396 + patches/*.patch
sudo ./install.sh      # /opt/fpc-a921/lib + udev 规则 + fprintd drop-in
fprintd-enroll         # 正常按压，约 11 个样本
```

卸载：`sudo ./uninstall.sh`。发行版 libfprint 全程不被修改。

若每次都报 `finger-not-centered`，先确认镜像补齐生效：

```bash
systemctl show fprintd -p Environment | tr ' ' '\n' | grep IMG_FILL
```

## Mint 桌面接入

登录和 sudo 走 lightdm / sudo 自己的 PAM 栈，两者都 `include common-auth`，所以只需改一处：

```
auth  [authinfo_unavail=1 default=ignore] pam_fingwit.so
auth  [success=2 default=ignore]          pam_fprintd.so max-tries=3 timeout=-1
```

`max-tries` 是失败几次才回落到密码；默认 1 会让一次没按准就跳 PIN。`timeout=-1`
是「不设指纹窗口」：锁屏后解锁框立刻出现，人可能很久才回来，15 秒的窗口会在回来
之前就过期（实测 15 秒后只剩 `Verification timed out` 和密码框，再按指纹没反应）。
失败 3 次后 PAM 照样回落到密码。

### 锁屏：换掉 slick-greeter

Mint 默认的锁屏是 light-locker 交给 lightdm 的 slick-greeter 2.2.6，它没有指纹界面：
PAM 在匹配时已经成功（日志里 `gkr-pam: no password is available for user`，即没输密码
就过了），但界面不会自己提交，必须点一次「登录」，提示文字也挤在一个放不下的小
标签里。

换成 XFCE 自带锁屏后，PAM 返回成功即解锁，无点击、无回车，实测从按压到回桌面约
3 秒。体积 260 kB 下载 / 1.3 MB 安装：

```bash
sudo apt install -y xfce4-screensaver
mkdir -p ~/.config/autostart
printf '[Desktop Entry]\nType=Application\nName=Light Locker (disabled)\nExec=light-locker\nHidden=true\nX-GNOME-Autostart-enabled=false\n' \
  > ~/.config/autostart/light-locker.desktop
pkill -x light-locker
nohup xfce4-screensaver >/dev/null 2>&1 &
xfconf-query -c xfce4-screensaver -p /lock/enabled -n -t bool -s true

install -Dm755 desktop/xfce-lock-dialog ~/.local/bin/xfce-lock-dialog
install -Dm644 desktop/xfce-lock-dialog.desktop ~/.config/autostart/xfce-lock-dialog.desktop
nohup ~/.local/bin/xfce-lock-dialog >/dev/null 2>&1 &
```

`Ctrl+Alt+L` 由 `xflock4` 处理，它会优先找 `xfce4-screensaver-command`，所以锁屏键
不用改。撤销：`sudo apt remove xfce4-screensaver`，删掉那两个 autostart 文件，再
`light-locker &`。

锁屏后默认只有一层壁纸：解锁框要等键鼠动作才由 `gs_manager_request_unlock()` 弹出，
这就是「锁了是黑的，动鼠标才出现」的原因。它的 DBus 接口 `SimulateUserActivity`
（即 `xfce4-screensaver-command -p`）走同一个函数，`desktop/xfce-lock-dialog` 监听
`ActiveChanged`，一上锁就 poke 一次。实测不碰键鼠，上锁后 2 秒内解锁框、头像和指纹
提示已在屏上，按压即解锁；快捷键、菜单、挂起前的锁屏都汇到同一个信号上。fprintd
没带中文翻译，所以这一行提示仍是英文（`Place your finger on the fingerprint reader`）。
要强制回到指纹提示（比如挂起唤醒后 fprintd 的设备掉了），点「取消」（或 Esc）再动一下
鼠标即可：屏幕保持锁定，只是重新拉起一次 PAM。对话框闲置 60 秒也会自己收起
（`DIALOG_TIMEOUT_SEC`），屏幕仍是锁定状态，下次键鼠动作照样把解锁框拉回来。

登录界面（开机时的 greeter）仍是 slick-greeter，同一条限制仍然存在；锁屏现在不受
影响。

### fprintd 的设备占用

fprintd 1.94.3 在客户端 `Claim` 超时后会留下设备占用，Mint 指纹 App 的表现是
「打不开」。`sudo systemctl restart fprintd` 即可；一次只开一个客户端。

## 仓库内容

```
patches/                    0001-0021，逐个可审阅的驱动改动
docs/A921.md                证据、判断过程、验证命令
desktop/xfce-lock-dialog    锁屏后立刻弹出解锁框的 DBus 触发器 + autostart 条目
tools/fpc_tlsclient.c       TLS 客户端 shim（LD_PRELOAD 进 fprintd）
tools/fpc-offline-harness.c 离线喂帧给 matcher 的 harness
tools/fpc-feed-preload.c    harness 用的假 mbedtls_ssl_read
build.sh / install.sh / uninstall.sh / get-blob.sh
```

**不包含**：`libfpcbep.so`（厂商专有）和 Windows 驱动包，都不提交，`get-blob.sh` 按需获取。

## 来源与许可

驱动来自 libfprint 上游 v1.94.6 与 [MR 396](https://gitlab.freedesktop.org/libfprint/libfprint/-/merge_requests/396)；a900 的工程骨架与脚本源自 [cityji/honor-magickbookpro-fingerprint-driver](https://github.com/cityji/honor-magickbookpro-fingerprint-driver)。许可证沿用上游，见 [LICENSE](LICENSE)。
