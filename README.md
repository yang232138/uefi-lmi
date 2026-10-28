# uefi-lmi

Redmi K30 Pro（`lmi`，SM8250）的 Mu-Silicium 板级 overlay，按 UniXNU 的
[UEFI 固件文档](https://unixnu.com/zh/porting/uefi-firmware) 在 GitHub Actions 上构建，
产物是可以用 `fastboot boot` **临时启动**（不刷入任何分区）的启动镜像。

## 仓库内容

| 路径 | 用途 |
| --- | --- |
| `Platforms/Xiaomi/lmiPkg/lmi.dsc`、`lmi.fdf` | EDK II 板级描述；UniXNU 的四个模块排在 `BdsDxe` 之前 |
| `Platforms/Xiaomi/lmiPkg/Include/` | `APRIORI.inc`、`DXE.inc`、`RAW.inc` 组件清单 |
| `Platforms/Xiaomi/lmiPkg/Library/` | 板级内存映射与配置文件映射 |
| `BootShim/BootShim.S` | 把固件卷搬到加载地址的 shim |
| `Resources/Configs/lmi.toml` | 固件基址/大小与 Android boot image header 参数 |
| `Binaries-lmi.zip` | 从本机 XBL 提取的厂商 DXE 集，见 [`docs/firmware-inputs.md`](docs/firmware-inputs.md) |
| `DeviceTree/lmi.dtb` | 手机的编译后设备树，打包时追加到 kernel 字段 |
| `scripts/adapt.py` | 两处上游适配，见下节 |
| `.github/workflows/build-uefi.yml` | 云编译流程 |

## 云编译

仓库 **Actions → build-uefi → Run workflow**。可改的参数：

| 输入 | 默认值 |
| --- | --- |
| `unixnu_repo` / `unixnu_ref` | `yang232138/UniXNU` / `main` |
| `device_repo` / `device_ref` | `yang232138/lmipro` / `main` |
| `mu_commit` | `e51cd877e31c8fbb322032dc4cb6715e83d25ad3` |

流程按文档执行：固定 commit 取 Mu-Silicium、`./unixnu defconfig`、`./unixnu fetch`、
`./unixnu build firmware --uefi`，再 `./unixnu bootimg` 打包。产物 artifact `lmi-uefi`：

- `SILICIUM_UEFI.fd`：固件卷，由 `unixnu build firmware` 校验大小
- `boot.img`：shim + 固件卷，gzip 后追加设备树
- `boot.json`：header、地址与各段哈希
- `firmware.log`：EDK II 构建日志

## 临时启动

```sh
fastboot devices            # 必须能看到设备
fastboot boot boot.img      # 临时启动，不写入 boot 分区
```

开机后如果停在加载器阶段，按
[绿条诊断](https://unixnu.com/zh/guide/debugging#green-bar) 查 `boot.json` 与串口日志。

## 两处上游适配

`scripts/adapt.py` 只改两行，都是为了贴合本机 ABL 的实际行为，运行前会断言上游未被改动：

1. **`image_size` 校验**：`unixnu bootimg` 要求 ARM64 header 的 `image_size` 等于
   `shim + 固件卷`。lmi 的 ABL 拒绝这种镜像（Load Error），所以 `BootShim.S` 写的是
   裸卷大小；适配后两种值都接受。
2. **空 DTB**：Mu-Silicium 的 `mkbootimg.py` 在 header v2 下拒绝空 DTB，而 `unixnu`
   不传 `--dtb`，是把设备树追加进 kernel 字段（`append_dtb = true`）；适配后允许空 DTB。

## 改动前须知

- 固件基址/大小（`0x9FC00000` / `0x300000`）是历史 lmi 值，编译进 BootShim 并由
  `unixnu bootimg` 复核；换机或换分区布局前先确认。
- `lmi.dsc` / `lmi.fdf` 里的四个模块顺序不要动，`UniXNURamDiskDxe` 必须在读取负载配置前就绪。
- 文件头保持上游 BSD-2-Clause-Patent 声明。
