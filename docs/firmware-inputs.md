# 固件输入

云编译用到的板级输入及其来源。任何一项变化都会改变固件卷，重新构建前先更新本文件。

## 厂商 DXE 集 — `Binaries-lmi.zip`

| 项 | 值 |
| --- | --- |
| 来源 | 本机 `xbl_4.elf`（Redmi K30 Pro 的 XBL 分区镜像）经 `MSMTools/UEFIReader` 解包 |
| SHA-256 | `9c76bc298053228969d2aac4b215aaaadc302ceb793d3f811a284156dcb623f4` |
| 大小 | 2691452 字节 |
| 文件数 | 311 |

解包后按 Mu-Silicium 的 `Binaries/<device>/` 布局存放（`ArmPkg/`、`QcomPkg/`、`MdeModulePkg/`、
`FatPkg/`、`EmbeddedPkg/`、`MiPkg/`、`RawFiles/`）。云编译把它解压到
`uefi/Binaries/lmi/`，不使用 Mu-Silicium 的 `Binaries` 子模块（那个子模块是别的机型的）。

关键驱动（`lmi.fdf` 经 `QcomPkg/Extra.fdf.inc` 引用）：`QcomPkg/Drivers/ButtonsDxe`、
显示、存储、电源相关 DXE。缺失会导致固件卷里对应服务为空。

## 设备树 — `DeviceTree/lmi.dtb`

| 项 | 值 |
| --- | --- |
| 来源 | 本机固件分区中提取的编译后设备树 |
| SHA-256 | `bb52bbbf97601450dbdca9a020145ebe7ea816a94418155919c139ba27d39529` |
| 大小 | 540143 字节 |

`unixnu bootimg` 把它追加到 kernel 字段（`append_dtb = true`），Mu-Silicium SEC 再把
FDT 地址经入口参数 HOB 交给 `UniXNURamDiskDxe`。设备树里的
`/chosen/linux,initrd-start`、`linux,initrd-end` 必须指向负载所在的保留内存。

## 固件卷参数

来自 `Resources/Configs/lmi.toml`，同时编译进 BootShim 并由 `unixnu bootimg` 复核：

| 键 | 值 | 含义 |
| --- | --- | --- |
| `uefi_fd.base` | `0x9FC00000` | 固件卷加载物理地址 |
| `uefi_fd.size` | `0x300000`（3 MiB） | 固件卷精确大小 |
| `boot_image.header_version` | `2` | 手机 boot.img 的 header 版本 |
| `boot_image.kernel_offset` | `0x8000` | kernel 加载偏移 |
| `boot_image.ramdisk_offset` | `0x1000000` | ramdisk 加载偏移 |
| `boot_image.tags_offset` | `0x100` | tags 地址 |

这些是历史 lmi 值，不是在本机 bootloader 内存映射上重新测得的；刷入前应从设备的
`fastboot getvar` 或内存映射确认。
