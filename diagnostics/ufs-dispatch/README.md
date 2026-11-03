# LMIPRO 原厂 IOMMU 调用记录诊断

本镜像在原厂 UFS 驱动正常启动期间，观察原厂 HALIOMMU 的 Create、Configure 和 Attach 调用。所有参数原样转发一次，真实 UINT32 返回码原样返回；不添加控制器调用，不修改原厂驱动文件。记录存放在有限容量的 RAM 表。

首屏 LMIPRO IOMMU ORIGINAL CALLS v1 显示调用完成标记、实际返回码、域、配置模式、ARID 和 flags。returned=0 表示尚未观察到调用完成，不能当作成功。Configure 成功返回后，观察器只读 HAL domain 结构偏移 0x20 的实际属性值；偏移由原厂 HAL 的写入指令确认。页面同时列出未修改 DAL 二进制表中 UFS0 的 CacheCoherency=0，作为静态表值而非运行时内存读数。各诊断页自动轮播，无需按键。

静态分析确认本机原厂 HALIOMMU 从 DAL 的 SMMU/IORT 属性读取内置二进制表。前版未找到命名 XBL 区域或 DT 中的 IORT，不能据此认定 UFS 失败根因。UFS0 表项的缓存一致性字段为 0；本版实测域属性用于和该值对照。

测试覆盖函数表布局、原参数及返回值保留、每次仅转发一次、只在 Configure 成功时记录域属性、目标启动窗口、空表和容量上限；实际源以 ARM64 严格警告编译。构建和镜像检查通过后仅使用 fastboot boot 临时启动。没有刷写、擦除或重新分区。

本版将板级 EnableUfsIOC 设为 1，使原厂 UFS HAL 使用带一致性属性的 IOMMU 域；Configure 后的运行时属性与 UFS0 DAL IORT 值仍需实机对照。诊断页自动轮播，无需键盘。

此改动是 UFS 启动修复候选。只有实机 Attach 成功、DMA/命令完成、已知块读取、根文件系统挂载和完整系统启动各自取得证据后，才能确认启动链修复完成。构建成功不能代替这些验证。
