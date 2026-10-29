# SEC to DXE MMU helper handoff

Photo `1793275712170.jpg` shows a firmware DXE exception, before the XNU
checkpoint. `ArmCpuDxe` faults at RVA `0x2480`, immediately after the live
translation-entry helper returns. The word read from that address is
`0x17FFFF3A`, the valid branch present in the exact compiled image. The last
message reports a block split with the MMU disabled. This is not evidence
that the XNU platform checkpoint failed.

The pinned upstream has a specific handoff for this situation:

- [ArmMmuPeiLibConstructor](https://github.com/microsoft/mu_basecore/blob/cfb93724a06ff86ff5ba971413368a7809ee42a5/UefiCpuPkg/Library/ArmMmuLib/AArch64/ArmMmuPeiLibConstructor.c)
  publishes an XIP helper through `gArmMmuReplaceLiveTranslationEntryFuncGuid`.
- [ArmMmuBaseLibConstructor and ReplaceTableEntry](https://github.com/microsoft/mu_basecore/blob/cfb93724a06ff86ff5ba971413368a7809ee42a5/UefiCpuPkg/Library/ArmMmuLib/AArch64/ArmMmuLibCore.c)
  consume that pointer. Without the HOB, each DXE instance uses its own helper.
  A helper inside the block being split forces the MMU-off path.

This Mu-Silicium boot goes directly from SEC to DXE. Its SEC builds a new HOB
list but does not run the upstream PEI constructor. The reviewed SEC source
does not publish the MMU helper HOB. The current SEC binary does contain the
helper; its fixed firmware address is outside the failing DXE-heap block.

Publish the SEC helper after library construction and before loading DXE.
Validate its location, size and alignment inside the existing FD reservation,
and clean it to PoC explicitly because this FD is RAM-backed. Use the existing
upstream HOB consumer without replacing the page-table assembly. Report the
selected pointer in the constructor.

Classify the same `0x9FC00000 + 0x300000` FD region as `EfiBootServicesCode`
instead of `EfiBootServicesData` so the resident helper remains executable
under the DXE memory policy. Addresses, lengths, cache attributes and vendor
executables remain unchanged. The helper lifetime is only boot services.

After building, inspect the SEC TE image and symbol map. Check that the helper
is in the fixed FD, aligned to 0x200, and that the captured fault's block would
not contain either this helper or the page-table entry. This verifies the
intended path selection, not elimination of the hardware fault. Hardware
testing and repeat-boot stability remain required. Reuse the no-reset XNU
entry/panic payload so kernel probes cannot be mistaken for firmware resets.

Build 40875433595 exposed an include-order collision: adding UefiCpuPkg
before ArmPlatformPkg selected a different PlatformSecLib.h. Keep the
existing SEC package order and append UefiCpuPkg after SiliciumPkg so the
board PlatformInitialize declaration remains visible. No C API is replaced.
