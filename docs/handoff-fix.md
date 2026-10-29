# lmi: pre-menu translation fault

The user observed a data abort before the menu with ELR 0x99EDA360,
FAR 0xA9DFE000. That address is outside the original board RAM mappings.
A matching symbol/load base is unavailable; the exact faulting function is
not established by this photograph alone.

The [UEFI documentation](https://unixnu.com/zh/porting/uefi-firmware#负载发现)
requires a valid FDT entry-argument HOB and a mapped/reserved payload until
file discovery completes. The previous board adapter preserved x0 without
preserving the physical FDT memory, and its initrd fallback accepted any
64-MiB range above 0x80000000, including unmapped addresses.

BootShim now bounds and copies the live, boot-loader-patched FDT before SEC
changes page tables. A 1-MiB reservation is split out of the existing
0x9f300000-0x9f7fffff RAM partition; neither the FD nor payload base changes.
Invalid FDT input results in x0=0, so consumers skip it rather than following
an invalid pointer. The RAM-disk adapter accepts only the exact reserved
XNUP payload window. The shim rejects invalid XNUP lengths.

The compiled shim was executed in Unicorn 2.1.4 for nine cases, covering FDT
outside the original mapping, overlap, absent/bad/oversized FDT, FD already
at destination, and zero/oversized XNUP. This verifies the shim operations,
not SEC/DXE behavior or a successful hardware boot.

The dedicated fix-handoff workflow pins its inputs and reuses only the FAT
payload from run 40824751238 after checking both image and payload SHA-256.
It rebuilds the FD and shim, never XNU. No register or vendor binary edits.
No flashing, partition editing or OS-root installation is part of this fix.
The payload remains a kernel/menu test, not a complete installed OS.

## LMI-DIAG2 isolation

Run 40835746473 built successfully but still failed before the menu. The new
photo 1793259836554.jpg shows ESR 0x02000000 (EC 0), unlike the previous data
translation fault. Its exact instruction and image base are not established.
The FDT/payload corrections therefore do not establish a successful menu boot.

Disable the optional dynamic DRAM extension driver in both DSC and FDF for
this iteration. Keep the static board map, shim, vendor executables and FAT
payload unchanged. This isolates an extra DXE memory-management path; it is
not evidence that this driver caused the exception. It also does not establish
enough memory for XNU. Restore/repair it only after collecting evidence.

The exception footer repeats ESR, PC, LR, image base/offset and argument
registers after the long dump. It reads one aligned instruction word only for
EC 0 within the baseline RAM window and with a recognized image. It does not
probe the instruction address for data-abort exceptions. Archive compiled
images and symbols so the next fault can be matched to this exact build.
