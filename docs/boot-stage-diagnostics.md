# Temporary boot-stage diagnostics

Select `boot_diagnostics=true` in build-uefi to apply the fail-closed source
adapter in `scripts/boot-stage-diagnostics.py` after component fetch. Defaults
remain unchanged. `firmware_only=true` skips both macOS jobs; its FD must be
packed with an independently validated payload before handset testing.

The large automatic screen is titled `LMIPRO BOOT STAGES v1`. No keyboard is
needed. Stages 01–04 pause for three seconds; stage 05 pauses for twenty seconds.

| Screen | Evidence |
| --- | --- |
| 01 LOADER REQUEST | DarwinBoot received a boot request; inputs not yet validated. |
| 02 KERNEL PARSED | Mach-O input passed the existing loader parser. |
| 03 ALLOCATING KERNEL WINDOW | Allocation is about to run; allocation success is not established. |
| 04 COPYING KERNEL AND INPUTS | Allocation and size checks passed; copying is about to run. |
| 05 BEFORE EXIT BOOT SERVICES | Inputs were copied and arguments prepared; firmware still owns execution. |
| LOADER REFUSED | Existing failure path returned a status shown below the stage; holds 60 seconds. |
| BOOT ENTRY RETURNED | UniXNU's boot operation returned; status is shown for 60 seconds before returning to its menu. |

The original assembly handoff draws the green bar after ExitBootServices. Neither
stage 05 nor the green bar proves that XNU has executed. Kernel progress, storage
I/O and root mount require separate evidence. Automatic reboot after stage 05
does not by itself identify a panic, watchdog, or particular failing instruction.

The adapter adds no disk writes, persistent variables, reset hooks, kernel
patches, or boot-services calls after ExitBootServices. The memory-map key is
refreshed by the original exit loop after the final pause. Firmware and hardware
watchdog behavior is otherwise unchanged.
