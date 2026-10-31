# lmipro UEFI standard read-only metadata diagnostic

This image uses the exact qualified 3 MiB FD and 368-byte BootShim, with a new FAT payload containing one documented `type="efi"` application entry. No XNU, system filesystem or old native UFS observer is included. The existing firmware initialization remains unchanged. The application has no MMIO or disk-write path, but firmware drivers necessarily implement ReadBlocks internally.

The diagnostic enumerates BlockIo handles and device paths, records media geometry/alignment, and reads only whole physical media large enough to hold the supplied userdata image. It validates the outer GPT header and entry CRCs, requires exactly one userdata entry, checks the SHNGROOT manifest hash and windows, parses the nested OS GPT, and compares six SHA256 metadata samples including APFS container/volume checksums and the known System volume UUID. The System volume block address is pinned to the audited image; this is not a general APFS object-map parser.

Expected root UUID: `04769D26-2CA0-4825-B443-E2E5F88300F2`. The historical full input hash in expected-metadata.json was not recomputed for this build. Only 37376 bytes of the explicitly supplied userdata file were sampled to generate the fixture. A passing result confirms these sampled bytes only, not the full disk, APFS authentication, root mounting, XNU DMA access or a working OS.

The application caps reads at 512 and 16 MiB, and checks byte bounds, media block size, IoAlign, MediaId stability, GPT/APFS checksums and exact sample hashes. A firmware ReadBlocks call can itself hang; there is no claim that this diagnostic imposes a controller timeout. No controller reset, raw SCSI requests, partition writes, formatting, SetVariable or ExitBootServices are issued by the app.

On hardware: temporary `fastboot boot boot.img` only. The default menu entry is **UEFI storage read-only**. Wait for **LMIPRO UEFI STORAGE RO v2** and photograph the summary. N/P navigate retained log pages, S returns to summary, Esc returns to the menu. There is no timed reboot.

`RESULT: METADATA SAMPLES MATCH` is the success criterion. `NO MATCHING USERDATA GPT` means the qualified firmware did not expose a matching usable whole disk, or its GPT could not be read/validated; inspect the log instead of assuming XPU or disk corruption. `METADATA CHECK FAILED` identifies a failed step. No target or mismatch is not an instruction to reflash userdata.

Source references:
- [Pinned official UEFI firmware guide](https://github.com/yang232138/UniXNU/blob/ee472385743ebd16941ab14892dcb9d02e219d15/docs/zh/porting/uefi-firmware.md)
- [Pinned official boot configuration and EFI entries](https://github.com/yang232138/UniXNU/blob/ee472385743ebd16941ab14892dcb9d02e219d15/docs/zh/reference/boot-configuration.md)
- [Pinned Mu BlockIo protocol](https://github.com/microsoft/mu_basecore/blob/cfb93724a06ff86ff5ba971413368a7809ee42a5/MdePkg/Include/Protocol/BlockIo.h)

V2 adds read-only protocol presence (SMEM/SPMI and supporting protocols), LoadedImage FV file GUIDs and DriverBinding correlation. No driver methods, ConnectController, Dispatch, forced LoadImage, reset or MMIO are invoked. UFSDxe's exact tested-FD DEPEX is SMEM AND SPMI. LoadedImage presence alone does not prove StartImage success; absence can also mean an unloaded failed driver. Names in FirmwareNames.h are extracted from the exact frozen FD, not guessed from overlay source. The full inventory is retained in N/P log pages.

V1 hardware evidence: only RAM payload VenHw(A9C6827C-1BD8-410C-885A-C46500F7D836), bs=512 last=0x1ffff, LogicalPartition=1 ReadOnly=1; zero physical disks and zero reads. Userdata remains untested.
