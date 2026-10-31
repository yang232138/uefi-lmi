# lmipro UEFI UFSDxe loader probe v3

The exact previously tested FD, BootShim and firmware DTB remain pinned. No XNU is included. V2 hardware video established SMEM=1, SPMI=1, no UFS LoadedImage/DriverBinding and no physical BlockIo.

This version enumerates current FV2 handles and reads the PE32 section of file 0d35cd8e-97ea-4f9a-96af-0f0d89f76567 through FV2.ReadSection. A probe proceeds only if exactly one copy exists, exactly matches the 118784-byte PE extracted from the tested FD (SHA256 ffeaed467f8251b7e30a45075da84a1c563e2bac7dc4be0f79f0ed49a88b8dc9), and UFS is not already loaded/bound. The app constructs a bounded single-instance FV-file device path and calls normal BootServices.LoadImage with SourceBuffer=NULL, retaining the normal firmware authentication path. It records the returned status and unloads any returned image. It never calls StartImage, Dispatch, ConnectController, vendor protocol methods, any BlockIo disk method, controller reset, SetVariable or direct MMIO.

The pinned CoreLoadImage implementation only loads/relocates/registers the image; the driver entry is called by CoreStartImage. CoreUnloadImage frees a never-started image without calling a vendor unload function. Thus this probe does not execute the vendor UFS initialization. A loading failure does not by itself identify the original dispatcher failure; success does not prove the UFS entry or disk initialization succeeds. Observe the distinction on the result page.

Temporary fastboot boot only. Menu: UEFI UFS loader check. Page: LMIPRO UEFI LOADER PROBE v3. Capture FV count/UFS copies/hash, FV read status, Load attempted/status, Unload attempted/status. N/P show retained logs. No timed reboot. A crash/hang during loading is also a result; no repeated automatic retry.

Tests: existing 52 portable metadata-parser tests remain offline checks, plus 10 tests of the real C FV path builder using fake Boot Services, including valid GUID/path output, malformed length/end, existing FV-file node, missing handle/path and traversal cap. No firmware or device is used by host tests.

Source references:
- https://github.com/microsoft/mu_basecore/blob/cfb93724a06ff86ff5ba971413368a7809ee42a5/MdeModulePkg/Core/Dxe/Image/Image.c
- https://github.com/microsoft/mu_basecore/blob/cfb93724a06ff86ff5ba971413368a7809ee42a5/MdePkg/Include/Protocol/FirmwareVolume2.h
- https://github.com/yang232138/UniXNU/blob/ee472385743ebd16941ab14892dcb9d02e219d15/docs/zh/reference/boot-configuration.md
