/** @file
  Keep the UFS device awake across ExitBootServices and stage the GPT head.

  Two jobs, both read-only with respect to the device:

    1. read the first block through the vendor BlockIo protocol so the device
       stays in its ACTIVE power state, then clear the UFSHCI auto-hibernate
       idle timer;
    2. copy that first block (MBR + GPT header + primary entries) into the tail
       of the payload ramdisk window, tagged with a signature, so the kernel can
       prove the firmware really can read this UFS device.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Protocol/BlockIo.h>

#define UFS_HC_BASE              0x01D84000ULL
#define UFS_REG_AUTO_HIBERNATE   0x18
#define UFS_REG_INTERRUPT_ENABLE 0x24

//
// Tail of the lmiPkg "Payload Ramdisk" reservation (0x93200000 + 0x05600000),
// past the 64 MiB payload image the device tree declares. The kernel does not
// own this window, so a staged copy survives into early kernel init.
//
#define UFS_BLOB_BASE            0x097200000ULL
#define UFS_BLOB_MAGIC           0x42534655U   // 'UFSB'
#define UFS_BLOB_VERSION         1U
#define UFS_BLOB_BYTES           4096U

STATIC
volatile UINT32 *
UfsReg (
  IN UINT32 Offset
  )
{
  return (volatile UINT32 *)(UINTN)(UFS_HC_BASE + Offset);
}

EFI_STATUS
EFIAPI
UfsKeepAliveEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS           Status;
  EFI_HANDLE           *Handles;
  UINTN                Count;
  UINTN                Index;
  BOOLEAN              ReadOk;

  Handles = NULL;
  Count   = 0;
  ReadOk  = FALSE;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiBlockIoProtocolGuid,
                  NULL,
                  &Count,
                  &Handles
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "UfsKeepAlive: no BlockIo (%r)\n", Status));
    return EFI_SUCCESS;
  }

  for (Index = 0; Index < Count; Index++) {
    EFI_BLOCK_IO_PROTOCOL  *BlockIo;
    UINT8                  *Buffer;
    UINT8                  *Blob;

    BlockIo = NULL;
    Status  = gBS->HandleProtocol (
                     Handles[Index],
                     &gEfiBlockIoProtocolGuid,
                     (VOID **)&BlockIo
                     );
    if (EFI_ERROR (Status) || (BlockIo == NULL) || (BlockIo->Media == NULL)) {
      continue;
    }

    //
    // UFS reports 4096-byte logical blocks; this also skips the 512-byte
    // emulated FAT volume that carries the payload.
    //
    if (!BlockIo->Media->MediaPresent || (BlockIo->Media->BlockSize != 4096)) {
      continue;
    }

    Buffer = AllocatePool (BlockIo->Media->BlockSize);
    if (Buffer == NULL) {
      continue;
    }
    Status = BlockIo->ReadBlocks (
                        BlockIo,
                        BlockIo->Media->MediaId,
                        0,
                        BlockIo->Media->BlockSize,
                        Buffer
                        );
    DEBUG ((
      DEBUG_INFO,
      "UfsKeepAlive: UFS BlockIo[%u] block0 -> %r\n",
      (UINT32)Index,
      Status
      ));
    if (EFI_ERROR (Status)) {
      FreePool (Buffer);
      continue;
    }

    Blob = (UINT8 *)(UINTN)UFS_BLOB_BASE;
    Blob[0] = (UINT8)(UFS_BLOB_MAGIC & 0xFF);
    Blob[1] = (UINT8)((UFS_BLOB_MAGIC >> 8) & 0xFF);
    Blob[2] = (UINT8)((UFS_BLOB_MAGIC >> 16) & 0xFF);
    Blob[3] = (UINT8)((UFS_BLOB_MAGIC >> 24) & 0xFF);
    Blob[4] = (UINT8)(UFS_BLOB_VERSION & 0xFF);
    Blob[5] = (UINT8)((UFS_BLOB_VERSION >> 8) & 0xFF);
    Blob[6] = (UINT8)((UFS_BLOB_VERSION >> 16) & 0xFF);
    Blob[7] = (UINT8)((UFS_BLOB_VERSION >> 24) & 0xFF);
    CopyMem (Blob + 8, Buffer, UFS_BLOB_BYTES);
    FreePool (Buffer);
    ReadOk = TRUE;
    break;
  }
  FreePool (Handles);

  *UfsReg (UFS_REG_INTERRUPT_ENABLE) = 0;
  *UfsReg (UFS_REG_AUTO_HIBERNATE)   = 0;
  DEBUG ((
    DEBUG_INFO,
    "UfsKeepAlive: staged=%u auto-hibernate timer cleared\n",
    ReadOk ? 1U : 0U
    ));

  return EFI_SUCCESS;
}
