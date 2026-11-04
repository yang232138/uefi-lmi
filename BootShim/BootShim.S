#define FDT_BASE 0x9F300000
#define FDT_BYTES 0x100000
#ifndef PAYLOAD_SIZE
#define PAYLOAD_SIZE 0x05600000
#endif
#if PAYLOAD_SIZE != 0x04000000 && PAYLOAD_SIZE != 0x05600000
#error Unsupported lmi payload reservation
#endif

_Head:
  adr   x1, _Payload    /* Set _Entry address */
  b     _Start          /* Jump to the real code */

#if REQUIRES_KERNEL_HEADER == 1
_StackBase:
  .quad FD_BASE         /* Text Offset */

_StackSize:
  /* Keep the upstream semantics: the ABL on this board rejects a header whose
     image_size includes the shim (Load Error), so this stays the bare volume size. */
  .quad FD_SIZE
  .quad 0               /* Flags */
  .quad 0               /* Reserved */
  .quad 0               /* Reserved */
  .quad 0               /* Reserved */
  .ascii "ARM\x64"      /* ARM64 Magic */
  .long 0               /* Reserved */
#endif

_Start:
  /* Preserve the bootloader-patched FDT across SEC's MMU transition. */
  mov   x8, x0
  mov   x0, xzr
  cbz   x8, _FdtDone
  tst   x8, #7
  b.ne  _FdtDone
  ldr   x9, =0x80000000
  cmp   x8, x9
  b.lo  _FdtDone
  lsr   x9, x8, #32
  cbnz  x9, _FdtDone
  ldr   w9, [x8]
  ldr   w10, =0xEDFE0DD0
  cmp   w9, w10
  b.ne  _FdtDone
  ldr   w10, [x8, #4]
  rev   w10, w10
  cmp   x10, #40
  b.lo  _FdtDone
  ldr   x9, =FDT_BYTES
  cmp   x10, x9
  b.hi  _FdtDone
  add   x11, x8, x10
  sub   x11, x11, #1
  lsr   x11, x11, #32
  cbnz  x11, _FdtDone
  ldr   x9, =FDT_BASE
  mov   x0, x9
  cmp   x8, x9
  b.eq  _FdtDone
  b.hi  _FdtForward
  add   x8, x8, x10
  add   x9, x9, x10
_FdtBackward:
  ldrb  w11, [x8, #-1]!
  strb  w11, [x9, #-1]!
  subs  x10, x10, #1
  b.ne  _FdtBackward
  b     _FdtDone
_FdtForward:
  ldrb  w11, [x8], #1
  strb  w11, [x9], #1
  subs  x10, x10, #1
  b.ne  _FdtForward
_FdtDone:
  mov   x4, x1
  ldr   x5, =FD_BASE
  cmp   x4, x5
  beq   _Entry
  ldr   x6,  =FD_SIZE

_CopyLoop:
  ldp   x2, x3, [x4], #16
  stp   x2, x3, [x5], #16
  subs  x6, x6, #16
  b.ne  _CopyLoop

#ifdef PAYLOAD_BASE
  /* x4 now points just past the FD: an optional "XNUP" payload may follow */
  ldr   w2, [x4]
  movz  w3, #0x4E58
  movk  w3, #0x5055, lsl #16
  cmp   w2, w3
  b.ne  _NoPayload
  ldr   w6, [x4, #4]    /* Payload Size */
  /* Never copy into the DXE heap, and reject zero before the countdown loop.
     The FAT disk must occupy exactly the reservation selected for this FD. */
  ldr   w3, =PAYLOAD_SIZE
  cmp   w6, w3
  b.ne  _NoPayload
  /* Copy the payload itself, not the 8-byte XNUP tag: the destination must
     start with the FAT boot sector the ramdisk driver expects. */
  add   x4, x4, #8
  add   x6, x6, #15     /* Round Up to 16 */
  and   x6, x6, #~15
  movz  x5, #(PAYLOAD_BASE >> 16), lsl #16

_PayloadLoop:
  ldp   x2, x3, [x4], #16
  stp   x2, x3, [x5], #16
  subs  x6, x6, #16
  b.ne  _PayloadLoop
  b     _PayloadDone

_NoPayload:
  /* Missing or wrong-sized payload: do not expose stale RAM as a disk. */
  ldr   x5, =PAYLOAD_BASE
  mov   x6, #32
_ClearInvalidPayload:
  stp   xzr, xzr, [x5], #16
  subs  x6, x6, #1
  b.ne  _ClearInvalidPayload
_PayloadDone:
#endif
  ldr   x5, =FD_BASE

_Entry:
#ifndef PAYLOAD_BASE
  /* Firmware-only boot: invalidate the reserved payload boot sector in RAM.
     The DXE adapter must not discover stale bytes from a previous boot as FAT.
     This address is reserved by lmi's MemoryMapLib; no storage is written. */
  movz  x4, #0x9320, lsl #16
  mov   x6, #32
_ClearPayloadSector:
  stp   xzr, xzr, [x4], #16
  subs  x6, x6, #1
  b.ne  _ClearPayloadSector
#endif
  br    x5

_Dead:
  b     _Dead

.ltorg
.text
.align 4

_Payload:
