/* Minimal ARM64 Darwin PID 1. No libc, dyld, UFS, or persistent writes.
 * BSD syscall numbers and reboot flags are from pinned XNU d8b80295.
 * -s requests an intentional userspace panic after a real getpid()==1.
 * Without -s, PID 1 writes a console heartbeat and sleeps indefinitely.
 */
.section __TEXT,__text,regular,pure_instructions
.p2align 2
.globl _start
_start:
    ldr x21, [sp]                  // kernel-supplied argc
    mov x19, #-1
    mov x16, #20                  // getpid
    svc #0x80
    b.cs failed
    cmp x0, #1
    b.ne failed
    adrp x0, console@PAGE
    add x0, x0, console@PAGEOFF
    mov x1, #2                    // O_RDWR, no create
    mov x2, #0
    mov x16, #5                   // open /dev/console only
    svc #0x80
    b.cs mode
    mov x19, x0
    adrp x1, hello@PAGE
    add x1, x1, hello@PAGEOFF
    mov x2, #(hello_end-hello)
    mov x16, #4                   // write
    svc #0x80
mode:
    cmp x21, #1
    b.ls loop
    ldr x0, [sp, #16]             // argv[1]
    cbz x0, loop
    ldrh w1, [x0]
    mov w2, #0x732d               // "-s"
    cmp w1, w2
    b.ne loop
    ldrb w1, [x0, #2]
    cbnz w1, loop
    adrp x1, proof@PAGE
    add x1, x1, proof@PAGEOFF
    b diagnostic
failed:
    adrp x1, failure@PAGE
    add x1, x1, failure@PAGEOFF
diagnostic:
    mov x0, #0xc00                // RB_PANIC | RB_QUICK; never RB_FORCERESET
    mov x16, #55                  // reboot(opt, message)
    svc #0x80
    // Refusal must not be mistaken for a completed diagnostic or reboot.
loop:
    adrp x4, timeout@PAGE
    add x4, x4, timeout@PAGEOFF
    mov x0, #5
    stp x0, xzr, [x4]            // Darwin timeval: 5 seconds, zero microseconds
    mov x0, #0
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x16, #93                  // select(0, NULL, NULL, NULL, &timeout)
    svc #0x80
    tbnz x19, #63, loop
    mov x0, x19
    adrp x1, beat@PAGE
    add x1, x1, beat@PAGEOFF
    mov x2, #(beat_end-beat)
    mov x16, #4
    svc #0x80
    b loop
.section __TEXT,__cstring,cstring_literals
console: .asciz "/dev/console"
hello: .ascii "LMIPRO MINIRAM: PID 1 running; RAM root only.\n"
hello_end:
beat: .ascii "MINIRAM heartbeat\n"
beat_end:
proof: .asciz "LMIPRO MINIRAM PID1: real getpid=1; RAM init executed; no UFS access"
failure: .asciz "LMIPRO MINIRAM FAILURE: getpid did not establish PID 1"
.section __DATA,__data
.p2align 3
timeout: .quad 5, 0
