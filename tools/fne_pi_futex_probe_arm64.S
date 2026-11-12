/* HONOR70 / ARM64 - bounded PI-futex syscall availability test.
 * Only normal uncontended FUTEX_LOCK_PI and FUTEX_UNLOCK_PI operations
 * on a private 32-bit futex. No requeue, UAF, race, root or bootloader change.
 * Static ARM64 Linux ELF, uses syscalls only; no Android NDK required.
 */
.equ SYS_write, 64
.equ SYS_exit, 93
.equ SYS_futex, 98
.equ FUTEX_LOCK_PI_PRIVATE, 134
.equ FUTEX_UNLOCK_PI_PRIVATE, 135

.macro puts name, length
 mov x0, #1
 adrp x1, \name
 add x1, x1, :lo12:\name
 mov x2, #\length
 mov x8, #SYS_write
 svc #0
.endm

.section .text
.global _start
.type _start, %function
_start:
 puts banner, banner_end-banner
 adrp x0, futex_word
 add x0, x0, :lo12:futex_word
 mov x1, #FUTEX_LOCK_PI_PRIVATE
 mov x2, xzr
 mov x3, xzr
 mov x4, xzr
 mov x5, xzr
 mov x8, #SYS_futex
 svc #0
 cbnz x0, failed_lock
 puts ok_lock, ok_lock_end-ok_lock
 adrp x0, futex_word
 add x0, x0, :lo12:futex_word
 mov x1, #FUTEX_UNLOCK_PI_PRIVATE
 mov x2, xzr
 mov x3, xzr
 mov x4, xzr
 mov x5, xzr
 mov x8, #SYS_futex
 svc #0
 cbnz x0, failed_unlock
 puts ok_unlock, ok_unlock_end-ok_unlock
 mov x0, xzr
 mov x8, #SYS_exit
 svc #0
failed_lock:
 puts err_lock, err_lock_end-err_lock
 mov x0, #11
 mov x8, #SYS_exit
 svc #0
failed_unlock:
 puts err_unlock, err_unlock_end-err_unlock
 mov x0, #12
 mov x8, #SYS_exit
 svc #0
.size _start, .-_start

.section .rodata
banner: .ascii "HONOR70 safe PI futex syscall check (NOT GhostLock)\\n"
banner_end:
ok_lock: .ascii "FUTEX_LOCK_PI returned 0\\n"
ok_lock_end:
ok_unlock: .ascii "FUTEX_UNLOCK_PI returned 0\\n"
ok_unlock_end:
err_lock: .ascii "FUTEX_LOCK_PI failed or blocked; report exit=11\\n"
err_lock_end:
err_unlock: .ascii "FUTEX_UNLOCK_PI failed; report exit=12\\n"
err_unlock_end:
.section .bss
.balign 4
futex_word: .skip 4
