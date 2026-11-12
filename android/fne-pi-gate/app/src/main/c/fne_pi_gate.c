/* Safe futex availability check from the real Android app UID/SELinux domain.
 * This sample is NOT a GhostLock PoC. It exercises a normal uncontended
 * private PI futex and ONE rejected PI-requeue syscall with identical
 * addresses, which the SHA-verified original C431 kernel rejects before
 * acquiring futex queue/hash locks or manipulating waiters.
 * No races, waiters, UAF, kernel memory addresses, root or persistence.
 */
#include <jni.h>
#include <errno.h>
#include <linux/futex.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

JNIEXPORT jstring JNICALL
Java_org_openhonor_fnepigate_MainActivity_runNativeProbe(JNIEnv *env, jclass clazz) {
    (void)clazz;
    int word __attribute__((aligned(4))) = 0;
    errno = 0;
    long lock_result = syscall(SYS_futex, &word, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG,
                               0, NULL, NULL, 0);
    int lock_errno = errno;
    long unlock_result = -2;
    int unlock_errno = 0;
    if (lock_result == 0) {
        errno = 0;
        unlock_result = syscall(SYS_futex, &word, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG,
                                0, NULL, NULL, 0);
        unlock_errno = errno;
    }
    char output[512];
    snprintf(output, sizeof(output),
             "ADB-neutral Android application context\n"
             "FUTEX_LOCK_PI | PRIVATE: rc=%ld errno=%d\n"
             "FUTEX_UNLOCK_PI | PRIVATE: rc=%ld errno=%d\n"
             "Initial word: 0; uncontended; own process memory\n"
             "Outcome: %s\n",
             lock_result, lock_errno, unlock_result, unlock_errno,
             lock_result == 0 && unlock_result == 0 ? "APP_PI_FUTEX_OK" : "APP_PI_FUTEX_UNAVAILABLE");
    return (*env)->NewStringUTF(env, output);
}

/* One intentionally invalid PI-requeue syscall: source and destination are
 * the SAME 32-bit word. This is rejected by the exact FNE-NX9 C431 kernel's
 * futex_requeue() uaddr1 == uaddr2 guard BEFORE get_futex_key/queue operations.
 * No FUTEX_WAIT_REQUEUE_PI, blocking, other threads or actual requeue.
 * This checks Android app-domain syscall dispatch only; EINVAL != UAF.
 */
JNIEXPORT jstring JNICALL
Java_org_openhonor_fnepigate_MainActivity_runRejectedRequeueProbe(JNIEnv *env, jclass clazz) {
    (void)clazz;
    int word __attribute__((aligned(4))) = 0;
    errno = 0;
    long rc = syscall(SYS_futex, &word, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                      1, (void *)0, &word, 0);
    int saved_errno = errno;
    const char *outcome =
        (rc == -1 && saved_errno == EINVAL)
        ? "REQUEUE_PI_EARLY_GUARD_OK"
        : (rc == -1 && saved_errno == ENOSYS)
        ? "REQUEUE_PI_NOT_IMPLEMENTED_OR_FILTERED"
        : (rc == -1 && (saved_errno == EPERM || saved_errno == EACCES))
        ? "REQUEUE_PI_DENIED_OR_RESTRICTED"
        : "REQUEUE_PI_UNEXPECTED_RESPONSE";
    char report[600];
    snprintf(report, sizeof(report),
             "FUTEX_CMP_REQUEUE_PI | PRIVATE; invalid identical addresses\n"
             "No waiters, no requeue, no UAF, no exploit trigger.\n"
             "Expected: rc=-1 errno=22 (EINVAL)\n"
             "Observed: rc=%ld errno=%d\n"
             "Outcome: %s\n",
             rc, saved_errno, outcome);
    return (*env)->NewStringUTF(env, report);
}
