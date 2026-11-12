/* Safe futex availability check from the real Android app UID/SELinux domain.
 * This sample is NOT a GhostLock PoC and DOES NOT make requeue syscalls.
 * It only acquires/releases one uncontended, private PI futex.
 * No races, UAF, kernel memory addresses, root, or persistence operations.
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
