/* Host-test compatibility for the Windows build of CivetWeb.
 *
 * CivetWeb asks the C library for the wall clock.  The llvm-mingw UCRT build used
 * by the contract tests declares the 64-bit-time variant but does not ship an
 * implementation, so this file answers it from the Win32 system time.  The real
 * CivetWeb server code is linked and exercised unchanged.
 */
#include <time.h>

#include <windows.h>

/* Declared by <pthread_time.h> (included from <time.h>) as
 *   int __cdecl clock_gettime64(clockid_t, struct _timespec64 *);
 * Fill it in with the Win32 wall clock. */
int __cdecl clock_gettime64(clockid_t clock_id, struct _timespec64 *tp) {
    FILETIME file_time;
    ULARGE_INTEGER value;
    (void)clock_id;
    GetSystemTimeAsFileTime(&file_time);
    value.LowPart = file_time.dwLowDateTime;
    value.HighPart = file_time.dwHighDateTime;
    if (tp != 0) {
        /* FILETIME counts 100 ns intervals since 1601-01-01. */
        const unsigned long long hundred_ns = value.QuadPart;
        const unsigned long long since_epoch = hundred_ns - 116444736000000000ull;
        tp->tv_sec = (__time64_t)(since_epoch / 10000000ull);
        tp->tv_nsec = (long)((since_epoch % 10000000ull) * 100ull);
    }
    return 0;
}
