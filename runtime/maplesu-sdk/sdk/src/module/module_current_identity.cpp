// module current identity implementation.
//
#include <cstddef>
#include <cerrno>
#include <cstring>
#include <pthread.h>

extern "C" __attribute__((weak, visibility("hidden"))) void maplesu_hook_fork_prepare() noexcept;
extern "C" __attribute__((weak, visibility("hidden"))) void maplesu_hook_fork_complete() noexcept;

static char maplesu_module_root_key_nL3sM35dAvzoDMNDUIolFXfHD1lRQix3[1024] = {};
static char maplesu_module_id32_5a4a7cf17e65ead4c6e67885dde9c46d[1024] =
    "GEfQdKmhZSkuWJI2rs21JO39Xmp8XcZg";

namespace {
pthread_mutex_t root_key_mutex = PTHREAD_MUTEX_INITIALIZER;
int root_key_fork_error = EAGAIN;
thread_local char root_key_snapshot[1024] = {};

void root_key_before_fork() {
    if (maplesu_hook_fork_prepare) maplesu_hook_fork_prepare();
    pthread_mutex_lock(&root_key_mutex);
}
void root_key_after_fork() {
    pthread_mutex_unlock(&root_key_mutex);
    if (maplesu_hook_fork_complete) maplesu_hook_fork_complete();
}

// Register before SDK work starts, without a function-local initialization guard
// that a fork child could inherit while another thread initializes it.
__attribute__((constructor)) void initialize_root_key_storage() {
    root_key_fork_error = pthread_atfork(root_key_before_fork, root_key_after_fork, root_key_after_fork);
}

bool lock_root_key() {
    const int error = root_key_fork_error ? root_key_fork_error : pthread_mutex_lock(&root_key_mutex);
    if (!error) return true;
    errno = error;
    return false;
}
}

// Keep the legacy 1023-character truncation and padding contract. Copy first so
// setting from this thread's last getter snapshot never aliases the authority.
extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(
    const char* root_key) {
    char candidate[1024] = {};
    if (root_key) strncpy(candidate, root_key, sizeof(candidate) - 1);
    if (!lock_root_key()) return;
    memcpy(maplesu_module_root_key_nL3sM35dAvzoDMNDUIolFXfHD1lRQix3, candidate, sizeof(candidate));
    pthread_mutex_unlock(&root_key_mutex);
}

// Stable across other threads' setters. A later getter on this same thread
// refreshes the snapshot; callers retaining an identity must copy its bytes.
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() {
    if (!lock_root_key()) {
        memset(root_key_snapshot, 0, sizeof(root_key_snapshot));
        return root_key_snapshot;
    }
    memcpy(root_key_snapshot, maplesu_module_root_key_nL3sM35dAvzoDMNDUIolFXfHD1lRQix3,
        sizeof(root_key_snapshot));
    pthread_mutex_unlock(&root_key_mutex);
    return root_key_snapshot;
}

extern "C" void __set_current_module_id32_1b0494ae8a788541db46b82cc1f0577c(
    const char* id32) {
    strncpy(maplesu_module_id32_5a4a7cf17e65ead4c6e67885dde9c46d, id32, 1023);
}

extern "C" const char* __get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c() {
    return maplesu_module_id32_5a4a7cf17e65ead4c6e67885dde9c46d;
}

extern "C" __attribute__((visibility("hidden"))) int maplesu_identity_fork_status() noexcept {
    return root_key_fork_error;
}
