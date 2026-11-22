#include <stdlib.h>
#include <string.h>

// Fixed-size, single-occurrence configuration slot. Contains a directory, never a key.
__attribute__((visibility("hidden"), used))
char maplesu_su_directory[1024] = "MAPLESU_SU_ENV_DIRECTORY_SLOT_5_1_0";

__attribute__((constructor)) static void maplesu_su_env_entry(void) {
    size_t size = strnlen(maplesu_su_directory, sizeof(maplesu_su_directory));
    if (size == 0 || size == sizeof(maplesu_su_directory) || maplesu_su_directory[0] != '/' ||
        strchr(maplesu_su_directory, ':') != NULL) return;
    const char* path = getenv("PATH");
    if (path == NULL) path = "";
    for (const char* entry = path; *entry;) {
        const char* end = strchr(entry, ':');
        size_t length = end ? (size_t)(end - entry) : strlen(entry);
        if (length == size && memcmp(entry, maplesu_su_directory, size) == 0) return;
        if (!end) break;
        entry = end + 1;
    }
    size_t path_size = strlen(path);
    char* value = malloc(size + path_size + 2);
    if (value == NULL) return;
    memcpy(value, maplesu_su_directory, size);
    value[size] = ':';
    memcpy(value + size + 1, path, path_size + 1);
    setenv("PATH", value, 1);
    free(value);
}
