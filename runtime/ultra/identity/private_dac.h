#pragma once
#ifdef __cplusplus
extern "C" {
#endif
int maplesu_private_chmod(const char *path, unsigned mode);
int maplesu_private_file_open(const char *path, int exclusive);
int maplesu_private_allowlist_create(const char *path);
#ifdef __cplusplus
}
#endif
