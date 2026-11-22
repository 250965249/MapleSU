#ifndef MAPLESU_LEASE_CONTRACT_H
#define MAPLESU_LEASE_CONTRACT_H
#ifdef __cplusplus
extern "C" {
#endif
/* Pure validation, also compiled and executed on the Windows host in tests. */
int maplesu_lease_endpoint(const char *value);
int maplesu_lease_nonce(const char *value, unsigned char out[32]);
int maplesu_lease_boot_id(const char *value);
int maplesu_lease_decimal(const char *value, int minimum, int *out);
#ifdef __cplusplus
}
#endif
#endif
