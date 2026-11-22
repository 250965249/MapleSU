#include "lease_contract.h"

static int hex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
int maplesu_lease_endpoint(const char *value) {
    const char prefix[] = "maplesu-jb-";
    int i = 0;
    if (!value) return 0;
    for (; prefix[i]; ++i) if (value[i] != prefix[i]) return 0;
    for (; value[i]; ++i) {
        if (i >= 100 || !((value[i] >= 'a' && value[i] <= 'z') ||
            (value[i] >= '0' && value[i] <= '9') || value[i] == '-')) return 0;
    }
    return i > 11;
}
int maplesu_lease_nonce(const char *value, unsigned char out[32]) {
    if (!value || !out) return 0;
    for (int i = 0; i < 32; ++i) {
        if (!value[2*i]) return 0;
        const int a = hex(value[2*i]);
        if (!value[2*i+1]) return 0;
        const int b = hex(value[2*i+1]);
        if (a < 0 || b < 0) return 0;
        out[i] = (unsigned char)((a << 4) | b);
    }
    return value[64] == 0;
}
int maplesu_lease_boot_id(const char *value) {
    if (!value) return 0;
    for (int i = 0; i < 36; ++i) {
        if (!value[i]) return 0;
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return 0;
        } else if (hex(value[i]) < 0) return 0;
    }
    return value[36] == 0;
}
int maplesu_lease_decimal(const char *value, int minimum, int *out) {
    if (!value || !value[0] || !out || minimum < 0) return 0;
    int result = 0;
    for (int i = 0; value[i]; ++i) {
        const int digit = value[i] - '0';
        if (digit < 0 || digit > 9 || result > (2147483647 - digit) / 10) return 0;
        result = result * 10 + digit;
    }
    if (result < minimum) return 0;
    *out = result;
    return 1;
}
