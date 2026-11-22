// Shared by the policy loader and the explicit LSPosed data-label adapter.
#pragma once
#include <stdio.h>
#include <string.h>
#ifndef MAPLE_SHARED_CONTEXT_STATE
#define MAPLE_SHARED_CONTEXT_STATE "/data/adb/maplesu_zygisk/shared-context"
#endif
// Positive bit: one exact LSPosed data rule, 0: unrelated, -1: unknown contract.
static inline int maple_shared_file_rule_bit(const char *line) {
    char text[4096], normalized[4096] = {0};
    if (strlen(line) >= sizeof(text)) return -1;
    strcpy(text, line);
    char *comment = strchr(text, '#');
    if (comment) *comment = 0;
    char *save = NULL;
    size_t used = 0;
    int relevant = 0;
    for (char *word = strtok_r(text, " \t\r\n{}:;", &save); word;
         word = strtok_r(NULL, " \t\r\n{}:;", &save)) {
        relevant |= strcmp(word, "lsposed_file") == 0;
        used += snprintf(normalized + used, sizeof(normalized) - used, "%s%s", used ? " " : "", word);
    }
    if (!relevant) return 0;
    const char *known[] = {"type lsposed_file file_type", "typeattribute lsposed_file mlstrustedobject",
        "allow domain lsposed_file dir *", "allow domain lsposed_file file *"};
    for (size_t i = 0; i < sizeof(known)/sizeof(*known); ++i)
        if (!strcmp(normalized, known[i])) return 1 << i;
    return -1;
}
static inline int maple_shared_file_rule(const char *line) {
    int bit = maple_shared_file_rule_bit(line);
    return bit < 0 ? bit : bit != 0;
}
static inline int maple_shared_file_contract(const char *text) {
    unsigned mask = 0, count = 0;
    while (*text) {
        const char *end = strchr(text, '\n');
        size_t length = end ? (size_t)(end - text) : strlen(text);
        char line[4096];
        if (length >= sizeof(line)) return 0;
        memcpy(line, text, length); line[length] = 0;
        int bit = maple_shared_file_rule_bit(line);
        if (bit < 0) return 0;
        if (bit) { mask |= (unsigned)bit; ++count; }
        text += length + (end != NULL);
    }
    return count == 4 && mask == 15;
}
