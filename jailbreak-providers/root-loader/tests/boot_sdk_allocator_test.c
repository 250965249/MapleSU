/* Host exercises the same live-code decoder used before kernel allocation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "boot_sdk_protocol.h"
#include "boot_sdk_allocator.h"
int main(int argc, char **argv)
{
    unsigned char code[120] = {0};
    struct msu_sdk_vm vm;
    unsigned long base = 0xffff800000000000UL;
    if (argc != 6) return 3;
    FILE *input = fopen(argv[1], "rb");
    if (!input || fread(code, 1, sizeof(code), input) != sizeof(code)) return 3;
    fclose(input);
    int error = msu_sdk_vmalloc(code, base + strtoul(argv[2], 0, 0),
        base + strtoul(argv[3], 0, 0), base, strtoul(argv[4], 0, 0), atoi(argv[5]), &vm);
    if (error) return 2;
    printf("%lu %lu %lu %lu %lu %lu %lu\n", 0UL-vm.start, 0UL-vm.end,
        vm.align, vm.gfp, vm.prot, vm.prot_set, vm.flag-base);
    return 0;
}
