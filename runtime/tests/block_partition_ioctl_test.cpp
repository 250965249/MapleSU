#include "../src/block_partition_ioctl.h"
#include <cstdio>
#include <cstdlib>

namespace {
struct Fake {
    int read_only = 1;
    int get_error = 0;
    int set_error = 0;
    bool interrupt_get = false;
    bool interrupt_set = false;
    bool ignore_set = false;
    bool driver_write_locked = false;
    int gets = 0;
    int sets = 0;
} fixture;
int control(int descriptor, unsigned long operation, int* value) {
    if (descriptor != 42) std::abort();
    if (operation == BLKROGET) {
        fixture.gets++;
        if (fixture.interrupt_get) { fixture.interrupt_get = false; errno = EINTR; return -1; }
        if (fixture.get_error) { errno = fixture.get_error; return -1; }
        *value = fixture.read_only;
    } else if (operation == BLKROSET) {
        fixture.sets++;
        if (fixture.interrupt_set) { fixture.interrupt_set = false; errno = EINTR; return -1; }
        if (fixture.set_error) { errno = fixture.set_error; return -1; }
        if (!fixture.ignore_set) {
            fixture.read_only = *value;
            fixture.driver_write_locked = *value != 0;
        }
    } else std::abort();
    return 0;
}
void check(bool condition, const char* message) {
    if (!condition) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
int run(int desired) { return maplesu::block_partition_read_only(42, desired, control); }
}  // namespace

int main() {
    fixture.read_only = 0;
    fixture.driver_write_locked = true;
    check(run(0) == 0 && !fixture.driver_write_locked && fixture.sets == 1,
        "BLKROGET=0 must still dispatch BLKROSET(0) to the driver before writing");
    fixture = {};
    check(run(-1) == 1 && fixture.sets == 0, "query must leave a read-only partition unchanged");
    check(run(0) == 0 && fixture.sets == 1 && fixture.read_only == 0, "prepare must clear read-only and read it back");
    check(run(0) == 0 && fixture.sets == 2, "each preparation must dispatch the idempotent driver operation");
    check(run(1) == 1 && fixture.sets == 3, "close must restore the original read-only flag");
    fixture = {}; fixture.interrupt_get = true; fixture.interrupt_set = true;
    check(run(0) == 0 && fixture.sets == 2, "interrupted ioctls must retry");
    fixture = {}; fixture.set_error = EPERM;
    check(run(0) == -EPERM && fixture.read_only == 1, "permission failure must retain errno and the original flag");
    fixture = {}; fixture.ignore_set = true;
    check(run(0) == -EIO, "an ignored flag update must fail verification");
    fixture = {}; fixture.get_error = ENOTTY;
    check(run(0) == -ENOTTY && fixture.sets == 0, "query failure must never attempt a write-mode change");
    fixture = {}; fixture.read_only = 2;
    check(run(0) == -EIO && fixture.sets == 0, "unexpected query values must fail before setting");
    fixture = {};
    check(maplesu::block_partition_read_only(-1, 0, control) == -EINVAL &&
        maplesu::block_partition_read_only(42, 2, control) == -EINVAL && fixture.gets == 0,
        "invalid requests must not touch a device");
    std::puts("BlockPartitionAccess: 11 checks passed; no block devices modified");
}
