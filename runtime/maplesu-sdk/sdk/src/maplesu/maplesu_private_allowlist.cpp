// maplesu private allowlist implementation.
//
// The persisted allow-list is replaced atomically: the secure temporary inode
// is truncated, written line by line, flushed to stable storage and then
// renamed over the live path.  A failed transaction removes the temporary inode
// and leaves the previously published allow-list untouched.
//
#include <string>
#include <vector>

extern "C" __attribute__((visibility("hidden"))) bool maplesu_private_allowlist_save(
        const std::string *path, const std::vector<std::string> *apps);

#include "../../../../ultra/identity/private_allowlist.cpp"
