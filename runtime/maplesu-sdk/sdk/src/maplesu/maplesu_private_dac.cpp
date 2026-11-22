// maplesu private dac implementation.
//
// Directory and allow-list files owned by the SDK are opened without following
// a substituted symlink, and their permissions are only tightened while the
// inode still belongs to the SDK (root-owned, single-link regular file or a
// directory).  A create path additionally labels the new inode for SELinux
// before it is published to an untrusted caller.
//
// The frozen member is a C translation unit: every definition carries C
// language linkage, including the file-internal `owned` helper (its symbol is
// the unmangled `owned`, not `_ZL5ownediP4stat`).
extern "C" {
#include "../../../../ultra/identity/private_dac.c"
}
