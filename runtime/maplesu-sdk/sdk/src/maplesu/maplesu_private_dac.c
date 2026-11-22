// maplesu private dac implementation (C translation unit).
//
// The frozen archive member is a C object: every definition in it, including
// the file-internal `owned` helper, carries a C symbol name.  Compiling the
// shared C source through a C++ wrapper would give `owned` internal C++
// linkage (`_ZL5ownediP4stat`), so this member is compiled as C.
#include "../../../../ultra/identity/private_dac.c"
