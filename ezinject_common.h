#ifndef __EZINJECT_COMMON_H
#define __EZINJECT_COMMON_H

#include "ezinject.h"
#include <sys/types.h>

#define DECL_SYM(var, lib, sym_name) \
	ez_addr var; \
	if(sym_addr(lib, sym_name, &var) != 0) return 1

extern char *common_ignores[];

int sym_addr(ez_lib lib, const char *sym_name, ez_addr *pAddr);
int lib_open(pid_t pid, char *lib_name, char *lib_substr, char **ignores, ez_lib *pLib);

// this is an interface, implemented differently
int libc_init_hook(struct ezinj_ctx *ctx, ez_lib libc);
#endif