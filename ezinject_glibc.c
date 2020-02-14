#include <stdio.h>
#include "ezinject.h"
#include "ezinject_common.h"
#include "log.h"

int libc_init_hook(struct ezinj_ctx *ctx, ez_lib libc){
	DECL_SYM(libc_dlopen, libc, "__libc_dlopen_mode");
	DBGADDR(libc_dlopen);
	ctx->libc_dlopen = libc_dlopen;
	return 0;
}