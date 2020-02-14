#include <stdio.h>
#include "ezinject.h"
#include "ezinject_common.h"
#include "log.h"

int uclibc_init_ldso(struct ezinj_ctx *ctx){
	ez_lib ldso;
	if(lib_open(ctx->target, DYN_LINKER_NAME, "ld-uClibc", common_ignores, &ldso) != 0){
		ERR("Failed to open ldso");
		return 1;
	}

	DECL_SYM(libc_dlopen, ldso, "_dl_load_shared_library");
	DBGADDR(libc_dlopen);
	ctx->libc_dlopen = libc_dlopen;

	DECL_SYM(uclibc_sym_tables, ldso, "_dl_symbol_tables");
	DBGADDR(uclibc_sym_tables);
	ctx->uclibc_sym_tables = uclibc_sym_tables;

	DECL_SYM(uclibc_loaded_modules, ldso, "_dl_loaded_modules");
	DBGADDR(uclibc_loaded_modules);
	ctx->uclibc_loaded_modules = uclibc_loaded_modules;	

#ifdef EZ_ARCH_MIPS
	DECL_SYM(uclibc_mips_got_reloc, ldso, "_dl_perform_mips_global_got_relocations");
	DBGADDR(uclibc_mips_got_reloc);
	ctx->uclibc_mips_got_reloc = uclibc_mips_got_reloc;
#endif

	DECL_SYM(uclibc_dl_fixup, ldso, "_dl_fixup");
	DBGADDR(uclibc_dl_fixup);
	ctx->uclibc_dl_fixup = uclibc_dl_fixup;

	dlclose(ldso.handle);
	return 0;
}

int uclibc_init_libdl(struct ezinj_ctx *ctx){
	ez_lib libdl;
	if(lib_open(ctx->target, DL_LIBRARY_NAME, "libdl", NULL, &libdl) == 0){
		// target has libdl loaded. this makes things easier for us
		DECL_SYM(actual_dlopen, libdl, "dlopen");
		ctx->actual_dlopen = actual_dlopen;
	} else {
		// target has no libdl loaded. we will need to load it ourselves
		void *dlopen_local = dlsym(libdl.handle, "dlopen");
		off_t dlopen_offset = (off_t)PTRDIFF(dlopen_local, libdl.baseaddr.local);
		DBG("dlopen offset: 0x%lx", dlopen_offset);
		ctx->dlopen_offset = dlopen_offset;
	}
	dlclose(libdl.handle);
	return 0;
}

int libc_init_hook(struct ezinj_ctx *ctx, ez_lib libc){
	UNUSED(libc);

	if(uclibc_init_ldso(ctx) != 0){
		return 1;
	}
	if(uclibc_init_libdl(ctx) != 0){
		return 1;
	}
	return 0;
}