#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include "ezinject.h"
#include "log.h"
#include "util.h"

char *common_ignores[] = {"ld-", NULL};

int sym_addr(ez_lib lib, const char *sym_name, ez_addr *pAddr){
	uintptr_t sym_addr = (uintptr_t)dlsym(lib.handle, sym_name);
	if(sym_addr == 0){
		ERR("dlsym failed for sybol: %s", sym_name);
		return 1;
	}
	ez_addr sym = {
		.local = sym_addr,
		.remote = EZ_REMOTE(lib.baseaddr, sym_addr)
	};
	*pAddr = sym;
	return 0;
}

int lib_open(pid_t pid, char *lib_name, char *lib_substr, char **ignores, ez_lib *pLib){
	ez_addr baseaddr = {
		.local = (uintptr_t)get_base(getpid(), lib_substr, ignores),
		.remote = (uintptr_t)get_base(pid, lib_substr, ignores)
	};
	if(!baseaddr.local || !baseaddr.remote){
		ERR("Failed to get library base (search: '%s')", lib_substr);
		return 1;
	}

	void *handle = dlopen(lib_name, RTLD_LAZY);
	if(!handle){
		ERR("dlopen(%s) failed: %s", lib_name, dlerror());
		return 1;
	}

	ez_lib lib = {
		.baseaddr = baseaddr,
		.handle = handle
	};
	*pLib = lib;
	return 0;
}