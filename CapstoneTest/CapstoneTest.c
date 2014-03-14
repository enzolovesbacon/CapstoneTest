//
//  CapstoneTest.c
//  CapstoneTest
//
//  Created by Enzo Matsumiya on 05/03/14.
//  Copyright (c) 2014 enzo. All rights reserved.
//

#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <sys/malloc.h>
#include <string.h>
#include <sys/param.h>
#include "capstone.h"

kern_return_t CapstoneTest_start(kmod_info_t * ki, void *d);
kern_return_t CapstoneTest_stop(kmod_info_t *ki, void *d);

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

#pragma mark Memory functions
/* Own memory functions (for capstone) */

void *my_calloc(size_t num, size_t size)
{
	if(size == 0 || num == 0)
		return NULL;
	
	size_t total = num * size;
	void *p = _MALLOC(total, M_TEMP, M_WAITOK);
	
	if(p == NULL)
		return NULL;
	
	return memset(p, 0, total);
}

void my_free(void *ptr)
{
	if(ptr != NULL)
		_FREE(ptr, M_TEMP);
}

void *my_malloc(size_t size)
{
	return _MALLOC(size, M_TEMP, M_WAITOK);
}

struct _mhead {
	size_t	mlen;
	char	dat[0];
};

void *my_realloc(void *ptr, size_t size)
{
	struct _mhead	*hdr;
	void		*newaddr;
	size_t		alloc;
	
	/* realloc(NULL, ...) is equivalent to malloc(...) */
	if (ptr == NULL)
		return (_MALLOC(size, M_TEMP, M_WAITOK));
	
	/* Allocate a new, bigger (or smaller) block */
	if ((newaddr = _MALLOC(size, M_TEMP, M_WAITOK)) == NULL)
		return (NULL);
	
	hdr = ptr;
	--hdr;
	alloc = hdr->mlen - sizeof (*hdr);
	
	/* Copy over original contents */
	bcopy(ptr, newaddr, MIN(size, alloc));
	_FREE(ptr, M_TEMP);
	
	return (newaddr);
}

kern_return_t test_function()
{
	csh handle = 0;
	unsigned long count = 0;
	cs_insn *insn;
	
	cs_opt_mem setup;
	
	setup.calloc = my_calloc;
	setup.free = my_free;
	setup.malloc = my_malloc;
	setup.realloc = my_realloc;
	setup.vsnprintf = vsnprintf;
	
	if(cs_option(0, CS_OPT_MEM, &setup) != CS_ERR_OK) {
		printf("[ERROR] Capstone memory setup failed!\n");
		
		return KERN_FAILURE;
	}
	
	int err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	
	if(err != CS_ERR_OK) {
		printf("[ERROR] Capstone engine failed to start (%d)\n", err);
		
		return KERN_FAILURE;
	}
	
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	
	count = cs_disasm_ex(handle, (uint8_t *)CODE, sizeof(CODE)-1, 0x1000, 0, &insn);
	
	if(count > 0) {
		size_t i, j;
		
		for (i = 0; i < count; i++) {
			printf("0x%llx: ", insn[i].address);
			
			for(j = 0; j < 16; j++) {
				printf("%x ", insn[i].bytes[j]);
			}
			printf("\n");
		}
		
		cs_free(insn, count);
		
		return KERN_SUCCESS;
	}
	
	return KERN_FAILURE;
}

kern_return_t CapstoneTest_start(kmod_info_t * ki, void *d)
{
	test_function();
	
	return KERN_SUCCESS;
}

kern_return_t CapstoneTest_stop(kmod_info_t *ki, void *d)
{
	return KERN_SUCCESS;
}
