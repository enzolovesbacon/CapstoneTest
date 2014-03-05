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
#include <kern/debug.h>
#include "capstone.h"

kern_return_t CapstoneTest_start(kmod_info_t * ki, void *d);
kern_return_t CapstoneTest_stop(kmod_info_t *ki, void *d);

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

// silences warning "unresolved symbol ___strcat_chk"
void __chk_fail (void)// __attribute__((__noreturn__));
{
	panic("inficere");
}

// silences warning "unresolved symbol ___strcat_chk"
char *
__strcat_chk (char *__restrict s, const char *__restrict append,
	      size_t slen)
{
	char *save = s;
	
	/* Advance to the end. */
	for (; *s; ++s)
		if (__builtin_expect (slen-- == 0, 0))
			__chk_fail ();
	
	do
	{
		/* Append the string.  Make sure we check before writing.  */
		if (__builtin_expect (slen-- == 0, 0))
			__chk_fail ();
		
	} while ((*s++ = *append++));
	
	return save;
	
}

void *my_calloc(size_t num, size_t size)
{
	size_t total = num * size;
	void *p = _MALLOC(total, M_TEMP, M_WAITOK);
	
	if(!p)
		return NULL;
	
	return memset(p, 0, total);
}

void my_free(void *ptr)
{
	_FREE(ptr, M_TEMP);
}

void *my_malloc(size_t size)
{
	return _MALLOC(size, M_TEMP, M_WAITOK);
}

void *my_realloc(void *ptr, size_t size)
{
	if(size == 0)
		return NULL;
	
	void *newptr = _MALLOC(size, M_TEMP, M_WAITOK);
	
	memcpy(newptr, ptr, size);
	
	return newptr;
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
	
	printf("[DEBUG] count: %zu\n", count);
	
	if(count > 0)
		return KERN_SUCCESS;
	
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
