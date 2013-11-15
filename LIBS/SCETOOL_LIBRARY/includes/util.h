/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>

#include "types.h"



#ifdef __cplusplus
extern "C" {
#endif



/*! Verbose. */
//extern _verbose = FALSE;
//BOOL _verbose = FALSE;

//#define _LOG_VERBOSE(...) _IF_VERBOSE(printf("[*] " __VA_ARGS__))
#define _LOG_VERBOSE(...)
#define _IF_VERBOSE(code) \
	do \
	{ \
		if(_verbose == TRUE) \
		{ \
			code; \
		} \
	} while(0)

/*! Raw. */
extern BOOL _raw;
#define _PRINT_RAW(fp, ...) _IF_RAW(fprintf(fp, __VA_ARGS__))
#define _IF_RAW(code) \
	do \
	{ \
		if(_raw == TRUE) \
		{ \
			code; \
		} \
	} while(0)

/*! ID to name entry. */
typedef struct _id_to_name
{
	u64 id;
	const s8 *name;
} id_to_name_t;

/*! Utility functions. */
void __stdcall _hexdump(FILE *fp, const char *name, u32 offset, u8 *buf, int len, BOOL print_addr);
void __stdcall _print_align(FILE *fp, const s8 *str, s32 align, s32 len);
u8* __stdcall _read_buffer(const s8 *file, u32 *length);
int __stdcall _write_buffer(const s8 *file, u8 *buffer, u32 length);
const s8* __stdcall _get_name(id_to_name_t *tab, u64 id);
u64 __stdcall _get_id(id_to_name_t *tab, const s8 *name);
void __stdcall _zlib_inflate(u8 *in, u64 len_in, u8 *out, u64 len_out);
void __stdcall _zlib_deflate(u8 *in, u64 len_in, u8 *out, u64 len_out);
u8 __stdcall _get_rand_byte();
void __stdcall _fill_rand_bytes(u8 *dst, u32 len);
void __stdcall _memcpy_inv(u8 *dst, u8 *src, u32 len);
void* __stdcall _memdup(void *ptr, u32 size);
u64 __stdcall _x_to_u64(const s8 *hex);
u8* __stdcall _x_to_u8_buffer(const s8 *hex);


#ifdef __cplusplus
}
#endif


#endif
