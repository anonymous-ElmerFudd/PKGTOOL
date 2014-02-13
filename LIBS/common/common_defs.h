// Copyright 2010       anonymous
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt


#ifndef _COMMONDEFS_H
#define _COMMONDEFS_H



#include "stdint.h"



#ifdef __cplusplus
extern "C" {
#endif



#define TRUE			1
#define FALSE			0
#define STATUS_SUCCESS	0


#ifndef BOOL
typedef int	BOOL;
#endif

/* should be in some equivalent to <sys/types.h> */
//typedef __int8            int8_t;
typedef __int16           int16_t; 
typedef __int32           int32_t;
typedef __int64           int64_t;
typedef unsigned __int8   uint8_t;
typedef unsigned __int16  uint16_t;
typedef unsigned __int32  uint32_t;
typedef unsigned __int64  uint64_t;

typedef char s8;
typedef short s16;
typedef int s32;
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;





#ifdef __cplusplus
}
#endif


#endif

// _COMMONDEFS_H
