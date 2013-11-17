// Copyright 2010            anonymous
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef _SPKG_H_
#define _SPKG_H_


#include "stdint.h"
#include "types.h"
#include "tool_structures.h"



#ifdef __cplusplus
extern "C" {
#endif



// decrypt spkg
int decrypt_spkg(u8* pInSpkg, u64* pDecSize, char* pKeyName);
int do_spkg_decrypt(char* pInPath, char* pOutPath, char* pKeyName);



#ifdef __cplusplus
}
#endif


#endif
// _SPKG_H_
