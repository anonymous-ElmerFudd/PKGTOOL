// Copyright 2010            anonymous
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef _COS_H_
#define _COS_H_


#include "stdint.h"
#include "types.h"
#include "tool_structures.h"


#ifdef __cplusplus
extern "C" {
#endif



// unpack cos functions
int unpack_file(u8* pInPkg, char* pOutPath, u32 i);
int unpack_cos_pkg(u8* pInPkg, char* pOutPath);
int do_unpack_cos_package(char* pInPath, char* pOutPath);

// pack cos functions
int create_cos_pkg(char* pInPath, char* pOutFile, u64 OverrideFileSize) ;
int get_files(char *pInPath, u32* pNumFiles);
int build_hdr(u8** ppCosHdr, u32* pHdrSize, u32 NumFiles, u64 OverrideFileSize, u64* pPaddSize);
int write_pkg(u8* pCosHdr, const char *pOutFile, u32 HdrSize, u32 NumFiles, u64 PaddSize);




#ifdef __cplusplus
}
#endif



#endif
// _COS_H_
