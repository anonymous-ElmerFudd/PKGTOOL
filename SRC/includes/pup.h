// Copyright 2010            anonymous
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef _PUP_H_
#define _PUP_H_


#include "stdint.h"
#include "types.h"
#include "sce.h"
#include "tool_structures.h"



#ifdef __cplusplus
extern "C" {
#endif


/// "pack" functions
int find_files(char* pInPath, u32* pNumFiles, u64* pDataSize);
int build_header(u8* pHmacSecretKey, u8* pInHdr, u32 num_files, u64 BuildNumber, u64 MyDataSize);
int calc_hmac(u8* pHmacSecretKey, u8* pInBuffer, u64 len, u8* pOutHmac);
int do_pup_pack(char* pInPath, char* pOutPath, u64 BuildNumber);
int write_pup(u8* pInPupHdr, char* pOutPath, u32 num_files);


/// "unpack" functions
int check_hmac(u8 *pMyHmacKey, u8* pMyOrgHmac, u8 *bfr, u64 len);
int do_pup_unpack(char* pInPath, char* pOutPath);
int do_section(char* pOutPath, u8* pInPup, u8* pMyHmacKey, u64 section_num, u64 num_sections);
int find_hmac(u8* pInPup, u8** ppHmacPtr, u64 entry, u64 num_sections);



#ifdef __cplusplus
}
#endif


#endif
// _PUP_H_
