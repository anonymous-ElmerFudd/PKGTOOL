// Copyright 2010            anonymous
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef _SPP_H_
#define _SPP_H_


#include "stdint.h"
#include "types.h"
#include "tool_structures.h"



#ifdef __cplusplus
extern "C" {
#endif



// decrypt spp
int decrypt_spp(u8* pInSpp, u64* pDecSize, char* pKeyName);
int do_spp_decrypt(char* pInPath, char* pOutPath, char* pKeyName);

// encrypt spp
int build_spp_meta_hdr(SPP_META_HDR* pMetaHdr, u64 ContentSizeOriginal);
int build_spp_sce_hdr(sce_header_t* pSceHdr, u64 ContentSizeOriginal);
u64 build_spp(sce_header_t* pSceHdr, SPP_META_HDR* pMetaHdr, u8** ppInSpp, u8* pContent, u64 ContentSizeOriginal);
int calculate_spp_hash(u8 *data, u64 len, u8 *digest);
int do_spp_encrypt(char* pInPath, char* pOutPath, char* pType, char* pKeyName);
int hash_spp(u8* pInPkg, u64 ContentSizeOriginal);
int sign_spp(u8* pInSpp);


#ifdef __cplusplus
}
#endif


#endif
// _SPP_H_
