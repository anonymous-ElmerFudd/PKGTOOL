// Copyright 2010            anonymous
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef _PKG_H_
#define _PKG_H_


#include "stdint.h"
#include "types.h"
#include "sce.h"
#include "tool_structures.h"


#ifdef __cplusplus
extern "C" {
#endif


/// "pkg" functions
int do_pkg_create(char* pInPath, char* pOutPath, char* pType, char* pKeyName, u64 OverrideFileSize);
int get_content(char* filename, u8** ppContent, u64* pContent_size_original, u64* pContent_size_final, u8* pDoCompress, u64 OverrideFileSize);
int get_key(const char *suffix, struct key* pMyKey);
int get_key_spkg(void);
int build_sce_hdr(sce_header_t* pSceHdr, u64 ContentSizeOriginal);
int build_meta_hdr(META_HDR* pMetaHdr, u64 ContentSizeFinal, u8 bDoCompress);
int fix_info_hdr(u8* pInfo0, u8* pInfo1, u64 ContentSizeOriginal, u64 ContentSizeFinal);
u64 build_pkg(sce_header_t* pSceHdr, META_HDR* pMetaHdr, u8** ppInPkg, u8** ppInSpkg, u8* pContent, u8* pInfo0, u8* pInfo1, u64 ContentSizeFinal);
int calculate_hash(u8 *data, u64 len, u8 *digest);
int hash_pkg(u8* pInPkg, u64 ContentSizeFinal);
int sign_pkg(u8* pInPkg);


/// "unpkg" functions
int do_pkg_decrypt(char* pInPath, char* pOutPath, char* pKeyName);
int decrypt_pkg(u8* pInPkg, u64* pDecSize, u32* pMetaOffset, char* pKeyName);
int unpack_content(const char *name, u8* pInPkg, u64* pDecSize, u32 MetaOffset);
int unpack_info(u32 i, char* filename, u8* pInPkg, u32 MetaOffset);
int unpack_pkg(u8* pInPkg, char* dirpath, u64* pDecSize, u32 MetaOffset);



#ifdef __cplusplus
}
#endif



#endif
// _PKG_H_
