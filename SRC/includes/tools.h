// Copyright 2010            anonymous
// 
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef TOOLS_H__
#define TOOLS_H__



#include "stdint.h"
#include "types.h"
#include "ecdsa.h"




#ifdef __cplusplus
extern "C" {
#endif
	

#ifndef MAX_PATH
#define MAX_PATH 260
#endif




/************************************************/
/**/
// define this for overriding input arguments, and setting
// and RNG functions to static ints (0x11, 0x11, 0x11...)
//#define TOOL_DEBUG

//#define TOOL_DEBUG_TEST_PKG
//#define TOOL_DEBUG_TEST_SPKG

//#define TOOL_DEBUG_TEST_UNPKG
//#define TOOL_DEBUG_TEST_UNSPKG

//#define TOOL_DEBUG_TEST_PKG_SPP
//#define TOOL_DEBUG_TEST_UNPKG_SPP

//#define TOOL_DEBUG_TEST_UNPACK_COS
//#define TOOL_DEBUG_TEST_PACK_COS

//#define TOOL_DEBUG_TEST_PACK_PUP
//#define TOOL_DEBUG_TEST_UNPACK_PUP
/**/
/************************************************/


#define		round_up(x,n)	(-(-(x) & -(n)))
#define		array_size(x)	(sizeof(x) / sizeof(*(x)))


enum sce_key {
	KEY_LV0 = 0,
	KEY_LV1,
	KEY_LV2,
	KEY_APP,
	KEY_ISO,
	KEY_LDR,
	KEY_PKG,
	KEY_SPKG,
	KEY_SPP,
    KEY_NPDRM
};


int ecdsa_get_params(u32 type, ecdsa_context* p_ecdsa_ctx);
void print_hash(u8 *ptr, u32 len);
int verify_sce_header (u8* pInPtr) ;
const char *id2name(u32 id, struct id2name_tbl *t, const char *unk);
void decompress(u8 *in, u64 in_len, u8 *out, u64 out_len);

int elf_read_hdr(u8 *hdr, struct elf_hdr *h);
void elf_read_phdr(int arch64, u8 *phdr, struct elf_phdr *p);
void elf_read_shdr(int arch64, u8 *shdr, struct elf_shdr *s);
void elf_write_shdr(int arch64, u8 *shdr, struct elf_shdr *s);

int aes256cbc(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out);
int aes256cbc_enc(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out);
int aes128ctr(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out);
int aes256ctr(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out);
int aes128cbc(u8 *key, u8 *iv_in, u8 *in, u64 len, u8 *out);
int aes128cbc_enc(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out);
int aes128(u8 *key, const u8 *in, u8 *out);
int aes128_enc(u8 *key, const u8 *in, u8 *out);

int key_get_old(enum sce_key type, const char* suffix, struct key* pInKey);
int key_get_new(u16 KeyRev, u16 header_type, struct key *pInKey);
int key_get_simple(const char *name, u8 *bfr, u32 len);
struct keylist* keys_get(enum sce_key type);
int key_read(const char *path, u32 len, u8 *dst);

int load_keylist_from_key(struct keylist** ppInKeyList, struct key* pInKey);
int load_singlekey_by_name(char* pKeyName, struct keylist** ppInKeyList);
int load_all_type_keys(struct keylist** ppInKeyList, u32 keytype);
int load_keys_files(void);

struct rif *rif_get(const char *content_id);
struct actdat *actdat_get(void);

int sce_remove_npdrm(u8 *ptr, struct keylist *klist);
void sce_decrypt_npdrm(u8 *ptr, struct keylist *klist, struct key *klicensee);

int sce_decrypt_header_pkgtool(u8 *ptr, struct keylist *klist);
int sce_encrypt_header_pkgtool(u8 *ptr, struct key *k);
int sce_decrypt_data_pkgtool(u8 *ptr);
int sce_encrypt_data_pkgtool(u8 *ptr);

int get_rand(u8 *bfr, u32 size);
int get_random_char(void* ptr, uint8_t* pOutchar, size_t bufsize);
int mem_swap_endian(u8* pInBuffer, uint32_t BufferSize);

#ifdef __cplusplus
}
#endif


#endif
