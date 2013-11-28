// Copyright 2010            anonymous
// 
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <dirent.h>
#include <assert.h>
#include "tool_structures.h"
#include "Zlib_functions.h"
#include "file_functions.h"
#include "sha1.h"
#include "tools.h"
#include "sce.h"
#include "keys.h"
#include "ecdsa.h"




#ifdef WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <sys/mman.h>
#endif

#include "tools.h"
#include "aes.h"
#include "sha1.h"
#include "common.h"



// define external globals
/*! Loaded keysets. */
extern list_t *_keysets;
/*! Loaded curves. */
extern curve_t *_curves;
/*! Loaded VSH curves. */
extern vsh_curve_t *_vsh_curves;
/* debug variable     */
extern uint8_t b_DebugModeEnabled;
/* new keys files loaded */
extern uint8_t b_NewKeysFilesLoaded;

// structure for the ECDSA parameters
ecdsa_context ecdsa_ctx;

static struct id2name_tbl t_key2file[] = {
        {TRUE, KEY_LV0, "lv0"},
        {TRUE, KEY_LV1, "lv1"},
        {TRUE, KEY_LV2, "lv2"},
        {TRUE, KEY_APP, "app"},
        {TRUE, KEY_ISO, "iso"},
        {TRUE, KEY_LDR, "ldr"},
        {TRUE, KEY_PKG, "pkg"},
		{TRUE, KEY_SPKG, "spkg"},
        {TRUE, KEY_SPP, "spp"},
        {TRUE, KEY_NPDRM, "app"},
        {FALSE, 0, NULL}
};


//
// misc
//
void print_hash(u8 *ptr, u32 len)
{
	while(len--)
		printf(" %02x", *ptr++);
}

// function to verify the "SCE_HEADER_MAGIC"
int verify_sce_header(u8* pInPtr) 
{
	int retval = -1;
	u32 magic = 0;	
	sce_header_t* pSceHdr = NULL;

	// verify input param
	if (pInPtr == NULL)
		goto exit;

	// setup the sce_header ptr,
	// and grab the 'magic' value
	pSceHdr = (sce_header_t*)pInPtr;	
	magic = be32((u8*)&pSceHdr->magic);
	// check if the sig matches
	if ( (magic == SCE_HEADER_MAGIC) || (magic == PUP_SCE_HEADER_MAGIC) )
		retval = STATUS_SUCCESS;

exit:
	// return status
	return retval;
}

// func. for "ID" to name
const char *id2name(u32 id, struct id2name_tbl *t, const char *unk)
{
	while (t->name != NULL) {
		if (id == t->id)
			return t->name;
		t++;
	}
	return unk;
}


//
// ELF helpers
//
int elf_read_hdr(u8 *hdr, struct elf_hdr *h)
{
	int arch64;
	memcpy(h->e_ident, hdr, 16);
	hdr += 16;

	arch64 = h->e_ident[4] == 2;

	h->e_type = be16(hdr);
	hdr += 2;
	h->e_machine = be16(hdr);
	hdr += 2;
	h->e_version = be32(hdr);
	hdr += 4;

	if (arch64) {
		h->e_entry = be64(hdr);
		h->e_phoff = be64(hdr + 8);
		h->e_shoff = be64(hdr + 16);
		hdr += 24;
	} else {
		h->e_entry = be32(hdr);
		h->e_phoff = be32(hdr + 4);
		h->e_shoff = be32(hdr + 8);
		hdr += 12;
	}

	h->e_flags = be32(hdr);
	hdr += 4;

	h->e_ehsize = be16(hdr);
	hdr += 2;
	h->e_phentsize = be16(hdr);
	hdr += 2;
	h->e_phnum = be16(hdr);
	hdr += 2;
	h->e_shentsize = be16(hdr);
	hdr += 2;
	h->e_shnum = be16(hdr);
	hdr += 2;
	h->e_shtrndx = be16(hdr);

	return arch64;
}

//  func. read ELF phdr
void elf_read_phdr(int arch64, u8 *phdr, struct elf_phdr *p)
{
	if (arch64) {
		p->p_type =   be32(phdr + 0);
		p->p_flags =  be32(phdr + 4);
		p->p_off =    be64(phdr + 1*8);
		p->p_vaddr =  be64(phdr + 2*8);
		p->p_paddr =  be64(phdr + 3*8);
		p->p_filesz = be64(phdr + 4*8);
		p->p_memsz =  be64(phdr + 5*8);
		p->p_align =  be64(phdr + 6*8);
	} else {
		p->p_type =   be32(phdr + 0*4);
		p->p_off =    be32(phdr + 1*4);
		p->p_vaddr =  be32(phdr + 2*4);
		p->p_paddr =  be32(phdr + 3*4);
		p->p_filesz = be32(phdr + 4*4);
		p->p_memsz =  be32(phdr + 5*4);
		p->p_flags =  be32(phdr + 6*4);
		p->p_align =  be32(phdr + 7*4);
	}
}
// func. read ELF shdr
void elf_read_shdr(int arch64, u8 *shdr, struct elf_shdr *s)
{
	if (arch64) {
		s->sh_name =	  be32(shdr + 0*4);
		s->sh_type =	  be32(shdr + 1*4);
		s->sh_flags =	  (u32)be64(shdr + 2*4);
		s->sh_addr =	  be64(shdr + 2*4 + 1*8);
		s->sh_offset =	  be64(shdr + 2*4 + 2*8);
		s->sh_size =	  (u32)be64(shdr + 2*4 + 3*8);
		s->sh_link =	  be32(shdr + 2*4 + 4*8);
		s->sh_info =	  be32(shdr + 3*4 + 4*8);
		s->sh_addralign = (u32)be64(shdr + 4*4 + 4*8);
		s->sh_entsize =   (u32)be64(shdr + 4*4 + 5*8);
	} else {
		s->sh_name =	  be32(shdr + 0*4);
		s->sh_type =	  be32(shdr + 1*4);
		s->sh_flags =	  be32(shdr + 2*4);
		s->sh_addr =	  be32(shdr + 3*4);
		s->sh_offset =	  be32(shdr + 4*4);
		s->sh_size =	  be32(shdr + 5*4);
		s->sh_link =	  be32(shdr + 6*4);
		s->sh_info =	  be32(shdr + 7*4);
		s->sh_addralign = be32(shdr + 8*4);
		s->sh_entsize =   be32(shdr + 9*4);
	}
}
// func. ELF write shdr
void elf_write_shdr(int arch64, u8 *shdr, struct elf_shdr *s)
{
	if (arch64) {
		wbe32(shdr + 0*4, s->sh_name);
		wbe32(shdr + 1*4, s->sh_type);
		wbe64(shdr + 2*4, s->sh_flags);
		wbe64(shdr + 2*4 + 1*8, s->sh_addr);
		wbe64(shdr + 2*4 + 2*8, s->sh_offset);
		wbe64(shdr + 2*4 + 3*8, s->sh_size);
		wbe32(shdr + 2*4 + 4*8, s->sh_link);
		wbe32(shdr + 3*4 + 4*8, s->sh_info);
		wbe64(shdr + 4*4 + 4*8, s->sh_addralign);
		wbe64(shdr + 4*4 + 5*8, s->sh_entsize);
	} else {
		wbe32(shdr + 0*4, s->sh_name);
		wbe32(shdr + 1*4, s->sh_type);
		wbe32(shdr + 2*4, s->sh_flags);
		wbe32(shdr + 3*4, (u32)s->sh_addr);
		wbe32(shdr + 4*4, (u32)s->sh_offset);
		wbe32(shdr + 5*4, s->sh_size);
		wbe32(shdr + 6*4, s->sh_link);
		wbe32(shdr + 7*4, s->sh_info);
		wbe32(shdr + 8*4, s->sh_addralign);
		wbe32(shdr + 9*4, s->sh_entsize);
	}
}
//////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////
//
// crypto
//
int aes256cbc(u8 *key, u8 *iv_in, u8 *in, u64 len, u8 *out)
{
	aes_context aes_ctx = {0};		
	u8 iv[AES128_KEY_SIZE] = {0};
	int retval = -1;


	memcpy(iv, iv_in, AES128_KEY_SIZE);
	// setup the decrypt key
	if (aes_setkey_dec(&aes_ctx, key, 256) != 0)
		goto exit;

	// do the AES_CBC decrypt
	if (aes_crypt_cbc(&aes_ctx, AES_DECRYPT, (size_t)len, iv, in, out) != 0)
		goto exit;

	// status success
	retval = STATUS_SUCCESS;

exit:
	// return status
	return retval;
}

////////////////////////////////////////////////////////////////////////////////////
int aes256cbc_enc(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out)
{
	aes_context aes_ctx = {0};		
	u8 tmp[AES128_KEY_SIZE] = {0};
	int retval = -1;


	memcpy(tmp, iv, AES128_KEY_SIZE);	
	// setup the encrypt key
	if (aes_setkey_enc(&aes_ctx, key, 256) != 0)
		goto exit;

	// do the AES_CBC encrypt
	if (aes_crypt_cbc(&aes_ctx, AES_ENCRYPT, (size_t)len, iv, in, out) != 0)
		goto exit;

	// status success
	retval = STATUS_SUCCESS;

exit:
	// return status
	return retval;
}

//////////////////////////////////////////////////////////////////////////
int aes128cbc(u8 *key, u8 *iv_in, u8 *in, u64 len, u8 *out)
{
	aes_context aes_ctx = {0};			
	u8 iv[AES128_KEY_SIZE] = {0};
	int retval = -1;


	memcpy(iv, iv_in, AES128_KEY_SIZE);
	// setup the decrypt key
	if (aes_setkey_enc(&aes_ctx, key, 128) != 0)
		goto exit;

	// do the AES_CBC decrypt
	if (aes_crypt_cbc(&aes_ctx, AES_DECRYPT, (size_t)len, iv, in, out) != 0)
		goto exit;

	// status success
	retval = STATUS_SUCCESS;

exit:
	// return status
	return retval;
}

//////////////////////////////////////////////////////////////////////////////////////
int aes128cbc_enc(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out)
{
	aes_context aes_ctx = {0};		
	int retval = -1;


	// set the AES key context
	if (aes_setkey_enc(&aes_ctx, key, 128) != 0)
		goto exit;

	// do the AES CRYPT CBC
	if (aes_crypt_cbc(&aes_ctx, AES_ENCRYPT, (size_t)len, iv, in, out) != 0)
		goto exit;

	// status success
	retval = STATUS_SUCCESS;

exit:
	// return status
	return retval;
}

///////////////////////////////////////////////////////////////////////////////
/// func. for AES 128-bit CTR mode ////////////////////////////////////////////
int aes128ctr(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out)
{
	aes_context aes_ctx = {0};		
	size_t nc_off = 0;	
	unsigned char stream_block[AES128_KEY_SIZE] = {0};
	int retval = -1;


	// validate input params
	if ( (key == NULL) || (iv == NULL) || (in == NULL) || (out == NULL) )
		goto exit;		
	
	// set the AES key context
	if (aes_setkey_enc(&aes_ctx, key, 128) != 0)
		goto exit;	

	// do the AES-CTR crypt
	if (aes_crypt_ctr(&aes_ctx, (size_t)len, &nc_off, iv, stream_block, in, out) != 0)
			goto exit;	
	// status success
	retval = STATUS_SUCCESS;
	
exit:
	// return status
	return retval;
}
///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// func. for AES 256-bit CTR mode ////////////////////////////////////////////
int aes256ctr(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out)
{
	aes_context aes_ctx = {0};	
	size_t nc_off = 0;	
	unsigned char stream_block[AES256_KEY_SIZE] = {0};
	int retval = -1;


	// validate input params
	if ( (key == NULL) || (iv == NULL) || (in == NULL) || (out == NULL) )
		goto exit;		
	
	// set the AES key context
	if (aes_setkey_enc(&aes_ctx, key, 128) != 0)
		goto exit;	

	// do the AES-CTR crypt
	if (aes_crypt_ctr(&aes_ctx, (size_t)len, &nc_off, iv, stream_block, in, out) != 0)
			goto exit;	

	// status success
	retval = STATUS_SUCCESS;
	
exit:
	// return status
	return retval;
}
///////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////
int aes128(u8 *key, const u8 *in, u8 *out) {
	aes_context aes_ctx = {0};
	int retval = -1;
   

    // setup the AES key
	if (aes_setkey_dec(&aes_ctx, key, 128) != 0)
		goto exit;

	// do the AES decrypt
	if (aes_crypt_ecb(&aes_ctx, AES_DECRYPT, in, out) != 0)
		goto exit;

	// status success
	retval = STATUS_SUCCESS;

exit:
	// return the status
	return retval;
}

//////////////////////////////////////////////////////////////////////////
int aes128_enc(u8 *key, const u8 *in, u8 *out) {
	aes_context aes_ctx = {0};
	int retval = -1;
   

	// initialize the enc key
	if (aes_setkey_enc(&aes_ctx, key, 128) != 0)
		goto exit;

	// AES_encrypt(in, out, &k);
	if (aes_crypt_ecb(&aes_ctx, AES_ENCRYPT, in, out) != 0)
		goto exit;

	// status success
	retval = STATUS_SUCCESS;

exit:
	// return the status
	return retval;
}

////////////////////////////////////////////////////////////////////////
static int key_build_path(char *ptr)
{
	char *home = NULL;
	char *dir = NULL;
	

	// setup to get the ENV VAR
	memset(ptr, 0, MAX_PATH);	
	dir = getenv("PS3_KEYS");
	if (dir != NULL) {
		strncpy_s(ptr, MAX_PATH, dir, 256);
		goto exit;
	}

#ifdef WIN32
	home = getenv("USERPROFILE");   
#else
	home = getenv("HOME");
#endif
	if (home == NULL) {
          sprintf_s(ptr, MAX_PATH, "ps3keys");
        } else {
#ifdef WIN32
          sprintf_s(ptr, MAX_PATH, "%s\\ps3keys\\", home);
#else
          sprintf_s(ptr, MAX_PATH, "%s/.ps3/", home);
#endif
        }

exit:
	// we are done
	return 0;
}

//////////////////////////////////////////////////////////////////////////////
int key_read(const char *path, u32 len, u8 *dst)
{	
	int retval = -1;



	// validate input params
	if ( (path == NULL) || (dst == NULL) )
		goto exit;

	// read in the key data
	if ( ReadFileToBuffer((char*)path, &dst, len, NULL, FALSE) != STATUS_SUCCESS ) {
		printf("failed to read in file:%s, exiting...\n", path);
		goto exit;
	}

	// status success
	retval = STATUS_SUCCESS;

exit:
	// return status
	return retval;
}

///////////////////////////////////////////////////////////////////////
struct keylist* keys_get(enum sce_key type)
{
	const char *name = NULL;
	char base[MAX_PATH] = {0};
	char path[MAX_PATH] = {0};
	void *tmp = NULL;
	char *id = NULL;
	DIR *dp = NULL;
	struct dirent *dent = NULL;
	struct keylist *klist = NULL;
	u8 bfr[4] = {0};
	int retval = -1;


	__try 
	{
		// alloc mem for the 'klist' structure
		klist = calloc( sizeof(*klist), sizeof(char));
		if (klist == NULL)
			__leave;

		name = id2name(type, t_key2file, NULL);
		if (name == NULL)
			__leave;

		// build the base path to keys
		if (key_build_path(base) < 0)
			__leave;

		// attempt to open the key dir
		dp = opendir(base);
		if (dp == NULL)
			__leave;

		while ((dent = readdir(dp)) != NULL)
		{
			if (strncmp(dent->d_name, name, strlen(name)) == 0 &&
				strstr(dent->d_name, "key") != NULL) {
				tmp = realloc(klist->keys, (klist->n + 1) * sizeof(struct key));
				if (tmp == NULL)
					__leave;

				id = strrchr(dent->d_name, '-');
				if (id != NULL)
					id++;

				klist->keys = tmp;
				memset(&klist->keys[klist->n], 0, sizeof(struct key));

				sprintf_s(path, sizeof(path), "%s/%s-key-%s", base, name, id);
				if (key_read(path, 32, klist->keys[klist->n].key) != 0) {
					printf("  key file:   %s (ERROR)\n", path);
				}

				sprintf_s(path, sizeof(path), "%s/%s-iv-%s", base, name, id);
				if (key_read(path, AES128_KEY_SIZE, klist->keys[klist->n].iv) != 0) {
					printf("  iv file:    %s (ERROR)\n", path);
				}

				klist->keys[klist->n].pub_avail = -1;
				klist->keys[klist->n].priv_avail = -1;

				sprintf_s(path, sizeof(path), "%s/%s-pub-%s", base, name, id);
				if (key_read(path, 40, klist->keys[klist->n].pub) == 0) {
					sprintf_s(path, sizeof(path), "%s/%s-ctype-%s", base, name, id);
					key_read(path, 4, bfr);

					klist->keys[klist->n].pub_avail = 1;
					klist->keys[klist->n].ctype = be32(bfr);
				} else {
					printf("  pub file:   %s (ERROR)\n", path);
				}

				sprintf_s(path, sizeof(path), "%s/%s-priv-%s", base, name, id);
				if (key_read(path, 21, klist->keys[klist->n].priv) == 0) {
					klist->keys[klist->n].priv_avail = 1;
				} else {
					printf("  priv file:  %s (ERROR)\n", path);
				}


				klist->n++;
			}
		} // end while{} loop

		// if type is "NPDRM"
		if (type == KEY_NPDRM) 
		{
			klist->idps = calloc(sizeof(struct key), 1);
			if (klist->idps == NULL)
				__leave;

			sprintf_s(path, sizeof(path), "%s/idps", base);
			if (key_read(path, AES128_KEY_SIZE, klist->idps->key) != 0) {
				printf("  key file:   %s (ERROR)\n", path);
			}

			klist->klic = calloc(sizeof(struct key), 1);
			if (klist->klic == NULL)
				__leave;

			sprintf_s(path, sizeof(path), "%s/klic-key", base);
			if (key_read(path, AES128_KEY_SIZE, klist->klic->key) != 0) {
				printf("  key file:   %s (ERROR)\n", path);
			}

			klist->rif = calloc(sizeof(struct key), 1);
			if (klist->rif == NULL)
				__leave;

			sprintf_s(path, sizeof(path), "%s/rif-key", base);
			if (key_read(path, AES128_KEY_SIZE, klist->rif->key) != 0) {
				printf("  key file:   %s (ERROR)\n", path);
			}

			klist->npdrm_const = calloc(sizeof(struct key), 1);
			if (klist->npdrm_const == NULL)
				__leave;

			sprintf_s(path, sizeof(path), "%s/npdrm-const", base);
			if (key_read(path, AES128_KEY_SIZE, klist->npdrm_const->key) != 0) {
				printf("  key file:   %s (ERROR)\n", path);
			}

			klist->free_klicensee = calloc(sizeof(struct key), 1);
			if (klist->free_klicensee == NULL)
				__leave;

			sprintf_s(path, sizeof(path), "%s/free_klicensee-key", base);
			if (key_read(path, AES128_KEY_SIZE, klist->free_klicensee->key) != 0) {
				printf("  key file:   %s (ERROR)\n", path);
			}
		} // end if (type == KEY_NPDRM) 

		// status success
		retval = STATUS_SUCCESS;	

	} // end try{}

	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		printf("Exception Thrown:  keys_get() function......exiting....\n");
		retval = -1;
	}

	// if failed, then free the klist, 
	// and exit out
	if (retval != STATUS_SUCCESS)
	{
		if (klist != NULL)
		{
			if (klist->keys != NULL)
				free(klist->keys);
			free(klist);
		}
		klist = NULL;
	}
	return klist;
}

////////////////////////////////////////////////////////////////////////
int key_get_simple(const char *name, u8 *bfr, u32 len)
{
	char base[MAX_PATH] = {0};
	char path[MAX_PATH] = {0};
	int retval = -1;

	// validate input params
	if ( (name == NULL) || (bfr == NULL) )
		goto exit;

	// build the base path for the keys
	if ( key_build_path(base) < 0 )
		goto exit;

	// go attempt to read in the key
	sprintf_s(path, MAX_PATH, "%s/%s", base, name);
	if ( key_read(path, len, bfr) < 0 )
		goto  exit;

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}

// func for finding 'old style' key set via direct 'keyname' specified
int key_get_old(enum sce_key type, const char* suffix, struct key* pInKey)
{
	my_ecp_point* pMyEcpPoint_pub = NULL;	
	const char *name = "";
	const char *rev = "";
	char base[MAX_PATH] = {0};
	char path[MAX_PATH] = {0};
	u8 tmp[4] = {0};
	int retval = -1;

	

	// validate input params
	if ( (suffix == NULL) || (pInKey == NULL) )
		goto exit;

	__try
	{
		// get the 'old' style keys
		if ( strncmp( suffix, "retail", strlen( suffix ) ) == 0 ) {
			rev = "retail";
		} else if ( atoi( suffix ) <= 92 ) {
			suffix = "092";
			rev = "0x00";
		} else if ( atoi( suffix ) <= 331 ) {
			suffix = "315";
			rev = "0x01";
		} else if ( atoi( suffix ) <= 342 ) {
			suffix = "341";
			rev = "0x04";
		} else if ( atoi( suffix ) <= 350 ) {
			suffix = "350";
			rev = "0x07";
		} else if ( atoi( suffix ) <= 355 ) {
			suffix = "355";
			rev = "0x0a";
		} else if ( atoi( suffix ) <= 356 ) {
			suffix = "356";
			rev = "0x0d";
		}
		// build the base path to the 'keys' 
		printf("  file suffix:    %s (rev %s)\n", suffix, rev );
		if (key_build_path(base) < 0)
			__leave;

		// grab the 'type' from the table
		name = id2name(type, t_key2file, NULL);
		if (name == NULL)
			__leave;

		// read in the "key" (erk)
		sprintf_s(path, sizeof(path), "%s/%s-key-%s", base, name, suffix);
		if (key_read(path, sizeof(pInKey->key), pInKey->key) != STATUS_SUCCESS ) {
			printf("  key file:   %s (ERROR)\n", path);
			__leave;
		}

		// read in the "iv"
		sprintf_s(path, sizeof(path), "%s/%s-iv-%s", base, name, suffix);
		if (key_read(path, sizeof(pInKey->iv), pInKey->iv) != STATUS_SUCCESS ) {
			printf("  iv file:    %s (ERROR)\n", path);
			__leave;
		}

		// read in the 'ctype'
		pInKey->pub_avail = pInKey->priv_avail = 1;
		sprintf_s(path, sizeof(path), "%s/%s-ctype-%s", base, name, suffix);
		if (key_read(path, sizeof(pInKey->ctype), tmp) != STATUS_SUCCESS ) {
			pInKey->pub_avail = pInKey->priv_avail = -1;
			printf("  ctype file: %s (ERROR)\n", path);
			__leave;
		}
		pInKey->ctype = be32(tmp);

		// read in the 'pub' key		
		sprintf_s(path, sizeof(path), "%s/%s-pub-%s", base, name, suffix);
		if (key_read(path, sizeof(pInKey->pub), pInKey->pub) != STATUS_SUCCESS ) {
			printf("  pub file:   %s (ERROR)\n", path);
			pInKey->pub_avail = -1;
		}

		// read in the 'priv' key
		sprintf_s(path, sizeof(path), "%s/%s-priv-%s", base, name, suffix);
		if (key_read(path, sizeof(pInKey->priv), pInKey->priv) != STATUS_SUCCESS ) {
			printf("  priv file:  %s (ERROR)\n", path);
			pInKey->priv_avail = -1;		
		}
		/**/
		/*******************************************************************/

		// read in the ECDSA curve parameters
		ecdsa_init( &ecdsa_ctx );		
		if ( ecdsa_get_params(pInKey->ctype, &ecdsa_ctx) != STATUS_SUCCESS )
			__leave;

		// read in the pub points Q.x, Q.y, & priv key 'D'
		pMyEcpPoint_pub = (my_ecp_point*)pInKey->pub;	
		if ( mpi_read_binary(&ecdsa_ctx.Q.X, (unsigned char*)&pMyEcpPoint_pub->x, ECDSA_KEYSIZE_PUB) != 0 )
			__leave;
		if ( mpi_read_binary(&ecdsa_ctx.Q.Y, (unsigned char*)&pMyEcpPoint_pub->y, ECDSA_KEYSIZE_PUB) != 0 )
			__leave;
		if ( mpi_read_binary(&ecdsa_ctx.d, (unsigned char*)&pInKey->priv, sizeof(pInKey->priv)) != 0 )
			__leave;

		// status success
		retval = STATUS_SUCCESS;

	} // end try{}

	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		printf("Exception thrown-->key_get() function....exiting...\n");
		retval = -1;
	}

exit:
	// return status
	return retval;
}
/**/
/*****************************************************************************/



/***************************************************************************/
int key_get_new(u16 KeyRev, u16 header_type, struct key *pInKey)
{
	keyset_t *pKeySet = NULL;
	u16 MyHdrType = 0;
	my_ecp_point* pMyEcpPoint_pub = NULL;	
	int retval = -1;
	


	// validate input params
	if ( (pInKey == NULL) || (b_NewKeysFilesLoaded == FALSE ) )
		goto exit;			

	__try 
	{		
		// correct the 'endianness' for the hdr-type
		MyHdrType = be16((u8*)&header_type);

		switch (MyHdrType) 
		{
		// find the "PKG/SPKG" decrypt key
		case SCE_HEADER_TYPE_PKG:

			// now go and try to find the correct keyset for this 'version'
			pKeySet = _keyset_find_for_pkg(KeyRev);	
			if (pKeySet == NULL) {
				printf("Error! Could not find PKG key in new keys file.....\n");
				__leave;
			}
			break;

		// find the "SPP" decrypt key
		case SCE_HEADER_TYPE_SPP:

			// now go and try to find the correct keyset for this 'version'
			pKeySet = _keyset_find_for_spp(KeyRev);	
			if (pKeySet == NULL) {
				printf("Error! Could not find SPP key in new keys file.....\n");
				__leave;
			}
			break;

		default:
			printf("Error!  Uknown header type specified:%x, exiting...\n", header_type);
			__leave;

		}; // end switch{}

		// copy over the ERK (ie 'key')
		if ( pKeySet->erk != NULL) {
			if ( memcpy_s(&pInKey->key, sizeof(pInKey->key), pKeySet->erk, sizeof(pInKey->key) ) != 0 ) {
				printf("Failed to copy keys, exiting!\n");
				__leave;
			}
		}
		// copy over the RIV (ie 'iv)
		if ( pKeySet->riv != NULL) {
			if ( memcpy_s(&pInKey->iv, sizeof(pInKey->iv), pKeySet->riv, sizeof(pInKey->iv) ) != 0 ) {
				printf("Failed to copy keys, exiting!\n");
				__leave;
			}
		}
		// get the 'c-type'	
		if ( memcpy_s(&pInKey->ctype, sizeof(pInKey->ctype), &pKeySet->ctype, sizeof(pInKey->ctype) ) != 0 )  {
			printf("Failed to copy keys, exiting!\n");
			__leave;
		}	
		// copy over the pub key
		if ( pKeySet->pub != NULL) {
			if ( memcpy_s(&pInKey->pub, sizeof(pInKey->pub), pKeySet->pub, sizeof(pInKey->pub) ) != 0 ) {
				printf("Failed to copy keys, exiting!\n");
				__leave;
			}
		}
		// copy over the priv key
		if ( pKeySet->priv != NULL) {
			if ( memcpy_s(&pInKey->priv, sizeof(pInKey->priv), pKeySet->priv, sizeof(pInKey->priv) ) != 0 ) {
				printf("Failed to copy keys, exiting!\n");
				__leave;
			}	
		}
		/* if we found the keyset in the 'keys' file  */
		// status success
		pInKey->pub_avail = pInKey->priv_avail = 1;					

		// read in the ECDSA curve parameters
		ecdsa_init( &ecdsa_ctx );		
		if ( ecdsa_get_params(pInKey->ctype, &ecdsa_ctx) != STATUS_SUCCESS )
			__leave;

		// read in the pub points Q.x, Q.y, & priv key 'D'
		pMyEcpPoint_pub = (my_ecp_point*)pInKey->pub;	
		if ( mpi_read_binary(&ecdsa_ctx.Q.X, (unsigned char*)&pMyEcpPoint_pub->x, ECDSA_KEYSIZE_PUB) != 0 )
			__leave;
		if ( mpi_read_binary(&ecdsa_ctx.Q.Y, (unsigned char*)&pMyEcpPoint_pub->y, ECDSA_KEYSIZE_PUB) != 0 )
			__leave;
		if ( mpi_read_binary(&ecdsa_ctx.d, (unsigned char*)&pInKey->priv, sizeof(pInKey->priv)) != 0 )
			__leave;
		
		// status success
		retval = STATUS_SUCCESS;

	} // end try{}

	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		printf("Exception thrown: key_get_new(), exiting....\n");
		retval = -1;
	}

exit:
	return retval;
}
/**/
/****************************************************************************/


/***************************************************************************/
int load_keylist_from_key(struct keylist** ppInKeyList, struct key* pInKey)
{	
	struct keylist* pMyKeyList = NULL;
	struct key* pKey = NULL;
	int retval = -1;
	


	// validate input params
	if ( (ppInKeyList == NULL) || (pInKey == NULL) )
		goto exit;


	__try
	{
		// alloc a struct for a single 'keylist'
		pKey = (struct key*)calloc(sizeof(struct key), sizeof(char));
		if (pKey == NULL) {
			printf("Error!  memory allocation failed, exiting....\n");
			__leave;
		}

		// alloc a struct for a single 'keylist'
		pMyKeyList = (struct keylist*)calloc(sizeof(struct keylist), sizeof(char));
		if (pMyKeyList == NULL) {
			printf("Error!  memory allocation failed, exiting....\n");
			__leave;
		}
		// setup the single 'keylist->key" struct
		pMyKeyList->keys = pKey;
		
		// copy over the ERK, (ie 'key') -- if defined --	
		if ( memcpy_s(&pMyKeyList->keys[0].key, sizeof(pInKey->key), pInKey->key, sizeof(pInKey->key) ) != 0 ) {
			printf("Failed to copy keys, exiting!\n");
			__leave;
		}	
		// copy over the RIV (ie 'iv) -- if defined --	
		if ( memcpy_s(&pMyKeyList->keys[0].iv, sizeof(pInKey->iv), pInKey->iv, sizeof(pInKey->iv) ) != 0 ) {
			printf("Failed to copy keys, exiting!\n");
			__leave;
		}	
		// get the 'c-type'  -- if defined --	
		if ( memcpy_s(&pMyKeyList->keys[0].ctype, sizeof(pInKey->ctype), &pInKey->ctype, sizeof(pInKey->ctype) ) != 0 )  {
			printf("Failed to copy keys, exiting!\n");
			__leave;
		}		
		// copy over the pub key  -- if defined --	
		if ( memcpy_s(&pMyKeyList->keys[0].pub, sizeof(pInKey->pub), pInKey->pub, sizeof(pInKey->pub) ) != 0 ) {
			printf("Failed to copy keys, exiting!\n");
			__leave;
		}	
		// copy over the priv key	
		if ( memcpy_s(&pMyKeyList->keys[0].priv, sizeof(pInKey->priv), pInKey->priv, sizeof(pInKey->priv) ) != 0 ) {
			printf("Failed to copy keys, exiting!\n");
			__leave;
		}	
		
		// status success	
		pMyKeyList->keys[0].pub_avail = pMyKeyList->keys[0].priv_avail = 1;
		pMyKeyList->n++;	

		*ppInKeyList = 	pMyKeyList;
		retval = STATUS_SUCCESS;

	} // end __try{}

	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		printf("Exception thrown: load_keylist_from_key(), exiting.....\n");
		retval = -1;
	}

exit:
	// return the status
	return retval;
}
/**/
/****************************************************************************/



/***************************************************************************/
int load_singlekey_by_name(char* pKeyName, struct keylist** ppInKeyList)
{	
	my_ecp_point* pMyEcpPoint_pub = NULL;	
	struct keylist* pMyKeyList = NULL;
	keyset_t *pKeySet = NULL;
	struct key* pKey = NULL;
	int retval = -1;



	// validate input params
	if ( (pKeyName == NULL) || (ppInKeyList == NULL) || (b_NewKeysFilesLoaded == FALSE) )
		goto exit;

	__try
	{
		// alloc a struct for a single 'keylist'
		pKey = (struct key*)calloc(sizeof(struct key), sizeof(char));
		if (pKey == NULL) {
			printf("Error!  memory allocation failed, exiting....\n");
			__leave;
		}

		// alloc a struct for a single 'keylist'
		pMyKeyList = (struct keylist*)calloc(sizeof(struct keylist), sizeof(char));
		if (pMyKeyList == NULL) {
			printf("Error!  memory allocation failed, exiting....\n");
			__leave;
		}
		// setup the single 'keylist->key" struct
		pMyKeyList->keys = pKey;
	
		// now go and try to find the keyset by 'keyname'
		pKeySet = keyset_find_by_name(pKeyName);
		if (pKeySet == NULL) {
			printf("Error! Could not find key in new keys file.....\n");
			__leave;
		}	
		// copy over the ERK, (ie 'key') -- if defined --
		if (pKeySet->erk != NULL) {
			if ( memcpy_s(&pMyKeyList->keys[0].key, sizeof(pKey->key), pKeySet->erk, sizeof(pKey->key) ) != 0 ) {
				printf("Failed to copy keys, exiting!\n");
				__leave;
			}
		}
		// copy over the RIV (ie 'iv) -- if defined --
		if (pKeySet->riv != NULL) {
			if ( memcpy_s(&pMyKeyList->keys[0].iv, sizeof(pKey->iv), pKeySet->riv, sizeof(pKey->iv) ) != 0 ) {
				printf("Failed to copy keys, exiting!\n");
				__leave;
			}
		}
		// get the 'c-type'  -- if defined --	
		if ( memcpy_s(&pMyKeyList->keys[0].ctype, sizeof(pKey->ctype), &pKeySet->ctype, sizeof(pKey->ctype) ) != 0 )  {
			printf("Failed to copy keys, exiting!\n");
			__leave;
		}		
		// copy over the pub key  -- if defined --
		if (pKeySet->pub != NULL) {
			if ( memcpy_s(&pMyKeyList->keys[0].pub, sizeof(pKey->pub), pKeySet->pub, sizeof(pKey->pub) ) != 0 ) {
				printf("Failed to copy keys, exiting!\n");
				__leave;
			}
		}
		// copy over the priv key
		if (pKeySet->priv != NULL) {
			if ( memcpy_s(&pMyKeyList->keys[0].priv, sizeof(pKey->priv), pKeySet->priv, sizeof(pKey->priv) ) != 0 ) {
				printf("Failed to copy keys, exiting!\n");
				__leave;
			}
		}
	
		/* if we found the keyset in the 'keys' file  */
		// status success	
		pMyKeyList->keys[0].pub_avail = pMyKeyList->keys[0].priv_avail = 1;
		pMyKeyList->n++;

		// read in the ECDSA curve parameters
		ecdsa_init( &ecdsa_ctx );		
		if ( ecdsa_get_params(pMyKeyList->keys[0].ctype, &ecdsa_ctx) != STATUS_SUCCESS )
			__leave;

		// read in the pub points Q.x, Q.y, & priv key 'D'
		pMyEcpPoint_pub = (my_ecp_point*)pMyKeyList->keys[0].pub;	
		if ( mpi_read_binary(&ecdsa_ctx.Q.X, (unsigned char*)&pMyEcpPoint_pub->x, ECDSA_KEYSIZE_PUB) != 0 )
			__leave;
		if ( mpi_read_binary(&ecdsa_ctx.Q.Y, (unsigned char*)&pMyEcpPoint_pub->y, ECDSA_KEYSIZE_PUB) != 0 )
			__leave;
		if ( mpi_read_binary(&ecdsa_ctx.d, (unsigned char*)&pMyKeyList->keys[0].priv, sizeof(pMyKeyList->keys[0].priv)) != 0 )
			__leave;

		// status success
		retval = STATUS_SUCCESS;
		*ppInKeyList = pMyKeyList;

	} // end try{}

	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		printf("Exception thrown: load_singlekey_by_name(), exiting....\n");
		retval = -1;
	}

exit:
	// if we failed, then free any memory
	if (retval != STATUS_SUCCESS) {
		if (pMyKeyList != NULL)
			free(pMyKeyList);
	}

	return retval;
}
/**/
/****************************************************************************/


/****************************************************************************/
/* func. for loading ALL keys of the requested 'type' into a keylist         */
int load_all_type_keys(struct keylist** ppInKeyList, u32 keytype)
{
	lnode_t* iter = NULL;
	struct keylist* pMyKeyList = NULL;
	keyset_t* pKeySet = NULL;
	struct key* pKey = NULL;
	void* tmp = NULL;
	int retval = -1;


	//validate input params
	if ( (ppInKeyList == NULL) || (b_NewKeysFilesLoaded == FALSE) )
		goto exit;

	pMyKeyList = (struct keylist*)calloc(sizeof(struct keylist), sizeof(char));
	if (pMyKeyList == NULL) {
		printf("Error!  memory allocation failed, exiting....\n");
		goto exit;
	}

	// iterate through the master "_keysets", and find ALL keys
	// that match the incoming type
	for(iter = _keysets->head; iter != NULL; iter = iter->next)	
	{
		pKeySet = (keyset_t*)iter->value;
		if(pKeySet->type == keytype)
		{
			// re-alloc our keystruct size, for the new keyset found
			tmp = realloc(pMyKeyList->keys, (pMyKeyList->n + 1) * sizeof(struct key));
			if (tmp == NULL)
				goto exit;
			
			pMyKeyList->keys = (struct key*)tmp;
			memset(&pMyKeyList->keys[pMyKeyList->n], 0, sizeof(struct key));		

			// copy over the ERK, (ie 'key') -- if defined --
			if (pKeySet->erk != NULL) {
				if ( memcpy_s(&pMyKeyList->keys[pMyKeyList->n].key, sizeof(pKey->key), pKeySet->erk, sizeof(pKey->key) ) != 0 ) {
					printf("Failed to copy keys, exiting!\n");
					goto exit;
				}
			}
			// copy over the RIV (ie 'iv) -- if defined --
			if (pKeySet->riv != NULL) {
				if ( memcpy_s(&pMyKeyList->keys[pMyKeyList->n].iv, sizeof(pKey->iv), pKeySet->riv, sizeof(pKey->iv) ) != 0 ) {
					printf("Failed to copy keys, exiting!\n");
					goto exit;
				}
			}
			// get the 'c-type'  -- if defined --			
			if ( memcpy_s(&pMyKeyList->keys[pMyKeyList->n].ctype, sizeof(pKey->ctype), &pKeySet->ctype, sizeof(pKey->ctype) ) != 0 )  {
				printf("Failed to copy keys, exiting!\n");
				goto exit;
			}				
			// copy over the pub key  -- if defined --
			if (pKeySet->pub != NULL) {
				if ( memcpy_s(&pMyKeyList->keys[pMyKeyList->n].pub, sizeof(pKey->pub), pKeySet->pub, sizeof(pKey->pub) ) != 0 ) {
					printf("Failed to copy keys, exiting!\n");
					goto exit;
				}
			}
			// copy over the priv key
			if (pKeySet->priv != NULL) {
				if ( memcpy_s(&pMyKeyList->keys[pMyKeyList->n].priv, sizeof(pKey->priv), pKeySet->priv, sizeof(pKey->priv) ) != 0 ) {
					printf("Failed to copy keys, exiting!\n");
					goto exit;
				}
			}	
			/* if we found the keyset in the 'keys' file  */
			// status success
			pMyKeyList->keys[pMyKeyList->n].pub_avail = pMyKeyList->keys[pMyKeyList->n].priv_avail = 1;
			pMyKeyList->n++;
		}
	} // end for (_keysets)....

	// if DEBUG, display the total num. of keys found
	if (b_DebugModeEnabled == TRUE)
		printf("Total keys loaded: %d\n", pMyKeyList->n);

	// status success
	retval = STATUS_SUCCESS;	
	*ppInKeyList = pMyKeyList;

exit:
	// if we failed, then return "NULL" for the keylist, 
	// and free any alloc'd memory
	if (retval != STATUS_SUCCESS) {
		*ppInKeyList = NULL;
		if (pMyKeyList != NULL)
			free(pMyKeyList);
	}

	return retval;
}
/**/
/*****************************************************************************/


/***************************************************************************/
int load_keys_files(void)
{		
	char path[MAX_PATH] = {0};	
	s8 *ps3 = NULL;
	char keypath[MAX_PATH] = {0};
	int retval = -1;
		


	// Try to get path from env var: "PS3_KEYS"
	if((ps3 = getenv(DEFAULT_PS3KEYS_ENV)) != NULL) {
		if(_access_s(ps3, 0) != 0)
			ps3 = NULL;
	}
	// if 'PS3_KEYS' env found, then go build
	// the path, and see if it exists
	if(ps3 != NULL)
	{
		sprintf_s(keypath, MAX_PATH, "%s/%s", ps3, CONFIG_KEYS_FILE);
		if(_access_s(keypath, 0) != 0)
			sprintf_s(keypath, MAX_PATH, "%s/%s", CONFIG_KEYS_PATH, CONFIG_KEYS_FILE);
	}
	else
		sprintf_s(keypath, MAX_PATH, "%s/%s", CONFIG_KEYS_PATH, CONFIG_KEYS_FILE);

	/*********************************************/
	/* load the 'scetool' compatible 'KEYS' file */
	if ( keys_load(keypath ) != TRUE) {
		printf("Error:  Failed to load the 'keys' file, reverting to old keys files....\n");
		goto exit;
	}
	else
		printf("Loaded keys from:%s\n", keypath);
	
	// setup path to 'curves'
	if(ps3 != NULL)
	{
		sprintf_s(keypath, MAX_PATH, "%s/%s", ps3, CONFIG_CURVES_FILE);
		if(_access_s(keypath, 0) != 0)
			sprintf_s(keypath, MAX_PATH, "%s/%s", CONFIG_CURVES_PATH, CONFIG_CURVES_FILE);			
	}
	else
		sprintf_s(keypath, MAX_PATH, "%s/%s", CONFIG_CURVES_PATH, CONFIG_CURVES_FILE);	

	/*********************************************/
	/* load the 'scetool' compatible 'CURVES' file */
	if ( curves_load(keypath) != TRUE ) {
		printf("Error:  Failed to load the 'curves' file, reverting to old keys files....\n");
		goto exit;
	}
	else
		printf("Loaded curves from:%s\n", keypath);
	
	// setup path to 'vsh curves'
	if(ps3 != NULL)
	{
		sprintf_s(keypath, MAX_PATH, "%s/%s", ps3, CONFIG_VSH_CURVES_FILE);
		if(_access_s(keypath, 0) != 0)
			sprintf_s(keypath, MAX_PATH, "%s/%s", CONFIG_VSH_CURVES_PATH, CONFIG_VSH_CURVES_FILE);
	}
	else
		sprintf_s(path, MAX_PATH, "%s/%s", CONFIG_VSH_CURVES_PATH, CONFIG_VSH_CURVES_FILE);

	/*********************************************/
	/* load the 'scetool' compatible 'VSH_CURVES' file */
	if ( vsh_curves_load(keypath) != TRUE ) {
		printf("Error:  Failed to load the 'vsh curves' file, reverting to old keys files....\n");
		goto exit;
	}
	else 
		printf("Loaded vsh curves from:%s\n\n", keypath);
	/**/
	/*********************************************/

	// status success
	b_NewKeysFilesLoaded = TRUE;
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
/**/
/****************************************************************************/


// build the RIF struct
struct rif *rif_get(const char *content_id)
{
	char base[MAX_PATH] = {0};
	char path[MAX_PATH] = {0};
    struct rif *rif = NULL;   
	int retval = -1;
	

	// validate input params
	if (content_id == NULL)
		goto exit;

	// alloc a struct for the RIF
    rif = (struct rif *)calloc( sizeof(struct rif), sizeof(char) );
	if (rif == NULL)
		goto exit;

	// build the path to the key file
	if (key_build_path(base) < 0)
		goto exit;

	// build the string path
    sprintf_s(path, MAX_PATH, "%s/exdata/%s.rif", base, content_id);

	// read in the "rif" key file
	if ( ReadFileToBuffer((char*)path, (uint8_t**)&rif, sizeof(struct rif), NULL, FALSE) != STATUS_SUCCESS ) {
		printf("failed to read in file:%s, exiting...\n", path);
		goto exit;  
	}

	// status success
	retval = STATUS_SUCCESS;

exit:
	// if we failed, then clean up
	if (retval != STATUS_SUCCESS) {
		// free any alloc'd mem
		if (rif != NULL) {
			free(rif);
			rif = NULL;
		}
	}
	return rif; 
}
////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////
//
struct actdat *actdat_get(void) 
{
	char base[MAX_PATH] = {0};
	char path[MAX_PATH] = {0};
    struct actdat *actdat = NULL;
	int retval = -1;


	// alloc memory for the ACTDATA struct
    actdat = (struct actdat *)calloc( sizeof(struct actdat), sizeof(char) );
	if (actdat == NULL)
		goto exit;

	// build the path to the key files
	if (key_build_path(base) < 0)
		goto exit;

	// build the string for the kety path
    sprintf_s(path, MAX_PATH, "%s/exdata/act.dat", base);

	// read in the 'act.dat' file
	if ( ReadFileToBuffer((char*)path, (uint8_t**)&actdat, (uint32_t)sizeof(struct actdat), NULL, FALSE) != STATUS_SUCCESS ) {
		printf("failed to read in file:%s, exiting...\n", path);
		goto exit;
	}
   
    // status success
	retval = STATUS_SUCCESS;

exit:
	// if not success, then clean up
	if (retval != STATUS_SUCCESS) {
		// free any alloc'd memory
		if (actdat != NULL) {
			free(actdat);
			actdat = NULL;
		}
	}
	return actdat; 
}
// func. to copy and 'invert' memory bytes
static void memcpy_inv(u8 *dst, u8 *src, u32 len)
{
	u32 j = 0;

	// iterate through, and copy/invert bytes
	for (j = 0; j < len; j++)
		dst[j] = ~src[j];
}
// func. to setup the ECDSA params
int ecdsa_get_params(u32 type, ecdsa_context* p_ecdsa_ctx)
{
	static u8 tbl[64 * 121] = {0};
	static u8 inv_tbl[64 * 121] = {0};
	char path[MAX_PATH] = {0};
	u32 offset = 0;
	curve_t* pCurveParams = NULL;
	int retval = -1;


	// validate input params
	if ( p_ecdsa_ctx == NULL ) 
		goto exit;

	// if we have the NEW 'keys/curves/etc' files loaded,
	// then look for the curves file there, otherwise,
	// load from 'old method'
	if (b_NewKeysFilesLoaded == TRUE)
	{
		// finding 'vsh curves'
		if(type & USE_VSH_CURVE)
		{
			//Loader curve.
			if((pCurveParams = vsh_curve_find((u8)type)) == NULL) {
				printf("Error:  Could not find key in 'vsh curves' file, exiting..\n");
				goto exit;			
			}
		}
		// finding regular curves
		else
		{
			//Loader curve.
			if((pCurveParams = curve_find((u8)type)) == NULL) {
				printf("Error:  Could not find key in 'curves' file, exiting...\n");
				goto exit;			
			}			
			
			// need to invert all the bytes
			memcpy_inv( (u8*)pCurveParams, (u8*)pCurveParams, sizeof(curve_t) );			

			// read in the ECDSA curve param - "P"
			if (mpi_read_binary(&ecdsa_ctx.grp.P, (u8*)&pCurveParams->p, sizeof(pCurveParams->p)) != 0)
				goto exit;

			// read in the ECDSA curve param - "A"
			if (mpi_read_binary(&ecdsa_ctx.grp.A, (u8*)&pCurveParams->a, sizeof(pCurveParams->a)) != 0)
				goto exit;

			// read in the ECDSA curve param - "B"
			if (mpi_read_binary(&ecdsa_ctx.grp.B, (u8*)&pCurveParams->b, sizeof(pCurveParams->b)) != 0)
				goto exit;

			// read in the ECDSA curve param - "N"
			if (mpi_read_binary(&ecdsa_ctx.grp.N, (u8*)&pCurveParams->N, sizeof(pCurveParams->N)) != 0)
				goto exit;

			// read in the ECDSA curve param - "Gx"
			if (mpi_read_binary(&ecdsa_ctx.grp.G.X, (u8*)&pCurveParams->Gx, sizeof(pCurveParams->Gx)) != 0)
				goto exit;

			// read in the ECDSA curve param - "Gy"
			if (mpi_read_binary(&ecdsa_ctx.grp.G.Y, (u8*)&pCurveParams->Gy, sizeof(pCurveParams->Gy)) != 0)		
				goto exit;	

			// set the "G.Z" co-ordinate as "1"
			mpi_lset( &ecdsa_ctx.grp.G.Z, 1 );

			// setup the number of bits in 'p' and 'n'
			ecdsa_ctx.grp.pbits = mpi_msb( &ecdsa_ctx.grp.P );
			ecdsa_ctx.grp.nbits = mpi_msb( &ecdsa_ctx.grp.N );
		}
	}
	//////  USE 'OLD FILES METHOD	/////////////////////////////////////////
	else 
	{	
		// make sure our key path is good
		if (key_build_path(path) < 0)
			goto exit;

		// finding 'vsh curves' (or 'curves' file)
		if(type & USE_VSH_CURVE)			 
			strncat_s(path, MAX_PATH, "/vsh_curves", sizeof(path));
		else 
			strncat_s(path, MAX_PATH, "/curves", sizeof(path));
		// read in the curves(or vsh_curves) file
		if (key_read(path, sizeof(tbl), tbl) < 0)
			goto exit;	

		// make a copy of the full keys table, 
		// with all bytes inverted
		memcpy_inv(inv_tbl, tbl, sizeof(tbl));	
	
		// setup the ptr at the index into the 'curves' file
		offset = type * sizeof(curve_t);
		pCurveParams = (curve_t*)(inv_tbl + offset);

		// read in the ECDSA curve param - "P"
		if (mpi_read_binary(&ecdsa_ctx.grp.P, (u8*)&pCurveParams->p, sizeof(pCurveParams->p)) != 0)
			goto exit;

		// read in the ECDSA curve param - "A"
		if (mpi_read_binary(&ecdsa_ctx.grp.A, (u8*)&pCurveParams->a, sizeof(pCurveParams->a)) != 0)
			goto exit;

		// read in the ECDSA curve param - "B"
		if (mpi_read_binary(&ecdsa_ctx.grp.B, (u8*)&pCurveParams->b, sizeof(pCurveParams->b)) != 0)
			goto exit;

		// read in the ECDSA curve param - "N"
		if (mpi_read_binary(&ecdsa_ctx.grp.N, (u8*)&pCurveParams->N, sizeof(pCurveParams->N)) != 0)
			goto exit;

		// read in the ECDSA curve param - "Gx"
		if (mpi_read_binary(&ecdsa_ctx.grp.G.X, (u8*)&pCurveParams->Gx, sizeof(pCurveParams->Gx)) != 0)
			goto exit;

		// read in the ECDSA curve param - "Gy"
		if (mpi_read_binary(&ecdsa_ctx.grp.G.Y, (u8*)&pCurveParams->Gy, sizeof(pCurveParams->Gy)) != 0)		
			goto exit;	

		// set the "G.Z" co-ordinate as "1"
		mpi_lset( &ecdsa_ctx.grp.G.Z, 1 );

		// setup the number of bits in 'p' and 'n'
		ecdsa_ctx.grp.pbits = mpi_msb( &ecdsa_ctx.grp.P );
		ecdsa_ctx.grp.nbits = mpi_msb( &ecdsa_ctx.grp.N );
	}
	//
	//////////////////////////////////////////////////////////////////

	// status success
	retval = STATUS_SUCCESS;

exit:	
	return retval;
}
/*************************************************************************/

// func to removed npdrm
int sce_remove_npdrm(u8 *ptr, struct keylist *klist)
{
    u64 ctrl_offset;
    u64 ctrl_size;
    u32 block_type;
    u32 block_size;
    u32 license_type;
    char content_id[0x31] = {'\0'};
    struct rif *rif;
    struct actdat *actdat;
    u8 enc_const[0x10];
    u8 dec_actdat[0x10];
    struct key klicensee;
    u64 i;

    ctrl_offset = be64(ptr + 0x58);
    ctrl_size = be64(ptr + 0x60);

    for (i = 0; i < ctrl_size; ) {
        block_type = be32(ptr + ctrl_offset + i);
        block_size = be32(ptr + ctrl_offset + i + 0x4);

        if (block_type == 3) {
            license_type = be32(ptr + ctrl_offset + i + 0x18);
            switch (license_type) {
                case 1:
                    // cant decrypt network stuff
                    return -1;
                case 2:
                    memcpy(content_id, ptr + ctrl_offset + i + 0x20, 0x30);
                    rif = rif_get(content_id);
                    if (rif == NULL) {
                        return -1;
                    }
                    aes128(klist->rif->key, rif->padding, rif->padding);
                    aes128_enc(klist->idps->key, klist->npdrm_const->key, enc_const);
                    actdat = actdat_get();
                    if (actdat == NULL) {
                        return -1;
                    }
                    aes128(enc_const, &actdat->keyTable[swap32(rif->actDatIndex)*0x10], dec_actdat);
                    aes128(dec_actdat, rif->key, klicensee.key);
                    sce_decrypt_npdrm(ptr, klist, &klicensee);
                    return 1;
                case 3:
                    sce_decrypt_npdrm(ptr, klist, klist->free_klicensee);
                    return 1;
            }
        }

        i += block_size;
    }

    return 0;
}

// func. to decrypt npdrm content
void sce_decrypt_npdrm(u8 *ptr, struct keylist *klist, struct key *klicensee)
{
	u32 meta_offset = 0;
	struct key d_klic = {0};

	// get the meta offset
	meta_offset = be32(ptr + 0x0c);

    // iv is 0
    memset(&d_klic, 0, sizeof(struct key));
    aes128(klist->klic->key, klicensee->key, d_klic.key);

    if ( aes128cbc(d_klic.key, d_klic.iv, ptr + meta_offset + 0x20, 0x40, ptr + meta_offset + 0x20) != STATUS_SUCCESS )
		goto exit;

exit:
	return;
}
////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////
// func. for decrypting the SCE header
int sce_decrypt_header_pkgtool(u8 *ptr, struct keylist *klist)
{
	u32 meta_offset = 0;
	u32 meta_len = 0;
	u64 header_len = 0;
	u32 i, j = 0;
	u8 tmp[0x40] = {0};
	sce_header_t* pSceHdr = NULL;
	int success = 0;
	int retval = -1;


	// validate input params
	if ( (ptr == NULL) || (klist == NULL) )
		goto exit;

	// setup the hdr sizes
	pSceHdr = (sce_header_t*)ptr;
	meta_offset = be32((u8*)&pSceHdr->metadata_offset);
	header_len  = be64((u8*)&pSceHdr->header_len);

	// setup the klist keys
	for (i = 0; i < klist->n; i++) {
		aes256cbc(klist->keys[i].key,
			  klist->keys[i].iv,
			  ptr + meta_offset + 0x20,
			  0x40,
			  tmp);

		// assume successful status, go through
		// decrypted bytes and verify decryption success
		success = 1;
		for (j = 0x10; j < (0x10 + 0x10); j++)
			if (tmp[j] != 0)
				success = 0;

		for (j = 0x30; j < (0x30 + 0x10); j++)
			if (tmp[j] != 0)
			       success = 0;
		// if success, copy our tmp data over
		if (success == 1) {
			memcpy(ptr + meta_offset + 0x20, tmp, 0x40);
			break;
		}
	}
	// if key not found, bail
	if (success != 1)
		goto exit;

	// do the AES-CTR of each meta block
	memcpy(tmp, ptr + meta_offset + 0x40, AES128_KEY_SIZE);
	if ( aes128ctr(ptr + meta_offset + 0x20,
		  tmp,
		  ptr + meta_offset + 0x60,
		  0x20,
		  ptr + meta_offset + 0x60) != STATUS_SUCCESS )
		  goto exit;

	meta_len = (u32)header_len - meta_offset;
	if ( aes128ctr(ptr + meta_offset + 0x20,
		  tmp,
		  ptr + meta_offset + 0x80,
		  meta_len - 0x80,
		  ptr + meta_offset + 0x80) != STATUS_SUCCESS )
		  goto exit;

	// if "debug enabled", print out our 
	// successful decrypt key
	if (b_DebugModeEnabled)
	{
		printf("Decrypt Successful!\n\tKey ERK:");
		for (j = 0; j < AES128_KEY_SIZE; j++)
			printf("%02x", klist->keys[i].key[j]);
		printf("\n\tKey  IV:");
		for (j = 0; j < AES128_KEY_SIZE; j++)
			printf("%02x", klist->keys[i].iv[j]);
		printf("\n\n");
	}
	// return successful status
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
// func. for encrypting the SCE hdr
int sce_encrypt_header_pkgtool(u8 *ptr, struct key *k)
{
	u32 meta_offset = 0;
	u32 meta_len = 0;
	u64 header_len = 0;
	u32 i = 0;
	u8 iv[AES128_KEY_SIZE] = {0};
	sce_header_t* pSceHdr = NULL;
	metadata_info_t* pMetaInfo = NULL;
	int retval = -1;


	// validate input params
	if ( (ptr == NULL) || (k == NULL) )
		goto exit;

	// setup the hdr fields
	pSceHdr = (sce_header_t*)ptr;
	meta_offset = be32((u8*)&pSceHdr->metadata_offset);
	header_len  = be64((u8*)&pSceHdr->header_len);
	meta_len = (u32)header_len - meta_offset;

	// setup the 'metadata_info' ptr
	pMetaInfo = (metadata_info_t*)(ptr + meta_offset);

	// copy over the 'iv', and do the 
	// 'aes128ctr' of the block
	memcpy(iv, ptr + meta_offset + 0x40, AES128_KEY_SIZE);
	if ( aes128ctr(ptr + meta_offset + 0x20,
		  iv,
		  ptr + meta_offset + 0x60,
		  meta_len - 0x60,
		  ptr + meta_offset + 0x60) != STATUS_SUCCESS )
		  goto exit;

	// do 'aes256 cbc' for the block
	if ( aes256cbc_enc(k->key, k->iv,
	              ptr + meta_offset + 0x20,
		      0x40,
		      ptr + meta_offset + 0x20) != STATUS_SUCCESS )
			  goto exit;

	// if "debug enabled", print out our 
	// encrypt key
	if (b_DebugModeEnabled)
	{
		printf("Key used for HDR encryption\n\tKey ERK:");
		for (i = 0; i < AES128_KEY_SIZE; i++)
			printf("%02x", k->key[i]);
		printf("\n\tKey  IV:");
		for (i = 0; i < AES128_KEY_SIZE; i++)
			printf("%02x", k->iv[i]);		
		printf("\n\n");
	}
	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
// func. for decrypting the SCE-DATA block(s)
int sce_decrypt_data_pkgtool(u8 *ptr)
{
	u64 meta_offset = 0;
	u32 meta_len = 0;
	u32 meta_n_hdr = 0;
	u64 header_len = 0;
	u32 i = 0;

	u64 offset = 0;
	u64 size = 0;
	u32 keyid = 0;
	u32 ivid = 0;
	u8 *tmp = NULL;
	u8 iv[AES128_KEY_SIZE] = {0};
	struct key MyKey = {0};
	sce_header_t* pSce_Header = NULL;
//	metadata_info_t* pMetaInfoHdr = NULL;
//	metadata_header_t* pMetaHeader = NULL;
	int retval = -1;


	// validate input params
	if (ptr == NULL)
		goto exit;

	// setup the hdr fields
	pSce_Header = (sce_header_t*)ptr;
	meta_offset = be32((u8*)&pSce_Header->metadata_offset);
	header_len  = be64((u8*)&pSce_Header->header_len);
	meta_len = (u32)header_len - (u32)meta_offset;
	meta_n_hdr = be32(ptr + meta_offset + sizeof(sce_header_t) + sizeof(metadata_info_t) + 0xc);

	for (i = 0; i < meta_n_hdr; i++) {
		tmp = ptr + meta_offset + 0x80 + 0x30*i;
		offset = be64(tmp);
		size = be64(tmp + 8);
		keyid = be32(tmp + 0x24);
		ivid = be32(tmp + 0x28);

		if (keyid == 0xffffffff || ivid == 0xffffffff)
			continue;

		// copy over the keys, and decrypt the data block
		memcpy(iv, ptr + meta_offset + 0x80 + 0x30 * meta_n_hdr + ivid * AES128_KEY_SIZE, AES128_KEY_SIZE);
		tmp = (ptr + meta_offset + 0x80 + 0x30 * meta_n_hdr + keyid * AES128_KEY_SIZE);
		memcpy_s(&MyKey.key, sizeof(MyKey.key), tmp, sizeof(MyKey.key) );
		if (aes128ctr(
				MyKey.key,		// erk
		        iv,				// iv
 		        ptr + offset,	// buffer
				size,			// size
				ptr + offset	// output
			  ) != STATUS_SUCCESS)
			  goto exit;
	}

	// if "debug enabled", print out our 
	// successful decrypt key
	if (b_DebugModeEnabled)
	{
		printf("Key used for Data Encrypt/Decrypt\n\tKey ERK:");
		for (i = 0; i < AES128_KEY_SIZE; i++)
			printf("%02x", MyKey.key[i]);
		printf("\n\tKey  IV:");
		for (i = 0; i < AES128_KEY_SIZE; i++)
			printf("%02x", MyKey.iv[i]);
		printf("\n\n");
	}
	// status success
	retval = STATUS_SUCCESS;

exit:
	// we are done, return!
	return retval;
}
// wrapper func for the decrypt data func
int sce_encrypt_data_pkgtool(u8 *ptr)
{
	return sce_decrypt_data_pkgtool(ptr);
}
/**/
/******************************************************************************/


// func. for GetRand  
int get_rand(u8 *bfr, u32 size)
{
	HCRYPTPROV hProv = 0;
	u32 i = 0;
	int retval = -1;

	// valid input params
	if ( bfr == NULL)
		goto exit;

	// init the crypto
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		printf("unable to open random\n");
		goto exit;
	}
	//gen the random nums
	if (!CryptGenRandom(hProv, size, bfr)) {
		printf("unable to read random numbers\n");
		goto exit;
	}
	// close the crypto handle
	CryptReleaseContext(hProv, 0);

	///////		DEBUG RNG OVERRIDE		////////////
	// if running "ebug" mode, then 
	// use static values of "0x11 0x11 0x11...."
	if (b_DebugModeEnabled == TRUE) {
		for (i = 0;i < size; i++)
			bfr[i] = 0x11;
	}
	////////////////////////////////////////////////

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}

// func for generating random chars
int get_random_char(void* ptr, uint8_t* pOutchar, size_t bufsize)
{
	HCRYPTPROV hProv = 0;
	size_t i = 0;
	int retval = -1;


	UNREFERENCED_PARAMETER(ptr);

	// validate input params
	if ( (pOutchar == NULL)  )
		goto exit;


	// init the crypto
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		printf("unable to open random\n");
		goto exit;
	}
	
	///////		DEBUG RNG OVERRIDE		////////////
	// if running "ebug" mode, then 
	// use static values of "0x11 0x11 0x11...."	
	if (b_DebugModeEnabled == TRUE)	{
		for (i = 0;i < bufsize; i++)
			pOutchar[i] = 0x11;
	}
	else {
		//gen the random nums
		if (!CryptGenRandom(hProv, (DWORD)bufsize, (BYTE*)pOutchar)) {
			printf("unable to read random numbers\n");
			goto exit;
		}		
	}	

	// close out the CryptContext
	// status success
	CryptReleaseContext(hProv, 0);
	retval = STATUS_SUCCESS;

exit:
	return retval;
}


// func. for swapping endianess of a buffer
int mem_swap_endian(u8* pInBuffer, uint32_t BufferSize)
{
	uint32_t i, j = 0;
	u8 temp = 0;
	int retval = -1;

	// validate input params
	if ( (pInBuffer == NULL) )
		goto exit;

	// iterate through the buffer
	for (i = 0, j = (BufferSize-1); i < (BufferSize/2); i++, j--)
	{
		temp = pInBuffer[i];
		pInBuffer[i] = pInBuffer[j];
		pInBuffer[j] = temp;
	}

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;


}
/**/
/*****************************************************************/