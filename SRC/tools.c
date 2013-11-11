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

#ifndef ECDSA_ORG
#include "ecdsa.h"
#endif



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
extern uint8_t b_DebugModeEnabled;


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
static int key_read(const char *path, u32 len, u8 *dst)
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
struct keylist *keys_get(enum sce_key type)
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


	klist = calloc( sizeof(*klist), sizeof(char));
	if (klist == NULL)
		goto fail;	

	name = id2name(type, t_key2file, NULL);
	if (name == NULL)
		goto fail;

	if (key_build_path(base) < 0)
		goto fail;

	dp = opendir(base);
	if (dp == NULL)
		goto fail;

	while ((dent = readdir(dp)) != NULL) {
		if (strncmp(dent->d_name, name, strlen(name)) == 0 &&
		    strstr(dent->d_name, "key") != NULL) {
			tmp = realloc(klist->keys, (klist->n + 1) * sizeof(struct key));
			if (tmp == NULL)
				goto fail;

			id = strrchr(dent->d_name, '-');
			if (id != NULL)
				id++;

			klist->keys = tmp;
			memset(&klist->keys[klist->n], 0, sizeof(struct key));

			sprintf_s(path, sizeof path, "%s/%s-key-%s", base, name, id);
			if (key_read(path, 32, klist->keys[klist->n].key) != 0) {
				printf("  key file:   %s (ERROR)\n", path);
			}

			sprintf_s(path, sizeof path, "%s/%s-iv-%s", base, name, id);
			if (key_read(path, AES128_KEY_SIZE, klist->keys[klist->n].iv) != 0) {
				printf("  iv file:    %s (ERROR)\n", path);
			}

			klist->keys[klist->n].pub_avail = -1;
			klist->keys[klist->n].priv_avail = -1;

			sprintf_s(path, sizeof path, "%s/%s-pub-%s", base, name, id);
			if (key_read(path, 40, klist->keys[klist->n].pub) == 0) {
				sprintf_s(path, sizeof path, "%s/%s-ctype-%s", base, name, id);
				key_read(path, 4, bfr);

				klist->keys[klist->n].pub_avail = 1;
				klist->keys[klist->n].ctype = be32(bfr);
			} else {
				printf("  pub file:   %s (ERROR)\n", path);
			}

			sprintf_s(path, sizeof path, "%s/%s-priv-%s", base, name, id);
			if (key_read(path, 21, klist->keys[klist->n].priv) == 0) {
				klist->keys[klist->n].priv_avail = 1;
			} else {
				printf("  priv file:  %s (ERROR)\n", path);
			}


			klist->n++;
		}
	}

    if (type == KEY_NPDRM) {
        klist->idps = calloc(sizeof(struct key), 1);
        if (klist->idps == NULL)
            goto fail;
        sprintf_s(path, sizeof (path), "%s/idps", base);
        if (key_read(path, AES128_KEY_SIZE, klist->idps->key) != 0) {
            printf("  key file:   %s (ERROR)\n", path);
        }

        klist->klic = calloc(sizeof(struct key), 1);
        if (klist->klic == NULL)
            goto fail;
        sprintf_s(path, sizeof (path), "%s/klic-key", base);
        if (key_read(path, AES128_KEY_SIZE, klist->klic->key) != 0) {
            printf("  key file:   %s (ERROR)\n", path);
        }

        klist->rif = calloc(sizeof(struct key), 1);
        if (klist->rif == NULL)
            goto fail;
        sprintf_s(path, sizeof path, "%s/rif-key", base);
        if (key_read(path, AES128_KEY_SIZE, klist->rif->key) != 0) {
            printf("  key file:   %s (ERROR)\n", path);
        }

        klist->npdrm_const = calloc(sizeof(struct key), 1);
        if (klist->npdrm_const == NULL)
            goto fail;
        sprintf_s(path, sizeof path, "%s/npdrm-const", base);
        if (key_read(path, AES128_KEY_SIZE, klist->npdrm_const->key) != 0) {
            printf("  key file:   %s (ERROR)\n", path);
        }

        klist->free_klicensee = calloc(sizeof(struct key), 1);
        if (klist->free_klicensee == NULL)
            goto fail;
        sprintf_s(path, sizeof path, "%s/free_klicensee-key", base);
        if (key_read(path, AES128_KEY_SIZE, klist->free_klicensee->key) != 0) {
            printf("  key file:   %s (ERROR)\n", path);
        }
    }

	return klist;

fail:
	if (klist != NULL) {
		if (klist->keys != NULL)
			free(klist->keys);
		free(klist);
	}
	klist = NULL;

	return NULL;
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
	sprintf_s(path, sizeof path, "%s/%s", base, name);
	if ( key_read(path, len, bfr) < 0 )
		goto  exit;

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}

int key_get(enum sce_key type, const char *suffix, struct key *k)
{
	const char *name = "";
	const char *rev = "";
	char base[MAX_PATH] = {0};
	char path[MAX_PATH] = {0};
	u8 tmp[4] = {0};

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
	printf("  file suffix:    %s (rev %s)\n", suffix, rev );

	if (key_build_path(base) < 0)
		return -1;

	name = id2name(type, t_key2file, NULL);
	if (name == NULL)
		return -1;

	sprintf_s(path, sizeof path, "%s/%s-key-%s", base, name, suffix);
	if (key_read(path, 32, k->key) < 0) {
		printf("  key file:   %s (ERROR)\n", path);
		return -1;
	}

	sprintf_s(path, sizeof path, "%s/%s-iv-%s", base, name, suffix);
	if (key_read(path, AES128_KEY_SIZE, k->iv) < 0) {
		printf("  iv file:    %s (ERROR)\n", path);
		return -1;
	}

	k->pub_avail = k->priv_avail = 1;

	sprintf_s(path, sizeof path, "%s/%s-ctype-%s", base, name, suffix);
	if (key_read(path, 4, tmp) < 0) {
		k->pub_avail = k->priv_avail = -1;
		printf("  ctype file: %s (ERROR)\n", path);
		return 0;
	}

	k->ctype = be32(tmp);

	sprintf_s(path, sizeof path, "%s/%s-pub-%s", base, name, suffix);
	if (key_read(path, 40, k->pub) < 0) {
		printf("  pub file:   %s (ERROR)\n", path);
		k->pub_avail = -1;
	}

	sprintf_s(path, sizeof path, "%s/%s-priv-%s", base, name, suffix);
	if (key_read(path, 21, k->priv) < 0) {
		printf("  priv file:  %s (ERROR)\n", path);
		k->priv_avail = -1;
	}

	return 0;
}
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

static void memcpy_inv(u8 *dst, u8 *src, u32 len)
{
	u32 j;

	for (j = 0; j < len; j++)
		dst[j] = ~src[j];
}

int ecdsa_get_params(u32 type, u8 *p, u8 *a, u8 *b, u8 *N, u8 *Gx, u8 *Gy)
{
	static u8 tbl[64 * 121] = {0};
	char path[MAX_PATH] = {0};
	u32 offset = 0;
	curve_t* pCurveParams = NULL;
	int retval = -1;


	// validate input params
	if ( (p == NULL) || (a == NULL) || (b == NULL) || (N == NULL) || (Gx == NULL) || (Gy == NULL) )
		goto exit;

	// verify 'type' is valid
	if (type >= 64)
		goto exit;

	// make sure our key path is good
	if (key_build_path(path) < 0)
		goto exit;

	// setup the path to the 'curves' file
	strncat_s(path, MAX_PATH, "/curves", sizeof path);
	if (key_read(path, sizeof tbl, tbl) < 0)
		goto exit;

	// setup the offset to the curve, 
	// at the ptr to the key 'struct'
	offset = type * sizeof(curve_t);
	pCurveParams = (curve_t*)(tbl + offset);
	memcpy_inv(p, (u8*)&pCurveParams->p, sizeof(pCurveParams->p));
	memcpy_inv(a, (u8*)&pCurveParams->a, sizeof(pCurveParams->a));
	memcpy_inv(b, (u8*)&pCurveParams->b, sizeof(pCurveParams->b));
	memcpy_inv(N, (u8*)&pCurveParams->N, sizeof(pCurveParams->N));
	memcpy_inv(Gx, (u8*)&pCurveParams->Gx, sizeof(pCurveParams->Gx));
	memcpy_inv(Gy, (u8*)&pCurveParams->Gy, sizeof(pCurveParams->Gy));
	
	// status success
	retval = STATUS_SUCCESS;

exit:	
	return retval;
}
/*************************************************************************/


#ifndef ECDSA_ORG
int ecdsa_get_params_new(u32 type, ecdsa_context* p_ecdsa_ctx)
{
	static u8 tbl[64 * 121] = {0};
	static u8 inv_tbl[64 * 121] = {0};
	char path[MAX_PATH] = {0};
	u32 offset = 0;
	//ECDSA_KEY_FORMAT* pEcdsaKey = NULL;	
	curve_t* pCurveParams = NULL;
	int retval = -1;
	
	

	// verify input params
	if (p_ecdsa_ctx == NULL)
		goto exit;

	// verify 'type' is valid
	if (type >= 64)
		goto exit;

	// build the default key path
	if (key_build_path(path) < 0)
		goto exit;

	// build the path for the 'curves' file
	strncat_s(path, MAX_PATH, "/curves", sizeof path);
	if (key_read(path, sizeof(tbl), tbl) < 0)
		goto exit;

	// make a copy of the full keys table, 
	// with all bytes inverted
	memcpy_inv(inv_tbl, tbl, sizeof(tbl));
	
	
	// setup the ptr at the index into the 'curves' file
	offset = type * sizeof(curve_t);
	pCurveParams = (curve_t*)(tbl + offset);

	// read in the ECDSA curve param - "P"
	if (mpi_read_binary(&p_ecdsa_ctx->grp.P, (u8*)&pCurveParams->p, sizeof(pCurveParams->p)) != 0)
		goto exit;

	// read in the ECDSA curve param - "A"
	if (mpi_read_binary(&p_ecdsa_ctx->grp.A, (u8*)&pCurveParams->a, sizeof(pCurveParams->a)) != 0)
		goto exit;

	// read in the ECDSA curve param - ".
	if (mpi_read_binary(&p_ecdsa_ctx->grp.B, (u8*)&pCurveParams->b, sizeof(pCurveParams->b)) != 0)
		goto exit;

	// read in the ECDSA curve param - "N"
	if (mpi_read_binary(&p_ecdsa_ctx->grp.N, (u8*)&pCurveParams->N, sizeof(pCurveParams->N)) != 0)
		goto exit;

	// read in the ECDSA curve param - "Gx"
	if (mpi_read_binary(&p_ecdsa_ctx->grp.G.X, (u8*)&pCurveParams->Gx, sizeof(pCurveParams->Gx)) != 0)
		goto exit;

	// read in the ECDSA curve param - "Gy"
	if (mpi_read_binary(&p_ecdsa_ctx->grp.G.Y, (u8*)&pCurveParams->Gy, sizeof(pCurveParams->Gy)) != 0)		
		goto exit;	

	// set the "G.Z" co-ordinate as "1"
	mpi_lset( &p_ecdsa_ctx->grp.G.Z, 1 );

	// setup the number of bits in 'p' and 'n'
	p_ecdsa_ctx->grp.pbits = mpi_msb( &p_ecdsa_ctx->grp.P );
    p_ecdsa_ctx->grp.nbits = mpi_msb( &p_ecdsa_ctx->grp.N );

	keys_load("test");

	// status success
	retval = STATUS_SUCCESS;
	
exit:
	// return our status
	return retval;
}
#endif

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

void sce_decrypt_npdrm(u8 *ptr, struct keylist *klist, struct key *klicensee)
{
	u32 meta_offset;
    struct key d_klic;

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
	int success = 0;
	int retval = -1;


	// validate input params
	if ( (ptr == NULL) || (klist == NULL) )
		goto exit;

	// setup the hdr sizes
	meta_offset = be32(ptr + 0x0c);
	header_len  = be64(ptr + 0x10);

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

	// return successful status
	retval = i;

exit:
	return retval;
}
// func. for encrypting the SCE hdr
int sce_encrypt_header_pkgtool(u8 *ptr, struct key *k)
{
	u32 meta_offset = 0;
	u32 meta_len = 0;
	u64 header_len = 0;
	u8 iv[AES128_KEY_SIZE] = {0};
	int retval = -1;


	// validate input params
	if ( (ptr == NULL) || (k == NULL) )
		goto exit;

	meta_offset = be32(ptr + 0x0c);
	header_len  = be64(ptr + 0x10);
	meta_len = (u32)header_len - meta_offset;

	memcpy(iv, ptr + meta_offset + 0x40, AES128_KEY_SIZE);
	if ( aes128ctr(ptr + meta_offset + 0x20,
		  iv,
		  ptr + meta_offset + 0x60,
		  meta_len - 0x60,
		  ptr + meta_offset + 0x60) != STATUS_SUCCESS )
		  goto exit;

	if ( aes256cbc_enc(k->key, k->iv,
	              ptr + meta_offset + 0x20,
		      0x40,
		      ptr + meta_offset + 0x20) != STATUS_SUCCESS )
			  goto exit;

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
	int retval = -1;


	// validate input params
	if (ptr == NULL)
		goto exit;

	// setup the hdr fields
	meta_offset = be32(ptr + 0x0c);
	header_len  = be64(ptr + 0x10);
	meta_len = (u32)header_len - (u32)meta_offset;
	meta_n_hdr = be32(ptr + meta_offset + 0x60 + 0xc);

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
		if (aes128ctr(ptr + meta_offset + 0x80 + 0x30 * meta_n_hdr + keyid * AES128_KEY_SIZE,
		          iv,
 		          ptr + offset,
			  size,
			  ptr + offset) != STATUS_SUCCESS)
			  goto exit;
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
int get_random_char(void* ptr, uint8_t* outchar, size_t bufsize)
{
	size_t i = 0;
	int temp = 0;

	UNREFERENCED_PARAMETER(ptr);


	///////		DEBUG RNG OVERRIDE		////////////
	// if running "ebug" mode, then 
	// use static values of "0x11 0x11 0x11...."
	if (b_DebugModeEnabled == TRUE)
	{
		for (i = 0;i < bufsize; i++)
			outchar[i] = 0x11;
	}
	else
	{
		// fill the incoming buffer with rand. data
		for (i = 0; i < bufsize; i++) 
		{
			temp = 0;
			while (temp == 0)
				temp = rand();			
			outchar[i] = (uint8_t)temp;
		}	
	}	
	return 0x00;
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