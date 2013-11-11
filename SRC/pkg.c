// Copyright 2010       anonymous
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
//



#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include "pkg.h"
#include "tool_structures.h"
#include "file_functions.h"
#include "Zlib_functions.h"
#include "sha1.h"
#include "tools.h"
#include "types.h"
#include "sce.h"
#include "bignum.h"

#ifndef ECDSA_ORG
#include "ecdsa.h"
#endif







/////////////////////////////////////
// define internal/external globals
//
extern PKG_FILE_NAMES g_pszPkgFileNames;
extern uint8_t b_DebugModeEnabled;
extern int32_t g_bZlibCompressLevel;

#ifndef ECDSA_ORG
ecdsa_context ecdsa_ctx;
#endif

//
/////////////////////////////////////




// func. for reading in the content file
int get_content(char* filename, u8** ppContent, u64* pContent_size_real, u64* pContent_size_compressed)
{
	u8* pBase = NULL;		
	uint32_t dwBytesRead = 0;
	int retval = -1;


	// validate input params
	if ( (filename == NULL) || (ppContent == NULL) || (pContent_size_real == NULL) || (pContent_size_compressed == NULL) )
		goto exit;

	// read the "content" file into a buffer (alloc buffer for the read)
	if ( ReadFileToBuffer(filename, &pBase, 0x00, &dwBytesRead, TRUE) != STATUS_SUCCESS) {
		printf("failed to read in file:%s, exiting...\n", filename);
		goto exit;
	}
	
	// calculate the size needed for compress buffer
	*pContent_size_real = (u64)dwBytesRead;
	*pContent_size_compressed = Zlib_GetMaxCompressedLen((int)*pContent_size_real);	

	// alloc memory for the compression output
	*ppContent = (u8*)calloc((size_t)*pContent_size_compressed, sizeof(char));
	if (*ppContent == NULL) {
		printf("out of memory");
		goto exit;
	}

	// do the Zlib compression
	*pContent_size_compressed = Zlib_CompressData(pBase, (int)*pContent_size_real, *ppContent, (int)*pContent_size_compressed, g_bZlibCompressLevel);
	if (*pContent_size_compressed <= 0) {
		printf("compress returned %d", *pContent_size_compressed);
		goto exit;
	}

	// resize the memory to the final size
	*ppContent = (u8*)realloc(*ppContent, (size_t)*pContent_size_compressed);
	if (*ppContent == NULL) {
		printf("out of memory");
		goto exit;
	}
	// free any alloc'd memory
	if (pBase != NULL)
		free(pBase);

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}

// func. for reading in the desired keyset
int get_key(const char *suffix, struct key* pMyKey)
{	
	#ifndef ECDSA_ORG
	my_ecp_point* pMyEcpPoint_pub = NULL;	
	#endif
	int retval = -1;

	// validate params
	if ( (suffix == NULL) || (pMyKey == NULL) )
		goto exit;

	if (key_get(KEY_PKG, suffix, pMyKey) < 0) {
		printf("key_get() failed");
		goto exit;
	}

	if (pMyKey->pub_avail < 0) {
		printf("no public key available");
		goto exit;
	}

	if (pMyKey->priv_avail < 0) {
		printf("no private key available");
		goto exit;
	}

	if (ecdsa_set_curve_org(pMyKey->ctype) < 0) {
		printf("ecdsa_set_curve failed");
		goto exit;
	}
	// setup the ECDSA pub/priv keys
	ecdsa_set_pub_org(pMyKey->pub);
	ecdsa_set_priv_org(pMyKey->priv);
	retval = STATUS_SUCCESS;

#ifndef ECDSA_ORG	
	pMyEcpPoint_pub = (my_ecp_point*)pMyKey->pub;	
	ecdsa_init( &ecdsa_ctx );		
	retval = ecdsa_get_params_new(pMyKey->ctype, &ecdsa_ctx);	
	mpi_read_binary(&ecdsa_ctx.Q.X, (unsigned char*)&pMyEcpPoint_pub->x, ECDSA_KEYSIZE);
	mpi_read_binary(&ecdsa_ctx.Q.Y, (unsigned char*)&pMyEcpPoint_pub->y, ECDSA_KEYSIZE);
	mpi_read_binary(&ecdsa_ctx.d, (unsigned char*)&pMyKey->priv, sizeof(pMyKey->priv));	
	retval = STATUS_SUCCESS;
#endif

exit:
	return retval;
}

// func. to get the "spkg" key
int get_key_spkg(void)
{
	int retval = -1;
	static struct key k, z = {0};

	// find the SPKG key
	if (key_get(KEY_SPKG, "retail", &z) < 0) {
		printf("key_get() failed");
		goto exit;
	}
	// check if 'pub' was found
	if (z.pub_avail < 0) {
		printf("no public key available");
		goto exit;
	}
	// check if 'priv' was found
	if (z.priv_avail < 0) {
		printf("no private key available");
		goto exit;
	}
	// set the ECDSA curve pts
	if (ecdsa_set_curve_org(z.ctype) < 0) {
		printf("ecdsa_set_curve failed");
		goto exit;
	}

	// setup the ECDSA pub/priv keys
	ecdsa_set_pub_org(z.pub);
	ecdsa_set_priv_org(z.priv);
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
// func for building the SCE hdr
int build_sce_hdr(sce_header_t* pSceHdr, u64 ContentSizeReal)
{
	sce_header_t* pSce_Header = NULL;
	int retval = -1;

	// validate input params
	if (pSceHdr == NULL)
		goto exit;

	// populate the SCE-HDR fields for PKG build
	pSce_Header = (sce_header_t*)pSceHdr;
	memset(pSceHdr, 0, sizeof (sce_header_t));	
	wbe32((u8*)&pSce_Header->magic, SCE_HEADER_MAGIC);			// magic
	wbe32((u8*)&pSce_Header->version, SCE_HEADER_VERSION_2);	// version
	wbe16((u8*)&pSce_Header->key_revision, KEY_REVISION_0);		// key revision
	wbe16((u8*)&pSce_Header->header_type, SCE_HEADER_TYPE_PKG);	// SCE header type; pkg
	wbe32((u8*)&pSce_Header->metadata_offset, 0);				// meta offset
	wbe64((u8*)&pSce_Header->header_len, sizeof (sce_header_t) + sizeof (META_HDR)); // header len
	wbe64((u8*)&pSce_Header->data_len, 0x80 + ContentSizeReal);	
	
	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
// func for building the META_HDR
int build_meta_hdr(META_HDR* pMetaHdr, u64 ContentSizeCompressed)
{
	u8 *ptr = NULL;
	metadata_info_t* pMetaDataInfoHeader = NULL;
	metadata_header_t* pMetaDataHeader = NULL;
	metadata_section_header_t* pMetaSectionHeader = NULL;
	int retval = -1;
	


	// validate input params
	if (pMetaHdr == NULL)
		goto exit;

	memset(pMetaHdr, 0, sizeof(META_HDR));
	ptr = (u8*)pMetaHdr;
	pMetaDataInfoHeader = (metadata_info_t*)ptr;

	// setup the "metadata" random generated keys
	get_rand((u8*)&pMetaDataInfoHeader->key, sizeof(pMetaDataInfoHeader->key));
	get_rand((u8*)&pMetaDataInfoHeader->iv, sizeof(pMetaDataInfoHeader->iv));
	ptr += sizeof(metadata_info_t);

	// area covered by the signature
	pMetaDataHeader = (metadata_header_t*)ptr;
	wbe64((u8*)&pMetaDataHeader->sig_input_length, sizeof(sce_header_t) + sizeof(META_HDR) - 0x30);
	wbe32((u8*)&pMetaDataHeader->unknown_0, 1);
	wbe32((u8*)&pMetaDataHeader->section_count, 3);		// number of encrypted headers
	wbe32((u8*)&pMetaDataHeader->key_count, (4 * 5));	// number of keys/hashes required ++++++
	ptr += 0x20;

	// first info header
	pMetaSectionHeader = (metadata_section_header_t*)ptr;
	wbe64((u8*)&pMetaSectionHeader->data_offset, 0x280);				// offset //SIZE_SPKG_HDR
	wbe64((u8*)&pMetaSectionHeader->data_size, 0x40);					// size
	wbe32((u8*)&pMetaSectionHeader->type, METADATA_SECTION_TYPE_SHDR);	// type
	wbe32((u8*)&pMetaSectionHeader->index, 1);							// index
	wbe32((u8*)&pMetaSectionHeader->hashed, METADATA_SECTION_HASHED);	// hashed
	wbe32((u8*)&pMetaSectionHeader->sha1_index, 0);						// sha index
	wbe32((u8*)&pMetaSectionHeader->encrypted, METADATA_SECTION_NOT_ENCRYPTED);// no encryption
	wbe32((u8*)&pMetaSectionHeader->key_index, 0xffffffff);				// key index
	wbe32((u8*)&pMetaSectionHeader->iv_index, 0xffffffff);				// iv index
	wbe32((u8*)&pMetaSectionHeader->compressed, METADATA_SECTION_NOT_COMPRESSED);// no compression
	ptr += sizeof(metadata_section_header_t);

	// second info header
	pMetaSectionHeader = (metadata_section_header_t*)ptr;
	wbe64((u8*)&pMetaSectionHeader->data_offset, 0x2c0);				// offset
	wbe64((u8*)&pMetaSectionHeader->data_size, 0x40);					// size
	wbe32((u8*)&pMetaSectionHeader->type, METADATA_SECTION_TYPE_PHDR); 	// type
	wbe32((u8*)&pMetaSectionHeader->index, 2);							// index
	wbe32((u8*)&pMetaSectionHeader->hashed, METADATA_SECTION_HASHED);	// hashed
	wbe32((u8*)&pMetaSectionHeader->sha1_index, 6);						// sha index
	wbe32((u8*)&pMetaSectionHeader->encrypted, METADATA_SECTION_NOT_ENCRYPTED);// no encryption
	wbe32((u8*)&pMetaSectionHeader->key_index, 0xffffffff);				// key index
	wbe32((u8*)&pMetaSectionHeader->iv_index, 0xffffffff);				// iv index
	wbe32((u8*)&pMetaSectionHeader->compressed, METADATA_SECTION_NOT_COMPRESSED);// no compression
	ptr += sizeof(metadata_section_header_t);

	// package files
	pMetaSectionHeader = (metadata_section_header_t*)ptr;
	wbe64((u8*)&pMetaSectionHeader->data_offset, 0x300);				// offset
	wbe64((u8*)&pMetaSectionHeader->data_size, ContentSizeCompressed);	// size
	wbe32((u8*)&pMetaSectionHeader->type, METADATA_SECTION_TYPE_UNK_3); // unknown
	wbe32((u8*)&pMetaSectionHeader->index, 3);							// index
	wbe32((u8*)&pMetaSectionHeader->hashed, METADATA_SECTION_HASHED);	// hashed
	wbe32((u8*)&pMetaSectionHeader->sha1_index, 12);					// sha index
	wbe32((u8*)&pMetaSectionHeader->encrypted, METADATA_SECTION_ENCRYPTED);// encrypted
	wbe32((u8*)&pMetaSectionHeader->key_index, 18);						// key index
	wbe32((u8*)&pMetaSectionHeader->iv_index, 19);						// iv index
	wbe32((u8*)&pMetaSectionHeader->compressed, METADATA_SECTION_COMPRESSED);// compressed
	ptr += sizeof(metadata_section_header_t);

	// add keys/ivs and hmac keys
	get_rand(ptr, 0x13c);
	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
// func for fixing the 'info' hdr
int fix_info_hdr(u8* pInfo0, u8* pInfo1, u64 ContentSizeReal, u64 ContentSizeCompressed)
{	
	int retval = -1;

	// validate input params
	if ( (pInfo0 == NULL) || (pInfo1 == NULL) )
		goto exit;

	// setup the info header
	wbe64(pInfo0 + 0x18, ContentSizeReal);
	wbe64(pInfo0 + 0x20, ContentSizeCompressed);
	wbe64(pInfo1 + 0x18, ContentSizeReal);
	wbe64(pInfo1 + 0x20, 0x01);

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
// main function for 'building' the output PKG file
u64 build_pkg(sce_header_t* pSceHdr, META_HDR* pMetaHdr, u8** ppInPkg, u8** ppInSpkg, u8* pContent, u8* pInfo0, u8* pInfo1, u64 ContentSizeCompressed)
{
	static u64 pkg_size = 0;
	u64 retval = STATUS_SUCCESS;


	// validate input params
	if ( (pSceHdr == NULL) || (pMetaHdr == NULL) || (ppInPkg == NULL) || (ppInSpkg == NULL) || (pContent == NULL) || (pInfo0 == NULL) || (pInfo1 == NULL) )
		goto exit;

	// setup the initial sizes
	pkg_size = sizeof(sce_header_t) + sizeof(META_HDR) + 0x80;
	pkg_size += ContentSizeCompressed;

	*ppInPkg = (u8*)calloc((size_t)pkg_size, sizeof(char));
	*ppInSpkg = (u8*)calloc((size_t)pkg_size, sizeof(char));
	if ( (*ppInPkg == NULL) || (*ppInSpkg == NULL) ) {
		printf("out of memory!\n");
		goto exit;
	}

	memset(*ppInPkg, 0xaa, (size_t)pkg_size);
	memcpy(*ppInPkg, pSceHdr, sizeof(sce_header_t));
	memcpy(*ppInPkg + 0x20, pMetaHdr, sizeof(META_HDR));
	memcpy(*ppInPkg + 0x280, pInfo0, SIZE_INFO_FILES);	
	memcpy(*ppInPkg + 0x2c0, pInfo1, SIZE_INFO_FILES);	
	memcpy(*ppInPkg + 0x300, pContent, (size_t)ContentSizeCompressed);
	retval = pkg_size;

exit:
	return retval;
}
// func for calculating section hashes
int calculate_hash(u8 *data, u64 len, u8 *digest)
{
	int retval = -1;

	// validate input params
	if ( (data == NULL) || (digest == NULL) )
		goto exit;

	// calculate the hdr HMAC hash
	memset(digest, 0, 0x20);
	sha1_hmac(digest + 0x20, PUP_HMAC_KEY_SIZE, data, (size_t)len, digest);

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
/// func for doing the pkg hashes
int hash_pkg(u8* pInPkg, u64 ContentSizeCompressed)
{
	int retval = -1;

	// validate input params
	if (pInPkg == NULL)
		goto exit;

	// update the hdr hashes
	calculate_hash(pInPkg + 0x280, sizeof(metadata_info_t), pInPkg + 0x80 + 3*sizeof(metadata_section_header_t));
	calculate_hash(pInPkg + 0x2c0, sizeof(metadata_info_t), pInPkg + 0x60 + 3*sizeof(metadata_section_header_t) + 8*0x10);
	calculate_hash(pInPkg + 0x300, ContentSizeCompressed, 
			pInPkg + sizeof(metadata_info_t) + 3*sizeof(metadata_section_header_t) + 16*0x10);
	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
////////////////////////////////////////////////////////////////////////

int sign_pkg(u8* pInPkg)
{
	u8 *r, *s = NULL;
	u8 hash[20] = {0};
	u64 sig_len = 0;
	int retval = -1;

	// validate input params
	if (pInPkg == NULL)
		goto exit;

	sig_len = be64(pInPkg + 0x60);
	r = pInPkg + sig_len;
	s = r + 21;

	// sha1 the hash
	sha1(pInPkg, (size_t)sig_len, hash);
	// ecdsa sign the hash
	#ifdef ECDSA_ORG
	ecdsa_sign_org(hash, r, s);
	#endif

	#ifndef ECDSA_ORG
	sig_len = ecdsa_sign(&ecdsa_ctx.grp, (mpi*)r, (mpi*)s, &ecdsa_ctx.d, hash, (size_t)sig_len, get_random_char, NULL);
	//sig_len = ecdsa_sign(&ecdsa_ctx.grp, (mpi*)r, (mpi*)s, &ecdsa_ctx.d, hash, (size_t)sig_len, get_rand, NULL);	
	#endif
	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
	
}
/**/
/***************************************************************************************************************/



/// UNPACK the content file
int unpack_content(const char *name, u8* pInPkg, u64* pDecSize, u32 MetaOffset)
{
	u8 *tmp = NULL;
	u8 *decompressed = NULL;
	u64 offset = 0;
	u64 size = 0;
	u64 size_real = 0;
	int retval = -1;


	// validate input params
	if ( (name == NULL) || (pInPkg == NULL) || (pDecSize == NULL) )
		goto exit;

	// setup the sizes
	tmp = pInPkg + MetaOffset + 0x80 + 0x30 * 2;
	offset = be64(tmp);
	size = be64(tmp + 8);
	size_real = *pDecSize - 0x80;

	if (be32(tmp + 0x2c) == 0x2)
	{
		// alloc a temp buffer, and decompress the 'content file
		decompressed = (u8*)calloc((size_t)size_real, sizeof(char));
		memset(decompressed, 0xaa, (size_t)size_real);
				
		// decompress the content, and write the file to disk
		size_real = Zlib_UncompressData(pInPkg + offset, (int)size, decompressed, (int)size_real);
		if ( WriteBufferToFile((char*)name, decompressed, (uint32_t)size_real, FALSE, 0, NULL) != STATUS_SUCCESS ) {
			printf("failed to write to file:%s, exiting...\n", name);
			goto exit;		
		}
	} else {		
		// write the 'non-compressed' content file to disk
		if ( WriteBufferToFile((char*)name, (pInPkg + offset), (uint32_t)size, FALSE, 0, NULL) != STATUS_SUCCESS ) {
			printf("failed to write to file:%s, exiting...\n", name);
			goto exit;
		}
	}
	// status success
	retval = STATUS_SUCCESS;

exit:
	// free any alloc'd memory
	if (decompressed != NULL)
		free(decompressed);

	return retval;
}
///////////////////////////////////////////////////////////


// func for unpacking and writing out the 'info' files
int unpack_info(u32 i, char* filename, u8* pInPkg, u32 MetaOffset)
{	
	u64 offset = 0;
	u64 size = 0;
	PKG_FILE_RECORD* pPkgFileRecord = NULL;
	int retval = -1;

	// calculate the 'info' file offset location
	pPkgFileRecord = (PKG_FILE_RECORD*)(pInPkg + sizeof(PKG_HEADER_STRUCT) + MetaOffset + (sizeof(PKG_FILE_RECORD) * i));	
	
	// calculate the offset
	offset = be64((u8*)&pPkgFileRecord->raw_offset);
	size = be64((u8*)&pPkgFileRecord->file_size);

	// verify 'size' in hdr is correct size
	if (size != SIZE_INFO_FILES) {
		printf("weird info size: %08x\n", size);
		goto exit;
	}
	// write out the unpacked 'info' file
	if ( WriteBufferToFile(filename, (pInPkg + offset), (uint32_t)size, FALSE, 0, NULL) != STATUS_SUCCESS ) {
		printf("failed to write to file:%s, exiting...\n", filename);
		goto exit;
	}

	// status success
	retval = STATUS_SUCCESS;
	
exit:
	return retval;
}
//////////////////////////////////////////


// func for unpacking all 3 embedded files
int unpack_pkg(u8* pInPkg, char* dirpath, u64* pDecSize, u32 MetaOffset)
{
	int retval = -1;
	int i = 0;
	char fullpath[MAX_PATH] = {0};
	

	// validate input params
	if ( (pInPkg == NULL) || (dirpath == NULL) || (pDecSize == NULL) )
		goto exit;		

	// for loop to unpack the "info0/info1" files
	for (i = 0; i < (NUM_PKG_EMBEDDED_FILES - 1); i++)
	{
		// create the fullpath of the "dir\filename" for the 'info0' file
		if ( sprintf_s(fullpath, MAX_PATH, "%s\\%s", dirpath, (char*)&g_pszPkgFileNames.names[i+1]) <= 0 )
			goto exit;	

		// unpack the 'info0' file
		if ( unpack_info(i, fullpath, pInPkg, MetaOffset) !=	STATUS_SUCCESS )
			goto exit;		
	}

	// create the fullpath of the "dir\filename" for the 'content' file
	if ( sprintf_s(fullpath, MAX_PATH, "%s\\%s", dirpath, &g_pszPkgFileNames.names[0]) <= 0 )
		goto exit;

	// unpack the 'content' file
	if ( unpack_content(fullpath, pInPkg, pDecSize, MetaOffset) != STATUS_SUCCESS )
		goto exit;

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
/////////////////////////////////////////////////////////

// func to decrypt the pkg file
int decrypt_pkg(u8* pInPkg, u64* pDecSize, u32* pMetaOffset)
{
	u16 keyrev = 0;
	u16 type = 0;
	u32 hdr_len = 0;
	u32 MyMetaOffset = 0;
	u32 num_sections = 0;
	struct keylist *k = NULL;	
	sce_header_t* pSce_Header = NULL;
	metadata_info_t* pMetaInfoHdr = NULL;
	metadata_header_t* pMetaHeader = NULL;
	int retval = -1;


	// validate input params
	if ( (pInPkg == NULL) || (pDecSize == NULL) || (pMetaOffset == NULL) )
		goto exit;
	
	// verify SCE header magic!
	if ( verify_sce_header(pInPkg) != STATUS_SUCCESS ) {
		printf("SCE Header is not valid for this file!, exiting!\n");
		goto exit;
	}
	
	// setup the SCE header
	pSce_Header = (sce_header_t*)pInPkg;
	keyrev   = be16((u8*)&pSce_Header->key_revision);	// key rev
	type     = be16((u8*)&pSce_Header->header_type);	// hdr type
	hdr_len  = (u32)be64((u8*)&pSce_Header->header_len);// hdr len
	*pDecSize = be64((u8*)&pSce_Header->data_len);		// data size

	// check the type from the hdr
	if (type != SCE_HEADER_TYPE_PKG) {
		printf("no .pkg file\n");
		goto exit;
	}
	
	// grab the decrypt keys
	k = keys_get(KEY_PKG);
	if (k == NULL) {
		printf("no key found\n");
		goto exit;
	}

	// decrypt the SCE header
	if (sce_decrypt_header_pkgtool(pInPkg, k) < 0) {
		printf("header decryption failed\n");
		goto exit;
	}

	// decrypt the main data
	if (sce_decrypt_data_pkgtool(pInPkg) < 0) {
		printf("data decryption failed\n");
		goto exit;
	}

	// derive the offsets/sections
	MyMetaOffset = be32((u8*)&pSce_Header->metadata_offset);
	pMetaInfoHdr = (metadata_info_t*)(pInPkg + + sizeof(sce_header_t) + MyMetaOffset);	
	pMetaHeader = (metadata_header_t*)(pInPkg + sizeof(sce_header_t) + sizeof(metadata_info_t) + MyMetaOffset);
	num_sections  = be32((u8*)&pMetaHeader->section_count);
	if (num_sections != 3) {
		printf("invalid section count: %d\n", num_sections);
		goto exit;
	}
	// if debug mode enabled, write the metadata file!
	if (b_DebugModeEnabled == TRUE) {		
		if ( WriteBufferToFile("metadata_decrypted", pInPkg, hdr_len, FALSE, 0, NULL) != STATUS_SUCCESS ) {
			printf("failed to write to file:\"metadata_decrypted\", exiting...\n");
			goto exit;
		}
	}

	// status success
	retval = STATUS_SUCCESS;
	*pMetaOffset = MyMetaOffset;

exit:
	return retval;
}
/**/
/************************************************************************************************************/