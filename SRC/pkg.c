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
#include "keys.h"
#include "bignum.h"
#include "ecdsa.h"








/////////////////////////////////////
// define internal/external globals
//
extern PKG_FILE_NAMES g_pszPkgFileNames;
extern uint8_t b_DebugModeEnabled;
extern uint8_t b_DefaultKeyListOverride;
extern int32_t g_bZlibCompressLevel;
extern uint8_t b_OverrideFileSize;
extern ecdsa_context ecdsa_ctx;


//
/////////////////////////////////////




// func. for reading in the content file
int get_content(char* filename, u8** ppContent, u64* pContent_size_original, u64* pContent_size_final, u8* pDoCompress, u64 OverrideFileSize)
{
	u8* pBase = NULL;
	u8* pNewBase = NULL;
	uint32_t dwBytesRead = 0;
	uint32_t MyOverrideFileSize = 0;
	int retval = -1;


	// validate input params
	if ( (filename == NULL) || (ppContent == NULL) || (pContent_size_original == NULL) || (pContent_size_final == NULL) )
		goto exit;

	// read the "content" file into a buffer (alloc buffer for the read)
	if ( ReadFileToBuffer(filename, &pBase, 0x00, &dwBytesRead, TRUE) != STATUS_SUCCESS) {
		printf("failed to read in file:%s, exiting...\n", filename);
		goto exit;
	}
	// if we are setting a 'new' CONTENT file size, then re-alloc the original block
	if ( b_OverrideFileSize == TRUE)	
	{
		// if the 'OverrideFileSize' is valid, then alloc a new buffer,
		// copy over the original 'content' data, and adjust ptrs, sizes
		// accordingly
		MyOverrideFileSize = (u32)OverrideFileSize;
		if (MyOverrideFileSize > dwBytesRead)
		{
			// re-alloc our buffer to the new size
			pNewBase = (u8*)calloc((size_t)MyOverrideFileSize, sizeof(char));
			if (pNewBase == NULL) {
				printf("Error:  memory allocation failed, exiting!!\n");
				goto exit;
			}

			// copy our original file over to the new buffer,			
			memcpy_s(pNewBase, (rsize_t)MyOverrideFileSize, pBase, (rsize_t)dwBytesRead);					
			if (pBase != NULL)
				free(pBase);			
			
			// if 'debug' mode, display the size adjustment msg
			if (b_DebugModeEnabled)
				printf("RE-SIZED PKG 'content' file, prev size:0x%x, new size:0x%x\n", dwBytesRead, MyOverrideFileSize);

			// re-assign the ptrs/values
			pBase = (u8*)pNewBase;				
			dwBytesRead = (uint32_t)MyOverrideFileSize;										
		}
		// otherwise, if our 'override' file size is smaller than our current size,
		// we have a 'fatal' error, and must exit out
		else if (MyOverrideFileSize < dwBytesRead) {
			printf("!!WARNING!! RE-SIZE ignored, modifed 'content' file size: 0x%x, is LARGER than original size: 0x%x.....\n", dwBytesRead, MyOverrideFileSize);			
		}
		else if (MyOverrideFileSize == dwBytesRead) {
			printf("Original 'Content' size: 0x%x, is already equal to 'override' file size, re-size not required...\n", MyOverrideFileSize);
		}

	}// end IF (b_OverrideFileSize)....
	
	// calculate the size needed for compress buffer
	*pContent_size_original = (u64)dwBytesRead;
	*pContent_size_final = Zlib_GetMaxCompressedLen((int)*pContent_size_original);	

	// alloc memory for the compression output
	*ppContent = (u8*)calloc((size_t)*pContent_size_final, sizeof(char));
	if (*ppContent == NULL) {
		printf("out of memory\n");
		goto exit;
	}

	// do the Zlib compression
	*pContent_size_final = Zlib_CompressData(pBase, (int)*pContent_size_original, *ppContent, (int)*pContent_size_final, g_bZlibCompressLevel);
	if (*pContent_size_final <= 0) {
		printf("Error: Zlib compress returned %d\n", *pContent_size_final);
		goto exit;
	}
	// if the data did not compress, then do NOT use
	// the compressed data, instead, set 'metadata' section as
	// NOT compressed
	if (*pContent_size_final >= *pContent_size_original)
	{
		if (b_DebugModeEnabled == TRUE)
			printf("ZlibCompress NOT applicable, data already compressed....PKG data will be NORMAL\n");

		*pContent_size_final = *pContent_size_original;		
		// free the buffer from the zlib compressed data
		if (*ppContent != NULL)
			free(*ppContent);

		*pDoCompress = FALSE;
		*ppContent = pBase;				
	}
	// data DID compress, so return the ZLIB compressed data
	else
	{
		// resize the memory to the final size
		*ppContent = (u8*)realloc(*ppContent, (size_t)*pContent_size_final);
		if (*ppContent == NULL) {
			printf("out of memory\n");
			goto exit;
		}
		// return status as COMPRESSED
		*pDoCompress = TRUE;

		// free the org. alloc'd memory
		if (pBase != NULL)
			free(pBase);
	}	

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}

// func for building the SCE hdr
int build_sce_hdr(sce_header_t* pSceHdr, u64 ContentSizeOriginal)
{
	sce_header_t* pSce_Header = NULL;
	int retval = -1;

	// validate input params
	if (pSceHdr == NULL)
		goto exit;

	// populate the SCE-HDR fields for PKG build
	pSce_Header = (sce_header_t*)pSceHdr;
	memset(pSceHdr, 0, sizeof(sce_header_t));	
	wbe32((u8*)&pSce_Header->magic, SCE_HEADER_MAGIC);			// magic
	wbe32((u8*)&pSce_Header->version, SCE_HEADER_VERSION_2);	// version
	wbe16((u8*)&pSce_Header->key_revision, KEY_REVISION_0);		// key revision
	wbe16((u8*)&pSce_Header->header_type, SCE_HEADER_TYPE_PKG);	// SCE header type; pkg
	wbe32((u8*)&pSce_Header->metadata_offset, 0);				// meta offset
	wbe64((u8*)&pSce_Header->header_len, sizeof(sce_header_t) + sizeof(META_HDR)); // header len
	wbe64((u8*)&pSce_Header->data_len, 0x80 + ContentSizeOriginal);	
	
	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
// func for building the META_HDR
int build_meta_hdr(META_HDR* pMetaHdr, u64 ContentSizeFinal, u8 bDoCompress)
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
	wbe64((u8*)&pMetaDataHeader->sig_input_length, sizeof(sce_header_t) + sizeof(META_HDR) - sizeof(metadata_section_header_t) );
	wbe32((u8*)&pMetaDataHeader->unknown_0, 1);
	wbe32((u8*)&pMetaDataHeader->section_count, 3);		// number of encrypted headers
	wbe32((u8*)&pMetaDataHeader->key_count, (4 * 5));	// number of keys/hashes required ++++++
	ptr += sizeof(metadata_header_t);

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
	wbe64((u8*)&pMetaSectionHeader->data_size, ContentSizeFinal);	// size
	wbe32((u8*)&pMetaSectionHeader->type, METADATA_SECTION_TYPE_UNK_3); // unknown
	wbe32((u8*)&pMetaSectionHeader->index, 3);							// index
	wbe32((u8*)&pMetaSectionHeader->hashed, METADATA_SECTION_HASHED);	// hashed
	wbe32((u8*)&pMetaSectionHeader->sha1_index, 12);					// sha index
	wbe32((u8*)&pMetaSectionHeader->encrypted, METADATA_SECTION_ENCRYPTED);// encrypted
	wbe32((u8*)&pMetaSectionHeader->key_index, 18);						// key index
	wbe32((u8*)&pMetaSectionHeader->iv_index, 19);						// iv index
	if (bDoCompress == TRUE)
		wbe32((u8*)&pMetaSectionHeader->compressed, METADATA_SECTION_COMPRESSED);// compressed
	else
		wbe32((u8*)&pMetaSectionHeader->compressed, METADATA_SECTION_NOT_COMPRESSED);// compressed
	ptr += sizeof(metadata_section_header_t);

	// add keys/ivs and hmac keys
	get_rand(ptr, 0x13c);
	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
// func for fixing the 'info' hdr
int fix_info_hdr(u8* pInfo0, u8* pInfo1, u64 ContentSizeOriginal, u64 ContentSizeFinal)
{	
	INFO_FILE_RECORD* pInfoFileRecord = NULL;
	int retval = -1;

	// validate input params
	if ( (pInfo0 == NULL) || (pInfo1 == NULL) )
		goto exit;

	// setup the info header
	pInfoFileRecord = (INFO_FILE_RECORD*)pInfo0;
	wbe64(pInfo0 + 0x18, ContentSizeOriginal);	// external file size
	wbe64(pInfo0 + 0x20, ContentSizeFinal);		// internal (pkg'd) file size
	wbe64(pInfo1 + 0x18, ContentSizeOriginal);	// external file size
	wbe64(pInfo1 + 0x20, 0x01);

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
// main function for 'building' the output PKG file
u64 build_pkg(sce_header_t* pSceHdr, META_HDR* pMetaHdr, u8** ppInPkg, u8** ppInSpkg, u8* pContent, u8* pInfo0, u8* pInfo1, u64 ContentSizeFinal)
{
	static u64 pkg_size = 0;
	u64 retval = STATUS_SUCCESS;


	// validate input params
	if ( (pSceHdr == NULL) || (pMetaHdr == NULL) || (ppInPkg == NULL) || (ppInSpkg == NULL) || (pContent == NULL) || (pInfo0 == NULL) || (pInfo1 == NULL) )
		goto exit;

	// setup the initial sizes
	pkg_size = sizeof(sce_header_t) + sizeof(META_HDR) + 0x80;
	pkg_size += ContentSizeFinal;

	*ppInPkg = (u8*)calloc((size_t)pkg_size, sizeof(char));
	*ppInSpkg = (u8*)calloc((size_t)pkg_size, sizeof(char));
	if ( (*ppInPkg == NULL) || (*ppInSpkg == NULL) ) {
		printf("out of memory!\n");
		goto exit;
	}

	// setup the final 'PKG' buffer
	memset(*ppInPkg, 0xaa, (size_t)pkg_size);
	memcpy(*ppInPkg, pSceHdr, sizeof(sce_header_t));
	memcpy(*ppInPkg + 0x20, pMetaHdr, sizeof(META_HDR));
	memcpy(*ppInPkg + 0x280, pInfo0, SIZE_INFO_FILES);	
	memcpy(*ppInPkg + 0x2c0, pInfo1, SIZE_INFO_FILES);	
	memcpy(*ppInPkg + 0x300, pContent, (size_t)ContentSizeFinal);
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
	sha1_hmac(digest + 0x20, HMAC_KEY_SIZE, data, (size_t)len, digest);

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
/// func for doing the pkg hashes
int hash_pkg(u8* pInPkg, u64 ContentSizeFinal)
{
	int retval = -1;

	// validate input params
	if (pInPkg == NULL)
		goto exit;

	// update the hdr hashes
	calculate_hash(pInPkg + 0x280, SIZE_INFO_FILES, pInPkg + 0x80 + 3*sizeof(metadata_section_header_t));
	calculate_hash(pInPkg + 0x2c0, SIZE_INFO_FILES, pInPkg + 0x60 + 3*sizeof(metadata_section_header_t) + 8*0x10);
	calculate_hash(pInPkg + 0x300, ContentSizeFinal, pInPkg + SIZE_INFO_FILES + 3*sizeof(metadata_section_header_t) + 16*0x10);

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
////////////////////////////////////////////////////////////////////////


// func. to ECDSA sign the PKG sections
int sign_pkg(u8* pInPkg)
{
	u8 *r, *s = NULL;
	u8 hash[20] = {0};
	u64 sig_len = 0;
	mpi r1;
	mpi s1;
	int retval = -1;

	// validate input params
	if (pInPkg == NULL)
		goto exit;

	// init the mpi
	mpi_init(&r1);
	mpi_init(&s1);

	// setup the 'signature len'
	sig_len = be64(pInPkg + 0x60);
	r = pInPkg + sig_len;
	s = r + 21;

	// sha1 the hash
	sha1(pInPkg, (size_t)sig_len, hash);

	// ecdsa sign the hash
	if ( ecdsa_sign(&ecdsa_ctx.grp, (mpi*)&r1, (mpi*)&s1, &ecdsa_ctx.d, hash, ECDSA_KEYSIZE_PRIV, get_random_char, NULL) == STATUS_SUCCESS ) {		
		mpi_write_binary(&r1, (unsigned char*)r, ECDSA_KEYSIZE_PRIV);
		mpi_write_binary(&s1, (unsigned char*)s, ECDSA_KEYSIZE_PRIV);

		// status success
		retval = STATUS_SUCCESS;
	}

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
int decrypt_pkg(u8* pInPkg, u64* pDecSize, u32* pMetaOffset, char* pKeyName)
{
	u16 keyrev = 0;
	u16 type = 0;
	u32 hdr_len = 0;
	u32 MyMetaOffset = 0;
	u32 num_sections = 0;
	struct keylist *pMyKeyList = NULL;	
	struct key MyKey = {0};
	sce_header_t* pSce_Header = NULL;
	metadata_info_t* pMetaInfoHdr = NULL;
	metadata_header_t* pMetaHeader = NULL;
	int retval = -1;


	// validate input params
	if ( (pInPkg == NULL) || (pDecSize == NULL) || (pMetaOffset == NULL) )
		goto exit;
	
	// verify SCE header magic!
	if ( verify_sce_header(pInPkg, SIG_SCE_PKG) != STATUS_SUCCESS ) {
		printf("SCE Header is not a valid PKG header!, exiting!\n");
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
		printf("not a valid PKG file\n");
		goto exit;
	}
	
	/////////////////	KEYS LOADING	//////////////////////////////////////////
	//
	// If we are OVERRIDING the default key from the 'keys' file, then
	// attempt to find it, first from the new 'keys' file, and if not, 
	// manually by the exact 'keyname' specified
	if ( b_DefaultKeyListOverride == TRUE )
	{
		if ( load_singlekey_by_name(pKeyName, &pMyKeyList) != STATUS_SUCCESS )
		{
			// failed to find the 'override' key in 'KEYS' file, 
			// so try 'old-style' keys
			printf("Error:  Failed to find override PKG key(%s) in new \"KEYS\" file, trying old style keys...\n", pKeyName);	
			if ( key_get_old(KEY_PKG, pKeyName, &MyKey) == STATUS_SUCCESS ) 
			{
				// now populate the "keylist*" with the key we just found
				if ( load_keylist_from_key(&pMyKeyList, &MyKey) != STATUS_SUCCESS )
				{
					printf("Error: Unexpected failure loading single 'keylist' from 'key' structure....exiting....\n");
					goto exit;
				}
			}
			else {
				printf("key_get() for PKG key failed");
				goto exit;
			}	
		}
	} // end if (KeyListOverride....)
	else
	{
		// try to get keys via the new 'keys' format first, if not,
		// failover to the old keys style	
		if ( load_all_type_keys(&pMyKeyList, KEYTYPE_PKG) != STATUS_SUCCESS )
		{
			printf("Failed to find keys in new \"KEYS\" file, trying old keys files....\n");
			// grab the decrypt keys
			pMyKeyList = keys_get(KEY_SPKG);
			if (pMyKeyList->n == 0) {
				printf("no key found\n");
				goto exit;
			}
		}	
	}
	//
	////////////////////////////////////////////////////////////////////////////////

	// decrypt the SCE headerpInPkg
	if (sce_decrypt_header_pkgtool(pInPkg, pMyKeyList) != STATUS_SUCCESS) {
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

// main function to do the pkg decrypt/unpackage
int do_pkg_create(char* pInPath, char* pOutPath, char* pType, char* pKeyName, u64 OverrideFileSize)
{	
	u8* pMyPkg = NULL;
	u8* pMySpkg = NULL;
	u8* pMyContent = NULL;
	u8* pMyInfo0 = NULL;
	u8* pMyInfo1 = NULL;	
	char szFullpath[MAX_PATH] = {0};
	sce_header_t sce_hdr = {0};
	META_HDR meta_hdr = {0};
	u64 content_size_original = 0;
	u64 content_size_final = 0;
	u32 dwBytesRead = 0;
	u64 pkg_size = 0;
	struct keylist* pMyKeyList = NULL;
	struct key MyKey = {0};	
	u8 bDoCompress = FALSE;
	int retval = -1;


	// validate input params
	if ( (pInPath == NULL) || (pOutPath == NULL) || (pType == NULL) )
		goto exit;

	// build the full path for the "info0" file
	if ( sprintf_s(szFullpath, MAX_PATH, "%s\\%s", pInPath, (char*)&g_pszPkgFileNames.names[1]) <= 0 ) {
		printf("unexpected failure, try again...\n");
		goto exit;
	}

	// read in the "info0" file, and assure we read in the right size (alloc a buffer)
	if ( ReadFileToBuffer(szFullpath, (uint8_t**)&pMyInfo0, SIZE_INFO_FILES, &dwBytesRead, TRUE) != STATUS_SUCCESS) {
		printf("failed to read in file:%s, exiting...\n", szFullpath);
		goto exit;
	}
	if (dwBytesRead != SIZE_INFO_FILES) {
		printf("Error! file:%s is not correct size, exiting...\n", szFullpath);
		goto exit;
	}
	// build the full path for the "info0" file
	if ( sprintf_s(szFullpath, MAX_PATH, "%s\\%s", pInPath, &g_pszPkgFileNames.names[2]) <= 0 )
		goto exit;

	// read in the "info1" file (alloc a buffer)
	if ( ReadFileToBuffer(szFullpath, (uint8_t**)&pMyInfo1, SIZE_INFO_FILES, &dwBytesRead, TRUE) != STATUS_SUCCESS) {
		printf("failed to read in file:%s, exiting...\n", szFullpath);
		goto exit;
	}
	if (dwBytesRead != SIZE_INFO_FILES) {
		printf("Error! file:%s is not correct size, exiting...\n", szFullpath);
		goto exit;
	}

	// build the full path for the "info0" file
	if ( sprintf_s(szFullpath, MAX_PATH, "%s\\%s", pInPath, &g_pszPkgFileNames.names[0]) <= 0 )
		goto exit;

	// read in the 'content' file
	if (get_content(szFullpath, &pMyContent, &content_size_original, &content_size_final, &bDoCompress, OverrideFileSize) != STATUS_SUCCESS)
		goto exit;

	// build the SCE & META headers
	if ( build_sce_hdr(&sce_hdr, content_size_original) != STATUS_SUCCESS )
		goto exit;
	
	
	/////////////////	KEYS LOADING	//////////////////////////////////////////
	//
	// If we are OVERRIDING the default key from the 'keys' file, then
	// attempt to find it, first from the new 'keys' file, and if not, 
	// manually by the exact 'keyname' specified
	if ( b_DefaultKeyListOverride == TRUE )
	{
		if ( load_singlekey_by_name(pKeyName, &pMyKeyList) != STATUS_SUCCESS )
		{
			// failed to find the 'override' key in 'KEYS' file, 
			// so try 'old-style' keys
			printf("Error:  Failed to find override PKG key(%s) in new \"KEYS\" file, trying old style keys...\n", pKeyName);	
			if ( key_get_old(KEY_PKG, pKeyName, &MyKey) == STATUS_SUCCESS ) 
			{
				if ( load_keylist_from_key(&pMyKeyList, &MyKey) != STATUS_SUCCESS )
				{
					printf("Error: Unexpected failure loading single 'keylist' from 'key' structure....exiting....\n");
					goto exit;
				}
			}
			else {
				printf("key_get() for PKG key failed");
				goto exit;
			}	
		}
	} // end if (KeyListOverride....)
	else
	{
		// try to get keys via the new 'keys' format first, if not,
		// failover to the old keys style	
		if ( key_get_new(sce_hdr.key_revision, sce_hdr.header_type, &MyKey) != STATUS_SUCCESS )
		{
			printf("Failed to find PKG keys in new \"KEYS\" file, exiting!\n");
			goto exit;			
		}	
	}	
	//
	////////////////////////////////////////////////////////////////////////////////


	// build the 'metadata' headers
	if ( build_meta_hdr(&meta_hdr, content_size_final, bDoCompress) != STATUS_SUCCESS )
		goto exit;

	// fix the 'info' headers
	if ( fix_info_hdr(pMyInfo0, pMyInfo1, content_size_original, content_size_final) != STATUS_SUCCESS )
		goto exit;

	// build the pkg
	pkg_size = build_pkg(&sce_hdr, &meta_hdr, &pMyPkg, &pMySpkg, pMyContent, pMyInfo0, pMyInfo1, content_size_final); // Create PKG
	if (pkg_size == 0) 
		goto exit;
		
	// hash/sha1 the pkg data
	if ( hash_pkg(pMyPkg, content_size_final) != STATUS_SUCCESS )
		goto exit;

	// ECDSA sign the pkg
	if ( sign_pkg(pMyPkg) != STATUS_SUCCESS )
		goto exit;

	// make a copy for the spkg
	memcpy(pMySpkg, pMyPkg, (size_t)pkg_size); // Copy buffer
		
	// encrypt the data
	if ( sce_encrypt_data_pkgtool(pMyPkg) != STATUS_SUCCESS )
		goto exit;

	// encrypt the hdrs
	if (sce_encrypt_header_pkgtool(pMyPkg, &MyKey) != STATUS_SUCCESS )
		goto exit;

	// write out the final .pkg file
	if (WriteBufferToFile(pOutPath, pMyPkg, (uint32_t)pkg_size, FALSE, 0, NULL) != STATUS_SUCCESS) {
		printf("failed to write to file:%s, exiting...\n", pOutPath);
		goto exit;
	}

	// if we are type "SPKG", then also gen the spkg.1 files
	if ( _stricmp(pType, "SPKG") == 0 )
	{
		// validate input 'spkg' is good
		if (pMySpkg == NULL)
			goto exit;

		/////////////////	KEYS LOADING	//////////////////////////////////////////
		//
		// If we are OVERRIDING the default key from the 'keys' file, then
		// attempt to find it, first from the new 'keys' file, and if not, 
		// manually by the exact 'keyname' specified
		if ( b_DefaultKeyListOverride == TRUE )
		{
			if ( load_singlekey_by_name(pKeyName, &pMyKeyList) != STATUS_SUCCESS )
			{
				// failed to find the 'override' key in 'KEYS' file, 
				// so try 'old-style' keys
				printf("Error:  Failed to find override PKG key(%s) in new \"KEYS\" file, trying old style keys...\n", pKeyName);	
				if ( key_get_old(KEY_PKG, pKeyName, &MyKey) == STATUS_SUCCESS ) 
				{
					if ( load_keylist_from_key(&pMyKeyList, &MyKey) != STATUS_SUCCESS )
					{
						printf("Error: Unexpected failure loading single 'keylist' from 'key' structure....exiting....\n");
						goto exit;
					}
				}
				else {
					printf("key_get() for PKG key failed");
					goto exit;
				}	
			}
		} // end if (KeyListOverride....)
		else
		{
			// try to get keys via the new 'keys' format first, if not,
			// exit out
			if ( load_singlekey_by_name("SPKG-REV000", &pMyKeyList) != STATUS_SUCCESS )
			{
				printf("Failed to find SPKG key in new \"KEYS\" file, exiting!\n");
				goto exit;			
			}					
		}				

		// encrypt the data
 		if ( sce_encrypt_data_pkgtool(pMySpkg) != STATUS_SUCCESS ) 
			goto exit;

		// encrypt the header
		if ( sce_encrypt_header_pkgtool(pMySpkg, &pMyKeyList->keys[0]) != STATUS_SUCCESS )
			goto exit;					

		// cat on the "spkg_hdr.1" filename
		strcat_s((char*)pOutPath, MAX_PATH, SPKG_HDR_NAME);			

		// write out the final *.spkg_hdr.1 file
		if (WriteBufferToFile(pOutPath, pMySpkg, (uint32_t)sizeof(SPKG_STRUCT), FALSE, 0, NULL) != STATUS_SUCCESS) {
			printf("failed to write to file:%s, exiting...\n", pOutPath);
			goto exit;				
		}
	}	////////////////  DONE SPKG //////////////////////

	// status success
	retval = STATUS_SUCCESS;

exit:
	// free up all used memory
	if (pMyInfo0 != NULL)
		free(pMyInfo0);
	
	// free the alloc'd memory
	if (pMyInfo1 != NULL)
		free(pMyInfo1);

	// free the alloc'd memory
	if (pMyContent != NULL)
		free(pMyContent);

	// free the alloc'd memory
	if (pMyPkg != NULL)
		free(pMyPkg);

	// free the alloc'd memory
	if (pMySpkg != NULL)
		free(pMySpkg);

	// return the status
	return retval;
}
/**/
/**********************************************************************************************************/


// main function to do the pkg decrypt/unpackage
int do_pkg_decrypt(char* pInPath, char* pOutPath, char* pKeyName)
{
	u8* pMyPkg = NULL;
	u64 dec_size = 0;
	u32 MetaOffset = 0;
	u32 dwBytesRead = 0;
	int retval = -1;



	// validate input params
	if ( (pInPath == NULL) || (pOutPath == NULL) )
		goto exit;	
	
	// create the target directory, if CreateDir
	// failed, see if the dir already exists.  If so,
	// we can continue...
	if ( CreateDirectory(pOutPath, NULL) == 0 ) {
		if ( GetLastError() != ERROR_ALREADY_EXISTS ) {
			printf("failed to create output directory:%s, exiting...\n", pOutPath);
			goto exit;
		}
	}

	// read in the "input" file (alloc a buffer)
	if ( ReadFileToBuffer(pInPath, (uint8_t**)&pMyPkg, FALSE, &dwBytesRead, TRUE) != STATUS_SUCCESS) {
		printf("failed to read in file:%s, exiting...\n", pInPath);
		goto exit;
	}	

	// decrypt the full pkg
	if ( decrypt_pkg(pMyPkg, &dec_size, &MetaOffset, pKeyName) != STATUS_SUCCESS ) {
		printf("failed to decrypt package:%s, exiting...\n", pInPath);
		goto exit;		
	}

	// create the full path to the output files			
	if ( unpack_pkg(pMyPkg, pOutPath, &dec_size, MetaOffset) != STATUS_SUCCESS ) {
		printf("failed to unpack package:%s, exiting....\n", pOutPath);
		goto exit;	
	}
	// status success
	retval = STATUS_SUCCESS;

exit:
	// free the alloc'd memory
	if (pMyPkg != NULL)
		free(pMyPkg);

	return retval;
}
/**/
/**********************************************************************************************************/