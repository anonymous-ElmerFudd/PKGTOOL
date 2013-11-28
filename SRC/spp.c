// Copyright 2010       anonymous
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt




#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include "spp.h"
#include "tool_structures.h"
#include "file_functions.h"
#include "sha1.h"
#include "tools.h"
#include "types.h"
#include "sce.h"
#include "keys.h"





/////////////////////////////////////
// define internal/external globals
//

extern uint8_t b_DebugModeEnabled;
extern uint8_t b_DefaultKeyListOverride;
extern ecdsa_context ecdsa_ctx;

//
/////////////////////////////////////





// func for building the SPP_META_HDR
int build_spp_meta_hdr(SPP_META_HDR* pMetaHdr, u64 ContentSizeOriginal)
{
	u8 *ptr = NULL;
	metadata_info_t* pMetaDataInfoHeader = NULL;
	metadata_header_t* pMetaDataHeader = NULL;
	metadata_section_header_t* pMetaSectionHeader = NULL;
	int retval = -1;
	


	// validate input params
	if (pMetaHdr == NULL)
		goto exit;

	memset(pMetaHdr, 0, sizeof(SPP_META_HDR));
	ptr = (u8*)pMetaHdr;
	pMetaDataInfoHeader = (metadata_info_t*)ptr;

	// setup the "metadata" random generated keys
	get_rand((u8*)&pMetaDataInfoHeader->key, sizeof(pMetaDataInfoHeader->key));
	get_rand((u8*)&pMetaDataInfoHeader->iv, sizeof(pMetaDataInfoHeader->iv));
	ptr += sizeof(metadata_info_t);

	// area covered by the signature
	pMetaDataHeader = (metadata_header_t*)ptr;
	wbe64((u8*)&pMetaDataHeader->sig_input_length, sizeof(sce_header_t) + sizeof(SPP_META_HDR) - sizeof(metadata_section_header_t ));
	wbe32((u8*)&pMetaDataHeader->unknown_0, 1);
	wbe32((u8*)&pMetaDataHeader->section_count, 2);		// number of encrypted headers
	wbe32((u8*)&pMetaDataHeader->key_count, (2 * 8));	// number of keys/hashes required ++++++
	ptr += sizeof(metadata_header_t);					// (size 0x20)

	// first info header
	pMetaSectionHeader = (metadata_section_header_t*)ptr;
	wbe64((u8*)&pMetaSectionHeader->data_offset, 0x200);				// offset //SIZE_SPP_HDR
	wbe64((u8*)&pMetaSectionHeader->data_size, 0x20);					// size
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
	wbe64((u8*)&pMetaSectionHeader->data_offset, 0x220);				// offset
	wbe64((u8*)&pMetaSectionHeader->data_size, ContentSizeOriginal - 0x20);// size
	wbe32((u8*)&pMetaSectionHeader->type, METADATA_SECTION_TYPE_PHDR); 	// type
	wbe32((u8*)&pMetaSectionHeader->index, 2);							// index
	wbe32((u8*)&pMetaSectionHeader->hashed, METADATA_SECTION_HASHED);	// hashed
	wbe32((u8*)&pMetaSectionHeader->sha1_index, 8);						// sha index
	wbe32((u8*)&pMetaSectionHeader->encrypted, METADATA_SECTION_ENCRYPTED);// no encryption
	wbe32((u8*)&pMetaSectionHeader->key_index, 0);						// key index
	wbe32((u8*)&pMetaSectionHeader->iv_index, 1);						// iv index
	wbe32((u8*)&pMetaSectionHeader->compressed, METADATA_SECTION_NOT_COMPRESSED);// no compression
	ptr += sizeof(metadata_section_header_t);	

	// add keys/ivs and hmac keys
	get_rand(ptr, 2 * 8 * 0x10);
	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}

// main function for 'building' the output SPP file
u64 build_spp(sce_header_t* pSceHdr, SPP_META_HDR* pMetaHdr, u8** ppInSpp, u8* pContent, u64 ContentSizeOriginal)
{
	static u64 spp_size = 0;
	u64 retval = STATUS_SUCCESS;


	// validate input params
	if ( (pSceHdr == NULL) || (pMetaHdr == NULL) || (ppInSpp == NULL) || (pContent == NULL) )
		goto exit;

	// setup the initial sizes
	spp_size = sizeof(sce_header_t) + sizeof(SPP_META_HDR);
	spp_size += ContentSizeOriginal;

	*ppInSpp = (u8*)calloc((size_t)spp_size, sizeof(char));	
	if (*ppInSpp == NULL) {
		printf("out of memory!\n");
		goto exit;
	}

	// setup the final 'SPP' buffer
	memset(*ppInSpp, 0xaa, (size_t)spp_size);
	memcpy(*ppInSpp, pSceHdr, sizeof(sce_header_t));
	memcpy(*ppInSpp + 0x20, pMetaHdr, sizeof(SPP_META_HDR));	
	memcpy(*ppInSpp + 0x200, pContent, (size_t)ContentSizeOriginal);
	retval = spp_size;

exit:
	return retval;
}

// func for building the SCE hdr (for SPP)
int build_spp_sce_hdr(sce_header_t* pSceHdr, u64 ContentSizeOriginal)
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
	wbe16((u8*)&pSce_Header->header_type, SCE_HEADER_TYPE_SPP);	// SCE header type; pkg
	wbe32((u8*)&pSce_Header->metadata_offset, 0);				// meta offset
	wbe64((u8*)&pSce_Header->header_len, sizeof(sce_header_t) + sizeof(SPP_META_HDR)); // header len
	wbe64((u8*)&pSce_Header->data_len, ContentSizeOriginal);	
	
	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}

// func for calculating section hashes
int calculate_spp_hash(u8 *data, u64 len, u8 *digest)
{
	int retval = -1;

	// validate input params
	if ( (data == NULL) || (digest == NULL) )
		goto exit;

	// calculate the hdr HMAC hash
	memset(digest, 0, 0x20);
	sha1_hmac(digest + 0x20, SPP_HMAC_KEY_SIZE, data, (size_t)len, digest);

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}

/// func for doing the spp hashes
int hash_spp(u8* pInSpp, u64 ContentSizeOriginal)
{
	int retval = -1;

	// validate input params
	if (pInSpp == NULL)
		goto exit;

	// update the hdr hashes
	calculate_spp_hash(pInSpp + 0x200, SPP_HMAC_KEY_SIZE, pInSpp + 0x80 + 2*sizeof(metadata_section_header_t));	
	calculate_spp_hash(pInSpp + 0x220, ContentSizeOriginal - 0x20, pInSpp + 0x80 + 2*sizeof(metadata_section_header_t ) + 8*0x10);

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
////////////////////////////////////////////////////////////////////////


// func. to ECDSA sign the SPP sections
int sign_spp(u8* pInSpp)
{
	u8 *r, *s = NULL;
	u8 hash[20] = {0};
	u64 sig_len = 0;
	mpi r1;
	mpi s1;
	int retval = -1;

	// validate input params
	if (pInSpp == NULL)
		goto exit;

	// init the mpi
	mpi_init(&r1);
	mpi_init(&s1);

	// setup the 'signature len'
	sig_len = be64(pInSpp + 0x60);
	r = pInSpp + sig_len;
	s = r + 21;

	// sha1 the hash
	sha1(pInSpp, (size_t)sig_len, hash);

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



/**********************************************/
// func. for decrypting the spp file
int decrypt_spp(u8* pInSpp, u64* pDecSize, char* pKeyName)
{
	u16 keyrev = 0;
	u16 type = 0;	
	struct keylist *pMyKeyList = NULL;
	struct key MyKey = {0};
	sce_header_t* pSceHdr = NULL;
	static u32 meta_offset;
	static u32 n_sections;
	u32 hdr_len;
	int retval = -1;


	// validate input params
	if ( (pInSpp == NULL) || (pDecSize == NULL) )
		goto exit;

	// assign sce hdr to start of buffer
	pSceHdr = (sce_header_t*)pInSpp;	

	// verify SCE header magic!
	if ( verify_sce_header((u8*)pSceHdr) != STATUS_SUCCESS ) {
		printf("SCE Header is not valid for this file!, exiting!\n");
		goto exit;
	}

	// derive the hdr offsets
	keyrev    = be16((u8*)&pSceHdr->key_revision);		// key-revision
	type     = be16((u8*)&pSceHdr->header_type);		// hdr type
	hdr_len  = (u32)be64((u8*)&pSceHdr->header_len);	// hdr len
	*pDecSize = be64((u8*)&pSceHdr->data_len);			// data len

	// check the hdr type
	if (type != SCE_HEADER_TYPE_SPP) {
		printf("not a valid PKG/SPKG file\n");
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
			printf("Error:  Failed to find override SPP key(%s) in new \"KEYS\" file, trying old style keys...\n", pKeyName);	
			if ( key_get_old(KEY_SPP, pKeyName, &MyKey) == STATUS_SUCCESS ) 
			{
				// now populate the "keylist*" with the key we just found
				if ( load_keylist_from_key(&pMyKeyList, &MyKey) != STATUS_SUCCESS )
				{
					printf("Error: Unexpected failure loading single 'keylist' from 'key' structure....exiting....\n");
					goto exit;
				}
			}
			else {
				printf("key_get() for SPKG key failed");
				goto exit;
			}	
		}
	} // end if (KeyListOverride....)
	else
	{
		// try to get keys via the new 'keys' format first, if not,
		// failover to the old keys style	
		if ( load_all_type_keys(&pMyKeyList, KEYTYPE_SPP) != STATUS_SUCCESS )
		{
			printf("Failed to find SPP keys in new \"KEYS\" file, trying old keys files....\n");
			// grab the decrypt keys
			pMyKeyList = keys_get(KEY_SPP);
			if (pMyKeyList->n == 0) {
				printf("no key found\n");
				goto exit;
			}
		}	
	}
	//
	////////////////////////////////////////////////////////////////////////////////
			
	// go and decrypt the SPKG hdr
	if ( sce_decrypt_header_pkgtool(pInSpp, pMyKeyList) != STATUS_SUCCESS ) {
		printf("header decryption failed\n");
		goto exit;
	}	
	
	// decrypt the main data
	if (sce_decrypt_data_pkgtool(pInSpp) < 0) {
		printf("data decryption failed\n");
		goto exit;
	}		

	// status success
	retval = STATUS_SUCCESS;

exit:
	// free any alloc'd memory
	if (pMyKeyList != NULL)
		free(pMyKeyList);

	// if we failed, then return "0"
	if (retval != STATUS_SUCCESS)
		*pDecSize = 0;

	return retval;
}
/**/
/************************************************************************************************************/


// main function to do the spkg decrypt/unpackage
int do_spp_decrypt(char* pInPath, char* pOutPath, char* pKeyName)
{
	u8* pMySpp = NULL;	
	u64 dec_size = 0;
	u64 hdr_len = 0;
	uint32_t dwBytesRead = 0;
	sce_header_t* pSceHdr = NULL;
	int retval = -1;



	// validate input params
	if ( (pInPath == NULL) || (pOutPath == NULL) )
		goto exit;

	// read the spp file into a buffer (alloc a new buffer)
	if ( ReadFileToBuffer(pInPath,(uint8_t**)&pMySpp, 0x00, &dwBytesRead, TRUE) != STATUS_SUCCESS ) {
		printf("failed to read in file:%s, exiting...\n", pInPath);
		goto exit;
	}

	/// Unpackage the "PKG" types ///
	if ( decrypt_spp(pMySpp, &dec_size, pKeyName) != STATUS_SUCCESS ) {
		printf("\n!!ERROR!!   FAILED to decrypt SPP file:%s\n\n", pInPath);
		goto exit;
	}
	// setup the SCE header
	pSceHdr = (sce_header_t*)pMySpp;//SIZE_SPKG_HDR
	wbe64((u8*)&hdr_len, pSceHdr->header_len);

	// write the decrypted file to disk
	if ( WriteBufferToFile(pOutPath, (pMySpp+hdr_len), (uint32_t)dec_size, FALSE, 0, NULL) != STATUS_SUCCESS ) {
		printf("failed to write to file:%s, exiting...\n", pOutPath);
		goto exit;
	}

	// status success
	retval = STATUS_SUCCESS;

exit:	
	// free the alloc'd memory
	if (pMySpp != NULL)
		free(pMySpp);

	return retval;
}
/**/
/*************************************************************************************************************/


// main function to do the pkg decrypt/unpackage
int do_spp_encrypt(char* pInPath, char* pOutPath, char* pType, char* pKeyName)
{	
	u8* pMySpp = NULL;
	u8* pMyContent = NULL;
	sce_header_t sce_hdr = {0};
	SPP_META_HDR meta_hdr = {0};
	u64 content_size_original = 0;
	u32 dwBytesRead = 0;
	u64 spp_size = 0;
	struct keylist* pMyKeyList = NULL;
	struct key MyKey = {0};	
	int retval = -1;


	// validate input params
	if ( (pInPath == NULL) || (pOutPath == NULL) || (pType == NULL) )
		goto exit;	

	// read in the 'input' (unencrypted) spp file (alloc a buffer)
	if ( ReadFileToBuffer(pInPath, (uint8_t**)&pMyContent, 0x00, &dwBytesRead, TRUE) != STATUS_SUCCESS) {
		printf("failed to read in file:%s, exiting...\n", pInPath);
		goto exit;
	}	
	// assign the read-in size
	content_size_original = (u32)dwBytesRead;	

	// build the SCE & META headers
	if ( build_spp_sce_hdr(&sce_hdr, content_size_original) != STATUS_SUCCESS )
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
			printf("Error:  Failed to find override SPP key(%s) in new \"KEYS\" file, trying old style keys...\n", pKeyName);	
			if ( key_get_old(KEY_SPP, pKeyName, &MyKey) == STATUS_SUCCESS ) 
			{
				if ( load_keylist_from_key(&pMyKeyList, &MyKey) != STATUS_SUCCESS )
				{
					printf("Error: Unexpected failure loading single 'keylist' from 'key' structure....exiting....\n");
					goto exit;
				}
			}
			else {
				printf("key_get() for SPP key failed");
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
			printf("Failed to find SPP key in new \"KEYS\" file, exiting!\n");
			goto exit;			
		}	
	}	
	//
	////////////////////////////////////////////////////////////////////////////////
	

	// build the 'metadata' headers
	if ( build_spp_meta_hdr(&meta_hdr, content_size_original) != STATUS_SUCCESS )
		goto exit;	

	// build the SPP file
	spp_size = build_spp(&sce_hdr, &meta_hdr, &pMySpp, pMyContent, content_size_original);
	if (spp_size == 0) 
		goto exit;
		
	// hash/sha1 the pkg data
	if ( hash_spp(pMySpp, content_size_original) != STATUS_SUCCESS )
		goto exit;

	// ECDSA sign the pkg
	if ( sign_spp(pMySpp) != STATUS_SUCCESS )
		goto exit;	
		
	// encrypt the data
	if ( sce_encrypt_data_pkgtool(pMySpp) != STATUS_SUCCESS )
		goto exit;

	// encrypt the hdrs
	if (sce_encrypt_header_pkgtool(pMySpp, &MyKey) != STATUS_SUCCESS )
		goto exit;

	// write out the final .pkg file
	if (WriteBufferToFile(pOutPath, pMySpp, (uint32_t)spp_size, FALSE, 0, NULL) != STATUS_SUCCESS) {
		printf("failed to write to file:%s, exiting...\n", pOutPath);
		goto exit;
	}	

	// status success
	retval = STATUS_SUCCESS;

exit:
	// free the alloc'd memory
	if (pMyContent != NULL)
		free(pMyContent);

	// free the alloc'd memory
	if (pMySpp != NULL)
		free(pMySpp);

	// return the status
	return retval;
}
/**/
/**********************************************************************************************************/