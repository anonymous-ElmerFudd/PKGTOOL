// Copyright 2010       anonymous
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt




#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include "spkg.h"
#include "tool_structures.h"
#include "file_functions.h"
#include "tools.h"
#include "types.h"
#include "sce.h"
#include "keys.h"





/////////////////////////////////////
// define internal/external globals
//

extern uint8_t b_DebugModeEnabled;
extern uint8_t b_DefaultKeyListOverride;
extern int32_t g_bZlibCompressLevel;

//
/////////////////////////////////////






/**********************************************/
// func. for decrypting the spkg file
int decrypt_spkg(u8* pInSpkg, u64* pDecSize, char* pKeyName)
{
	u16 keyrev = 0;
	u16 type = 0;	
	struct keylist *pMyKeyList = NULL;
	struct key MyKey = {0};
	sce_header_t* pSceHdr = NULL;
	metadata_header_t* pMetaDataHdr = NULL;
	static u32 meta_offset;
	static u32 n_sections;
	u32 hdr_len;
	int retval = -1;


	// validate input params
	if ( (pInSpkg == NULL) || (pDecSize == NULL) )
		goto exit;

	// assign sce hdr to start of buffer
	pSceHdr = (sce_header_t*)pInSpkg;	

	// verify SCE header magic!
	if ( verify_sce_header((u8*)pSceHdr, SIG_SCE_SPKG) != STATUS_SUCCESS ) {
		printf("SCE Header is not a valid PKG/SPKG header!, exiting!\n");
		goto exit;
	}

	// derive the hdr offsets
	keyrev    = be16((u8*)&pSceHdr->key_revision);		// key-revision
	type     = be16((u8*)&pSceHdr->header_type);		// hdr type
	hdr_len  = (u32)be64((u8*)&pSceHdr->header_len);	// hdr len
	*pDecSize = be64((u8*)&pSceHdr->data_len);			// data len

	// check the hdr type
	if (type != SCE_HEADER_TYPE_PKG) {
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
			printf("Error:  Failed to find override SPKG key(%s) in new \"KEYS\" file, trying old style keys...\n", pKeyName);	
			if ( key_get_old(KEY_SPKG, pKeyName, &MyKey) == STATUS_SUCCESS ) 
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
		if ( load_all_type_keys(&pMyKeyList, KEYTYPE_PKG) != STATUS_SUCCESS )
		{
			printf("Failed to find PKG keys in new \"KEYS\" file, trying old keys files....\n");
			// grab the decrypt keys
			pMyKeyList = keys_get(KEY_SPKG);
			if (pMyKeyList->n == 0) {
				printf("no SPKG key found\n");
				goto exit;
			}
		}	
	}
	//
	////////////////////////////////////////////////////////////////////////////////
		
	// go and decrypt the SPKG hdr
	if ( sce_decrypt_header_pkgtool(pInSpkg, pMyKeyList) != STATUS_SUCCESS ) {
		printf("header decryption failed\n");
		goto exit;
	}	

	// setup the meta offsets	
	meta_offset = be32((u8*)&pSceHdr->metadata_offset);
	pMetaDataHdr = (metadata_header_t*)(pInSpkg + sizeof(sce_header_t) + sizeof(metadata_info_t) + meta_offset);
	n_sections  = be32((u8*)&pMetaDataHdr->section_count);
	if (n_sections != NUM_SPKG_METADATA_SECTIONS) {
		printf("invalid section count: %d\n", n_sections);
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
int do_spkg_decrypt(char* pInPath, char* pOutPath, char* pKeyName)
{
	u8* pMySpkg = NULL;	
	u64 dec_size = 0;
	u64 hdr_len = 0;
	uint32_t dwBytesRead = 0;
	sce_header_t* pSceHdr = NULL;
	int retval = -1;



	// validate input params
	if ( (pInPath == NULL) || (pOutPath == NULL) )
		goto exit;

	// read the spkg file into a buffer (alloc a new buffer)
	if ( ReadFileToBuffer(pInPath,(uint8_t**)&pMySpkg, 0x00, &dwBytesRead, TRUE) != STATUS_SUCCESS ) {
		printf("failed to read in file:%s, exiting...\n", pInPath);
		goto exit;
	}

	/// Unpackage the "PKG" types ///
	if ( decrypt_spkg(pMySpkg, &dec_size, pKeyName) != STATUS_SUCCESS ) {
		printf("\n!!ERROR!!   FAILED to decrypt SPKG file:%s\n\n", pInPath);
		goto exit;
	}
	// setup the SCE header
	pSceHdr = (sce_header_t*)pMySpkg;//SIZE_SPKG_HDR
	wbe64((u8*)&hdr_len, pSceHdr->header_len);

	// write the decrypted file to disk
	if ( WriteBufferToFile(pOutPath, pMySpkg, (uint32_t)hdr_len, FALSE, 0, NULL) != STATUS_SUCCESS ) {
		printf("failed to write to file:%s, exiting...\n", pOutPath);
		goto exit;
	}

	// status success
	retval = STATUS_SUCCESS;

exit:	
	// free the alloc'd memory
	if (pMySpkg != NULL)
		free(pMySpkg);

	return retval;
}
/**/
/*************************************************************************************************************/