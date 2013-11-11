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





/**********************************************/
// func. for decrypting the spkg file
int decrypt_spkg(u8* pInSpkg, u64* pDecSize)
{
	u16 keyrev = 0;
	u16 type = 0;	
	struct keylist *k = NULL;
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
	if (type != SCE_HEADER_TYPE_PKG) {
		printf("not a valid PKG/SPKG file\n");
		goto exit;
	}
	// go get the SPKG keys
	k = keys_get(KEY_SPKG);
	if (k == NULL) {
		printf("no key found\n");
		goto exit;
	}
	// go and decrypt the SPKG hdr
	if ( sce_decrypt_header_pkgtool(pInSpkg, k) != STATUS_SUCCESS ) {
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
	// if we failed, then return "0"
	if (retval != STATUS_SUCCESS)
		*pDecSize = 0;

	return retval;
}
/**/
/************************************************************************************************************/