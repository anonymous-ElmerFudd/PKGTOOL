// Copyright 2010       anonymous
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
//



#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include "pup.h"
#include "tool_structures.h"
#include "file_functions.h"
#include "Zlib_functions.h"
#include "sha1.h"
#include "tools.h"
#include "types.h"
#include "sce.h"
#include "keys.h"






/////////////////////////////////////
// define internal/external globals
//
extern PKG_FILE_NAMES g_pszPkgFileNames;
extern uint8_t b_DebugModeEnabled;
extern int32_t g_bZlibCompressLevel;
//
/////////////////////////////////////


// structure for capturing the file data
// for each file being embedded into the PUP
struct pup_file {
    u8 *ptr;
    u64 id;
    u64 len;
    u64 offset;
};
struct pup_file pup_files[PUP_MAX_FILES] = {0};

// struct for the 'filenames' associated with 
// the PUP embedded files
// TRUE/FALSE designator is for whether
// or not the file is REQ'D in order to
// build the PUP 
// (ie some files are NOT in ALL FW releases)
static struct id2name_tbl t_names[] = {
    {TRUE, 0x100, "version.txt"},
    {TRUE, 0x101, "license.xml"},
    {FALSE,0x102, "promo_flags.txt"},
    {TRUE, 0x103, "update_flags.txt"},
    {FALSE,0x104, "patch_build.txt"},
    {TRUE, 0x200, "ps3swu.self"},
    {TRUE, 0x201, "vsh.tar"},
    {TRUE, 0x202, "dots.txt"},
    {FALSE,0x203, "patch_data.pkg"},
    {TRUE, 0x300, "update_files.tar"},
    {FALSE,0x501, "spkg_hdr.tar"},
    {FALSE,0x601, "ps3swu2.self"},
    {FALSE, 0, NULL}
};






/*  ------------------------------------------------------------------------------- */
/*  --------------------  PUP PACKING SECTION ----------------------------------- */
/*  ------------------------------------------------------------------------------- */
// func to find the PUP files
int find_files(char* pInPath, u32* pNumFiles, u64* pDataSize)
{
    struct id2name_tbl *table = NULL;
	char szFileName[MAX_PATH] = {0};
	LARGE_INTEGER qwFileSize = {0};    
    u64 offset = 0;    
	u64 data_size = 0;
	u32 num_files = 0;
	u32 i = 0;
	int retval = -1;

	

	// validate input params
	if ( (pInPath == NULL) || (pNumFiles == NULL) || (pDataSize == NULL) )
		goto exit;

    
	// assign ptr to the table names   
    table = t_names;

	// iterate through the names table, and 
	// find the corresponding files
    while(table->name != NULL) {

		// get the file size, and it legit, read
		// the file into the files[] list
		sprintf_s(szFileName, MAX_PATH, "%s\\%s", pInPath, table->name);
		if ( GetMyFileSizeA(szFileName, &qwFileSize ) != STATUS_SUCCESS ) {
			if (table->required == TRUE) {
				printf("Failed to find required file:%s, exiting...\n", table->name);
				goto exit;
			}	
			else {
				printf("failed to find file:%s, but skipping since it may not be in this FW version....\n", table->name);
			}
		}
		else 
		{
			// assure that filesize is not too large!
			if (qwFileSize.HighPart != 0) {
				printf("Error:  file is too large:%s, exiting...\n", table->name);
				goto exit;
			}
			// populate the files[] struct
            pup_files[num_files].id = table->id;
			if ( ReadFileToBuffer(szFileName, &pup_files[num_files].ptr, qwFileSize.LowPart, NULL, TRUE ) != STATUS_SUCCESS ) {
				printf("Error:  could not read in file:%s, exiting...\n", table->name);
				goto exit;
			}  
			// assign the length, and increment the total 'data size'
			pup_files[num_files].len = qwFileSize.LowPart;
            data_size+= pup_files[num_files].len;
            num_files++;
        }
        table++;
    }
	// calculate the offset
    offset = sizeof(SCE_PUP_HDR) + sizeof(SCE_PUP_SECTION_HDR) + (sizeof(SCE_PUP_FILE_RECORD) * num_files);
	// iterate through the files list, and calculate offset for each file
    for (i = 0; i < num_files; i++) {
        pup_files[i].offset = offset;
        offset += pup_files[i].len;
    }
	// status success
	*pNumFiles = num_files;
	*pDataSize = data_size;
	retval = STATUS_SUCCESS;

exit:
	return retval;
}

// func. to calulcate the hmac
int calc_hmac(u8* pHmacSecretKey, u8* pInBuffer, u64 len, u8* pOutHmac)
{
	int retval = -1;


	// validate input params
	if ( (pInBuffer == NULL) || (pHmacSecretKey == NULL) || (pOutHmac == NULL) )
		goto exit;

	// calculate the 'sha1_hmac' for the specified block
	sha1_hmac(pHmacSecretKey, HMAC_KEY_SIZE, (unsigned char*)pInBuffer, (size_t)len, pOutHmac);

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}

// func. for building the PUP header
int build_header(u8* pHmacSecretKey, u8* pInHdr, u32 num_files, u64 BuildNumber, u64 MyDataSize)
{
    u32 i = 0;
	SCE_PUP_HDR* pPupSceHeader = NULL;
	SCE_PUP_FILE_RECORD* pPupFileRecord = NULL;
	int retval = -1;


	// validate input params
	if ( (pInHdr == NULL) || (pHmacSecretKey == NULL) )
		goto exit;


	// setup the initial PUP header params
	pPupSceHeader = (SCE_PUP_HDR*)pInHdr;
    //memset((u8*)&pPupSceHeader->, 0, sizeof(pInHdr));
	memcpy((u8*)&pPupSceHeader->magic, PUP_SCE_HEADER_STRING, sizeof(u64));
	wbe64((u8*)&pPupSceHeader->key_revision, 1);
	wbe64((u8*)&pPupSceHeader->pup_build_number, BuildNumber);
	wbe64((u8*)&pPupSceHeader->num_sections, num_files);
	wbe64((u8*)&pPupSceHeader->header_size, (sizeof(SCE_PUP_HDR)+sizeof(SCE_PUP_SECTION_HDR)) + (num_files * sizeof(SCE_PUP_FILE_RECORD)) );
	wbe64((u8*)&pPupSceHeader->data_size, MyDataSize);

	// iterate the files list, and populate the section hdr
	// for each file
    for (i = 0; i < num_files; i++) {
		pPupFileRecord = (SCE_PUP_FILE_RECORD*)(pInHdr + sizeof(SCE_PUP_HDR) + (sizeof(SCE_PUP_SECTION_HDR) * i));
		wbe64((u8*)&pPupFileRecord->id, pup_files[i].id);
		wbe64((u8*)&pPupFileRecord->offset, pup_files[i].offset);
		wbe64((u8*)&pPupFileRecord->len, pup_files[i].len);
		wbe64((u8*)&pPupFileRecord->unknown0, 0);
        wbe64(pInHdr + sizeof(SCE_PUP_HDR) + (sizeof(SCE_PUP_SECTION_HDR) * num_files) + (sizeof(SCE_PUP_SECTION_HDR) * i), i);

		// calulate the "hmac" for the current file, and update it in the file record
        if ( calc_hmac( 
			pHmacSecretKey,		// hmac key
			pup_files[i].ptr,	// ptr to start of file data
			pup_files[i].len,	// len of file data
			(pInHdr + sizeof(SCE_PUP_HDR) + (sizeof(SCE_PUP_SECTION_HDR) * num_files) + (sizeof(SCE_PUP_SECTION_HDR) * i) + 0x08)	// offset in file for 'hmac' result
			) != STATUS_SUCCESS ) {

			printf("Failed to calculate HMAC for PUP file id:%d, exiting....\n", pup_files[i].id);
			goto exit;
		}
    }
	// calc the hmac for the PUP header block
    if ( calc_hmac(
		pHmacSecretKey,										// hmac key
		pInHdr,												// ptr to start of file data
		(sizeof(SCE_PUP_HDR) + (sizeof(SCE_PUP_FILE_RECORD) * num_files)),			// len of file data
		(pInHdr + sizeof(SCE_PUP_HDR) + (sizeof(SCE_PUP_FILE_RECORD) * num_files))	// offset in file for 'hmac' result
		) != STATUS_SUCCESS ) {

		printf("Failed to calculate HMAC for PUP header block, exiting....\n");
		goto exit;
	}	
	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}

// func. to write out the final pup
int write_pup(u8* pInPupHdr, char* pOutPath, u32 num_files)
{	
    u32 i = 0;
	int retval = -1;


	// validate input params
	if ( (pInPupHdr == NULL) || (pOutPath == NULL) )
		goto exit;	

	// write the initial PUP headers
	if ( WriteBufferToFile(pOutPath, pInPupHdr, (sizeof(SCE_PUP_HDR) + sizeof(SCE_PUP_SECTION_HDR) + (sizeof(SCE_PUP_FILE_RECORD) * num_files)), FALSE, 0, NULL) != STATUS_SUCCESS ) {
		printf("Failed to write to output file:%s, exiting...\n", pOutPath);
		goto exit;
	}

	// iterate through the 'files[]' array, and write
	// out the read-in file to the PUP package
    for (i = 0; i < num_files; i++) {
		// write the file data, appended to the existing file, 
		// start at the specified 'offset'
		if (WriteBufferToFile(pOutPath, (uint8_t*)pup_files[i].ptr, (uint32_t)pup_files[i].len, TRUE, (int32_t)pup_files[i].offset, NULL) != STATUS_SUCCESS ) {
			printf("Failed to embed file in PUP file:%s, exiting...\n", pOutPath);
			goto exit;
		}
    }
	// status success
	retval = STATUS_SUCCESS;

exit:	
	// return status
	return retval;
}

// func for packing up the pup 
int do_pup_pack(char* pInPath, char* pOutPath, u64 BuildNumber)
{		
	u64 total_data_size = 0;
	keyset_t* pPupHmacKey = NULL;
	u8 pup_hmac_key[HMAC_KEY_SIZE] = {0};	
	u8 PupHeader[sizeof(SCE_PUP_HDR) + sizeof(SCE_PUP_SECTION_HDR) + (sizeof(SCE_PUP_FILE_RECORD) * PUP_MAX_FILES)] = {0};
	u32 num_files = 0;
	u32 i = 0;
	int retval = -1;	



	// validate input params
	if ( (pInPath == NULL) || (pOutPath == NULL) )
		goto exit;

	// get the PUP 'HMAC' KEY, first check the 'scetool'
	// style 'KEYS' file, then default to 'old keys format'
	pPupHmacKey = keyset_find_by_name(PUP_KEYS_ENTRY_NAME);
	if (pPupHmacKey != NULL) {
		if ( memcpy_s(pup_hmac_key, sizeof(pup_hmac_key), pPupHmacKey->erk, sizeof(pup_hmac_key)) != 0 )
			printf("Error:  Failed attempting to copy 'pup-hmac' key from KEYS file, trying old keys format....\n");
		else {
			if (b_DebugModeEnabled == TRUE)
				printf("Successfully retrieved PUP HMAC key from new 'keys' file\n");
		}
	}
	else {
		printf("Could not find: PUP-HMAC key in 'KEYS' file, defaulting to old key style..\n");
		if ( key_get_simple("pup-hmac", pup_hmac_key, sizeof(pup_hmac_key)) != STATUS_SUCCESS ) {
			printf("Error!  Could not locate \"pup-hmac\" key, exiting...\n");
			goto exit;
		}
		if (b_DebugModeEnabled == TRUE)
			printf("Successfully retrieved PUP HMAC key from old-method (\'pup-hmac\') file\n");
	}

	// go find the files for packing
	if ( find_files(pInPath, &num_files, &total_data_size) != STATUS_SUCCESS ) {
		printf("Failed to find all files....exiting\n");
		goto exit;
	}
    // build the pup header
	if ( build_header(pup_hmac_key, PupHeader, num_files, BuildNumber, total_data_size) != STATUS_SUCCESS ) {
		printf("Failed to build the PUP header, exiting...\n");
		goto exit;
	}
	// go write out the PUP pkg
    if ( write_pup(PupHeader, pOutPath, num_files) != STATUS_SUCCESS ) {
		printf("Failed to write out the PUP package...exiting....\n");
		goto exit;
	}

	// status success
	retval = STATUS_SUCCESS;

exit:
	// loop through the file[] struct, 
	// and free all the alloc'd buffers!
	for (i = 0; i < num_files; i++) {
		if (pup_files[i].ptr != NULL) {
			free(pup_files[i].ptr);
			pup_files[i].ptr = NULL;
		}
	}

	return retval;
}
/**/
/************************************************************************************/


/*  ------------------------------------------------------------------------------- */
/*  --------------------  PUP UNPACKING SECTION ----------------------------------- */
/*  ------------------------------------------------------------------------------- */
// func. for checking the sha hmac for the header
int check_hmac(u8 *pMyHmacKey, u8* pMyOrgHmac, u8 *bfr, u64 len)
{	
	u8 calc[PUP_HMAC_RESULT_SIZE] = {0};
	int retval = -1;

	
	// validate input params
	if ( (pMyHmacKey == NULL) || (pMyOrgHmac == NULL) || (bfr == NULL) )
			goto exit;
	
	// calculate the 'sha1-hmac' of the section
	sha1_hmac(pMyHmacKey, HMAC_KEY_SIZE, (unsigned char*)bfr, (size_t)len, calc);

	// compare the hdr hmac value to the calc'd
	// one, return result of the compare
	if ( memcmp(calc, pMyOrgHmac, sizeof(calc)) == 0 )
			retval = STATUS_SUCCESS;

exit:
	// return the status
	return retval;	
}

// func. to find the "hmac" entry
int find_hmac(u8* pInPup, u8** ppHmacPtr, u64 entry, u64 num_sections)
{
	u8 *ptr = NULL;
	u64 i = 0;
	int retval = -1;


	// validate input params
	if ( (ppHmacPtr == NULL) || (pInPup == NULL) )
		goto exit;

	// setup the starting ptr
	ptr = (pInPup + sizeof(SCE_PUP_HDR) + (sizeof(SCE_PUP_SECTION_HDR) * num_sections));

	// iteration through the sections, to find
	// the hmac entry
	for(i = 0; i < num_sections; i++)
	{
		if (be64(ptr) == entry) {
			*ppHmacPtr =  (ptr + 8);
			break;
		}
		ptr += sizeof(SCE_PUP_SECTION_HDR);
	}
	// if we did not find it, fail out
	if (*ppHmacPtr == NULL) {
		printf("hmac not found: %d\n", entry);
		goto exit;
	}

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}

// func. for parsing the section
int do_section(char* pOutPath, u8* pInPup, u8* pMyHmacKey, u64 section_num, u64 num_sections)
{
	u8 *ptr = NULL;
	u8* pHmacPtr = NULL;
	u64 entry = 0;
	u64 offset = 0;
	u64 size = 0;	
	const char *fname = NULL;	
	char szFilePath[MAX_PATH] = {0};
	sce_header_t* pSceHeader = NULL;
	SCE_PUP_SECTION_HDR* pSectionHdr = NULL;
	int retval = -1;



	// validate input params
	if ( (pInPup == NULL) || (pMyHmacKey == NULL) || (pOutPath == NULL) )
		goto exit;

	// setup the SCE header
	pSceHeader = (sce_header_t*)pInPup;

	// setup the params from pup header
	ptr = (pInPup + sizeof(SCE_PUP_HDR) + (sizeof(SCE_PUP_SECTION_HDR) * section_num));
	pSectionHdr = (SCE_PUP_SECTION_HDR*)ptr;

	// extract the section info
	entry = be64((u8*)&pSectionHdr->entry);
	offset = be64((u8*)&pSectionHdr->offset);
	size = be64((u8*)&pSectionHdr->size);

	// lookup the file 'id', and get the 'name' from the table
	fname = id2name((u32)entry, t_names, NULL);
	if (fname == NULL) {
		printf("ERROR: PUP file--> unknown entry id: %08x_%08x\n", (u32)(entry >> 32), (u32)entry);
		goto exit;
	}
	// go find the current section's hmac
	if ( find_hmac(pInPup, &pHmacPtr, section_num, num_sections) != STATUS_SUCCESS )
		goto exit;

	// check the hmac for this file
	if ( check_hmac(pMyHmacKey, pHmacPtr, (pInPup + offset), size) != STATUS_SUCCESS ) {
		printf("ERROR: HMAC failed for current section!, exiting....\n");
		goto exit;
	}	
	// output the current file info...
	printf("unpacking %s (%08x bytes; hmac: OK)...\n", fname, (u32)(size));

	// create the full output path string
	if ( sprintf_s(szFilePath, MAX_PATH, "%s\\%s", pOutPath, fname) <= 0 ) {
		printf("Unexpected API error, exiting!\n");
		goto exit;
	}
	
	// write the extracted file to disk
	if ( WriteBufferToFile(szFilePath, (pInPup + offset), (uint32_t)size, FALSE, 0, NULL) != STATUS_SUCCESS ) {
		printf("Error:  Failed writing file:%s\n", fname);
		goto exit;
	}

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;	
}
/////////////////////////////////////////////////////////////////////////////////



// func for unpacking the pup 
int do_pup_unpack(char* pInPath, char* pOutPath)
{
	u8* pMyPup = NULL;
	u64 data_size = 0;	
	u64 n_sections = 0;
	u64 hdr_size = 0;
	keyset_t* pPupHmacKey = NULL;
	u8 pup_hmac_key[HMAC_KEY_SIZE] = {0};		
	SCE_PUP_HDR* pScePupHeader = NULL;
	u32 dwBytesRead = 0;
	u64 i = 0;	
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

	// read the COS file to a buffer (alloc buffer)
	if ( ReadFileToBuffer(pInPath,(uint8_t**)&pMyPup, 0x00, &dwBytesRead, TRUE) != STATUS_SUCCESS ) {
		printf("failed to read in file:%s, exiting...\n", pInPath);
		goto exit;
	}	

	// verify SCE header magic!
	if ( verify_sce_header(pMyPup, SIG_SCE_PUP) != STATUS_SUCCESS ) {
		printf("SCE Header is not a valid PUP header!, exiting!\n");
		goto exit;
	}
	
	// get the PUP 'HMAC' KEY, first check the 'scetool'
	// style 'KEYS' file, then default to 'old keys format'
	pPupHmacKey = keyset_find_by_name(PUP_KEYS_ENTRY_NAME);
	if (pPupHmacKey != NULL) {
		if ( memcpy_s(pup_hmac_key, sizeof(pup_hmac_key), pPupHmacKey->erk, sizeof(pup_hmac_key)) != 0 )
			printf("Error:  Failed attempting to copy 'pup-hmac' key from KEYS file, trying old keys format....\n");
		else {
			if (b_DebugModeEnabled == TRUE)
				printf("Successfully retrieved PUP HMAC key from new 'keys' file\n");
		}
	}
	else {
		printf("Could not find: PUP-HMAC key in 'KEYS' file, defaulting to old key style..\n");
		if ( key_get_simple("pup-hmac", pup_hmac_key, sizeof(pup_hmac_key)) != STATUS_SUCCESS ) {
			printf("Error!  Could not locate \"pup-hmac\" key, exiting...\n");
			goto exit;
		}	
		if (b_DebugModeEnabled == TRUE)
			printf("Successfully retrieved PUP HMAC key from old-method (\'pup-hmac\') file\n");
	}	
	
	// setup the SCE PUP header
	// calculate data from the hdr
	pScePupHeader = (SCE_PUP_HDR*)pMyPup;
	n_sections = be64((u8*)&pScePupHeader->num_sections);
	hdr_size = be64((u8*)&pScePupHeader->header_size);
	data_size = be64((u8*)&pScePupHeader->data_size);

	// if in "DEBUG" mode, then print out extra info
	if (b_DebugModeEnabled == TRUE) {
		printf("sections: %lld\n", n_sections);
		printf("hdr size: %08x_%08x\n", (u32)(hdr_size >> 32), (u32)hdr_size);
		printf("data size: %08x_%08x\n", (u32)(data_size >> 32), (u32)data_size);
		printf("header hmac:");
		for (i = 0;i < HMAC_KEY_SIZE; i++)
			printf("%x", pup_hmac_key[i]);
		printf("\n");
	}

	// check the hmac of the header, make sure it's valid
	if ( check_hmac( pup_hmac_key, (pMyPup + sizeof(SCE_PUP_HDR) + 0x40 * n_sections), pMyPup, (0x30 + 0x40 * n_sections) ) != STATUS_SUCCESS )
	{
		printf("PUP failed header verification!, exiting..\n");
		goto exit;
	}
	// HMAC verified!
	printf("PUP HMAC OK\n");	

	// iterate the pup sections, and extract
	// the embedded files
	for (i = 0; i < n_sections; i++)
		do_section(pOutPath, pMyPup, pup_hmac_key, i, n_sections);

	// status success
	retval = STATUS_SUCCESS;

exit:
	// free the alloc'd memory
	if (pMyPup != NULL)
		free(pMyPup);

	return retval;
}
/**/
/***************************************************************************************************/