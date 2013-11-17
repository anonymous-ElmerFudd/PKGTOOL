// Copyright 2010       anonymous
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt


#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "tools.h"
#include "types.h"
#include "cos.h"
#include "file_functions.h"





/////////////////////////////////////
// define internal/external globals
//
extern uint8_t b_DebugModeEnabled;
extern uint8_t b_DefaultKeyListOverride;
extern int32_t g_bZlibCompressLevel;
extern uint8_t b_OverrideFileSize;
//
////////////////////////////////////




// struct for capturing the 'files' info
struct pkg_file {
	char name[SIZE_COSPKG_FILERECORD_FILENAME];
	u8 *ptr;
	u64 size;
	u64 offset;
};
struct pkg_file cos_files[COS_MAX_FILES] = {0};





////////////				 CORE OS UNPACKAGE FUNCTIONS			/////////////////////////////////
// unpack CORE_OS file
int unpack_file(u8* pInPkg, char* pOutPath, u32 i)
{
	u8 *ptr = NULL;
	u8 filename[MAX_PATH] = {0};
	u8 name[MAX_PATH] = {0};
	u64 offset = 0;
	u64 size = 0;	
	COS_PKG_FILE_RECORD* pFileRecord = NULL;
	int retval = -1;


	// validate input params
	if ( (pInPkg == NULL) || (pOutPath == NULL) )
		goto exit;

	// setup ptr to start of file, offsets, etc
	ptr = pInPkg + sizeof(COS_PKG_HDR) + (sizeof(COS_PKG_FILE_RECORD) * i);
	pFileRecord = (COS_PKG_FILE_RECORD*)ptr;
	offset = be64((u8*)&pFileRecord->raw_offset);
	size   = be64((u8*)&pFileRecord->file_size);

	// build the full 'filepath+filename'
	memset(filename, 0, sizeof(filename));
	strncpy( (char *)name, (char *)&pFileRecord->file_name, SIZE_COSPKG_FILERECORD_FILENAME );	
	sprintf_s((char*)filename, MAX_PATH, "%s\\%s", pOutPath, name);

	// write the unpacked file to disk
	printf("unpacking %s...\n", name);
	if ( WriteBufferToFile((char*)filename, (pInPkg + offset), (uint32_t)size, FALSE, 0, NULL) != STATUS_SUCCESS ) {
		printf("failed to write to file:%s, exiting...\n", filename);
		goto exit;
	}
	
	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}

// func for starting the unpack process
int unpack_cos_pkg(u8* pInPkg, char* pOutPath)
{
	u32 n_files = 0;
	u64 size = 0;
	u32 i = 0;
	COS_PKG_HDR* pCosPkgHdr = NULL;
	int retval = -1;

	// validate input params
	if (pInPkg == NULL)
		goto exit;

	// extract out the num files and size
	pCosPkgHdr = (COS_PKG_HDR*)pInPkg;
	n_files = be32((u8*)&pCosPkgHdr->num_files);
	size = be64((u8*)&pCosPkgHdr->file_size);

	// loop through the files in the pkg
	for (i = 0; i < n_files; i++)
		unpack_file(pInPkg, pOutPath, i);

	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}
//
/////////////////////////////////////////////////////////////////////////////////////////////////////////////


/////////////				CORE OS 'PACKAGE' FUNCTIONS							////////////////////////////
//
//

// func to get the core os files to pkg up
int get_files(char *pInPath, u32* pNumFiles)
{
	WIN32_FIND_DATA FindData = {0};
	HANDLE hFind = INVALID_HANDLE_VALUE;	
	char path[MAX_PATH] = {0};
	char InDirPath[MAX_PATH] = {0};
	u32 MyNumFiles = 0;
	u32 i = 0;
	u64 offset = 0;
	int retval = -1;


	
	// validate input params
	if ( (pNumFiles == NULL) || (pInPath == NULL) )
		goto exit;
	
	// build the directory search string (ie All files)
	if ( sprintf_s(InDirPath, MAX_PATH, "%s\\*", pInPath) <= 0 )
		goto exit;

	// open handle to start find function
	hFind = FindFirstFile(InDirPath, &FindData);
	if (INVALID_HANDLE_VALUE == hFind) {
		printf("Error! No files found!\n");
		goto exit;
	} 
	
	/////////////////////////////////////////////////////////////////////////
	// do/while loop to iterate the entire directory
	do 
	{
		if (MyNumFiles >= COS_MAX_FILES) {
			printf("file overflow. increase MAX_FILES\n");
			goto exit;
		}
		// check if current entry is a "DIR", if we encounter
		// a dir (i.e. "." & "..", just continue
		if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)		
			continue;
		
		// make sure our file is "FILE_ATTRIBUTE_ARCHIVE" (normal file)
		if ( !(FindData.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) ) {			
			printf("Abnormal file encountered:%s, please fix it!\n", FindData.cFileName);
			goto exit;
		}

		// make sure the filename is within the COS HDR specs
		if (strlen(FindData.cFileName) > SIZE_COSPKG_FILERECORD_FILENAME) {
			printf("name too long: %s\n",FindData.cFileName);
			goto exit;
		}

		// create the file path
		memset(&cos_files[i], 0, sizeof(*cos_files));
		sprintf_s((char*)path, MAX_PATH, "%s\\%s", pInPath, FindData.cFileName);		
		strncpy_s(cos_files[i].name, sizeof(cos_files[i].name), FindData.cFileName, 0x19);
		
		// get the size of the file, if
		// the filesize is too large, bail out
		cos_files[i].size = FindData.nFileSizeLow;		
		if (FindData.nFileSizeHigh != 0) {
			printf("!! ERROR! file:%s is TOO LARGE!\n", FindData.cFileName);
			goto exit;
		}		
		
		// read in the file, and assign the alloc'd memory
		// ptr to the "files[i].ptr" structure
		if ( ReadFileToBuffer((char*)path, &cos_files[i].ptr, 0x00, NULL, TRUE) != STATUS_SUCCESS ) {
			printf("unable to read in file:%s\n", path);
			goto exit;
		}
		// setup the 'offset' value
		cos_files[i].offset = offset;
		#pragma warning( disable : 4146 ) 
		offset = round_up( (offset + cos_files[i].size), SIZE_COSPKG_FILERECORD_FILENAME );		
	
		i++;
		MyNumFiles++;
	}
	while (FindNextFile(hFind, &FindData) != 0);

	//
	///////////////////////////////////////////////////////////////////////////////////////////////
		
	// make sure our final error was the expected
	// "ERROR_NO_MORE_FILES"
	if ( GetLastError() != ERROR_NO_MORE_FILES ) {
		printf("!! Unexpected error parsing files!, exiting!\n");
		goto exit;
	}
	
	// status success
	retval = STATUS_SUCCESS;
	*pNumFiles = MyNumFiles;

exit:
	// if 'hFind' was valid, close it
	if (hFind != NULL)
		 FindClose(hFind);

	return retval;
}

// func. to build the cos pkg hdr
int build_hdr(u8** ppCosHdr, u32* pHdrSize, u32 NumFiles, u64 OverrideFileSize, u64* pPaddSize)
{
	u8 *ptr = NULL;
	u32 i = 0;
	u64 file_size = 0;	
	COS_PKG_HDR* pCosPkgHdr = NULL;
	COS_PKG_FILE_RECORD* pFileRecord = NULL;
	int retval = -1;



	// validate input params
	if ( (ppCosHdr == NULL) || (pHdrSize == NULL) || (pPaddSize == NULL) )
		goto exit;

	// calculate the final 'filesize' and the hdr size
	file_size = (cos_files[NumFiles - 1].offset) + (cos_files[NumFiles - 1].size);
	*pHdrSize = sizeof(COS_PKG_HDR) + (NumFiles * sizeof(COS_PKG_FILE_RECORD));
		
	// if the 'OverrideFileSize' is valid, fix the 'filesize'
	// in the COS header	
	if ( b_OverrideFileSize == TRUE)	
	{
		if (OverrideFileSize > (file_size + *pHdrSize))
		{
			if (b_DebugModeEnabled)
				printf("RE-SIZED COS 'content' file to override size:0x%x\n", OverrideFileSize);
			// calculate the new sizes
			*pPaddSize = (OverrideFileSize - *pHdrSize) - file_size;
			file_size = (OverrideFileSize - *pHdrSize);
		}
		// otherwise, if our 'override' file size is smaller than our current size,
		// we have a 'fatal' error, and must exit out
		else if (OverrideFileSize < (file_size + *pHdrSize)) {
			printf("ERROR:  Attempted to resize COS 'content' file with invalid size:0x%x, exiting!\n", OverrideFileSize);
			goto exit;
		}
		else if (OverrideFileSize == (file_size + *pHdrSize)) {
			printf("Original COS 'Content' size is already sized properly, re-size not required...\n");
		}
	}
	// alloc memory for the hdr
	*ppCosHdr =  (u8*)calloc(*pHdrSize, sizeof(char));
	if (*ppCosHdr == NULL) {
		printf("out of memory\n");
		goto exit;
	}

	// setup the ptr for the COS_PKG_HDR,
	// and populate the COS_PKG_HDR fields
	pCosPkgHdr = (COS_PKG_HDR*)*ppCosHdr;		
	ptr = *ppCosHdr;

	wbe32((u8*)&pCosPkgHdr->magic, 1);	// magic
	wbe32((u8*)&pCosPkgHdr->num_files, NumFiles);
	wbe64((u8*)&pCosPkgHdr->file_size, (*pHdrSize + file_size));
	ptr += sizeof(COS_PKG_HDR);

	// iterate through the buffer, and populate the FILE_RECORD hdrs
	// with the appropriate data from the files
	for (i = 0; i < NumFiles; i++) {
		pFileRecord = (COS_PKG_FILE_RECORD*)ptr;
		wbe64((u8*)&pFileRecord->raw_offset, cos_files[i].offset + *pHdrSize);
		wbe64((u8*)&pFileRecord->file_size, cos_files[i].size);
		strncpy((char*)&pFileRecord->file_name, cos_files[i].name, SIZE_COSPKG_FILERECORD_FILENAME);
		ptr+= sizeof(COS_PKG_FILE_RECORD);
	}
	// status success
	retval = STATUS_SUCCESS;

exit:
	return retval;
}

// func. to write out the pkg file
int write_pkg(u8* pCosHdr, const char *pOutFile, u32 HdrSize, u32 NumFiles, u64 PaddSize)
{	
	u8* pTmpBuffer = NULL;
	u32 i = 0;	
	int retval = -1;


	// validate input params
	if ( (pOutFile == NULL) || (pCosHdr == NULL) )
		goto exit;	

	// write the file header
	if ( WriteBufferToFile((char*)pOutFile, (uint8_t*)pCosHdr, (uint32_t)HdrSize, FALSE, 0, NULL) != STATUS_SUCCESS ) {
		printf("Failed to write to output file:%s, exiting...\n", pOutFile);
		goto exit;
	}

	// loop through the directory and files, 
	// and write them to the pkg file
	for (i = 0; i < NumFiles; i++) {
		// write the file data, appended to the existing file, 
		// start at the specified 'offset'
		if ( WriteBufferToFile((char*)pOutFile, (uint8_t*)cos_files[i].ptr, (uint32_t)cos_files[i].size, TRUE, (int32_t)(cos_files[i].offset + HdrSize), NULL) != STATUS_SUCCESS ) {
			printf("Failed to embed file in COSPKG file:%s, exiting...\n", pOutFile);
			goto exit;
		}
	}
	// if we are 'overriding' the file size, then padd the 
	// file with data if necessary
	if (b_OverrideFileSize == TRUE) {
		if (PaddSize > 0)
		{
			pTmpBuffer = (u8*)calloc((size_t)PaddSize, sizeof(char));
			if (pTmpBuffer == NULL) {
				printf("Error: Memory allocation failed\n");
				goto exit;
			}

			// write out the zero-padding buffer to final output file,
			// APPENDING to file 'EOF'
			if ( WriteBufferToFile((char*)pOutFile, (uint8_t*)pTmpBuffer, (uint32_t)PaddSize, TRUE, 0, NULL) != STATUS_SUCCESS )			{
				printf("Failed padding final file:%s, exiting...\n", pOutFile);
				goto exit;
			}
		}
	} // end IF (b_Overridefilesize...)

	// status success
	retval = STATUS_SUCCESS;

exit:
	// free any alloc'd memory
	if (pTmpBuffer != NULL)
		free(pTmpBuffer);

	// return our final status
	return retval;
}
/**/
/******************************************************************************************************************/

// main function to build the COS pkg
int create_cos_pkg(char* pInPath, char* pOutFile, u64 OverrideFileSize) 
{	
	u32 i = 0;
	u8* pCosHdr = NULL;
	u32 HdrSize = 0;
	u32 NumFiles = 0;
	u64 PaddSize = 0;
	int retval = -1;


	// validate input params
	if ( (pInPath == NULL) || (pOutFile == NULL) )
		goto exit;
	
	// go build up the files list
	if ( get_files(pInPath, &NumFiles) != STATUS_SUCCESS )
		goto exit;

	// build the final COS PKG 'HDR'
	if ( build_hdr(&pCosHdr, &HdrSize, NumFiles, OverrideFileSize, &PaddSize) != STATUS_SUCCESS )
		goto exit;

	// write out the final pkg file
	if ( write_pkg(pCosHdr, pOutFile, HdrSize, NumFiles, PaddSize) != STATUS_SUCCESS )
		goto exit;

	// status success
	retval = STATUS_SUCCESS;

exit:
	// loop through the file[] struct, 
	// and free all the alloc'd buffers!
	for (i = 0; i < NumFiles; i++) {
		if (cos_files[i].ptr != NULL) {
			free(cos_files[i].ptr);
			cos_files[i].ptr = NULL;
		}
	}

	return retval;
}
/**/
/*************************************************************************************/


// main function for 'unpacking' COS files
int do_unpack_cos_package(char* pInPath, char* pOutPath)
{
	u8* pMyPkg = NULL;
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

	// read the COS file to a buffer (alloc buffer)
	if ( ReadFileToBuffer(pInPath,(uint8_t**)&pMyPkg, 0x00, &dwBytesRead, TRUE) != STATUS_SUCCESS ) {
		printf("failed to read in file:%s, exiting...\n", pInPath);
		goto exit;
	}

	// extract out the COS.pkg files
	if ( unpack_cos_pkg(pMyPkg, pOutPath) != STATUS_SUCCESS ) {
		printf("failed to unpack cos file:%s, exiting\n", pOutPath );
		goto exit;		
	}

	// status success
	retval = STATUS_SUCCESS;

exit:
	// free any alloc'd memory
	if (pMyPkg != NULL)
		free(pMyPkg);

	return retval;

}
/**/
/*************************************************************************************/