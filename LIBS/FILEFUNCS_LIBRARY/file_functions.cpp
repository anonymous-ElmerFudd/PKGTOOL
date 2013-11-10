/*
* Copyright (c) 2011-2013 by anonymous
* This file is released under the GPLv2.
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "stdint.h"
#include "file_functions.h"

// function declarations


/**/
/*
//
//
//
*///////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////
//
//
uint32_t __stdcall GetMyFileSizeA(char* pszInFileName, LARGE_INTEGER* pqwFileSize)
{
	HANDLE hFile = NULL;
	LARGE_INTEGER qwMyFileSize = {0};
	int retval = -1;


	// validate input params
	if ( (pszInFileName == NULL) || (pqwFileSize == NULL) )
		goto exit;

	// open the file handle to the file
	hFile = CreateFileA((LPCSTR)pszInFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		goto exit;

	// get the file size
	if ( GetFileSizeEx(hFile, &qwMyFileSize) == 0 ) {
		printf("Error:  Failed to get size of file:%s\n", pszInFileName);
		goto exit;
	}
	else
		*pqwFileSize = qwMyFileSize;
	
	// status success
	retval = 0x00;

exit:
	// if 'hFile' handle valid, close it
	if ( (hFile != INVALID_HANDLE_VALUE) && (hFile != NULL) )
		CloseHandle(hFile);

	// return status
	return retval;
}



uint32_t __stdcall ReadFileToBuffer(char* pszInFileName, uint8_t** ppBuffer, uint32_t dwBytesToRead, uint32_t* pdwBytesRead, uint8_t bAllocMemory)
{
	HANDLE hFile = NULL;	
	uint32_t dwBytesReadIn = 0;
	uint32_t dwMyBytesToRead = 0;
	uint32_t dwRetVal = (uint32_t)(-1);
	uint8_t* pData = NULL;

	// verify calling params
	if ( (pszInFileName == NULL) || (ppBuffer == NULL) )
		goto exit;

	// if NOT allocating memory, then make sure user passed
	// a valid pointer
	if ( (bAllocMemory == FALSE) && (*ppBuffer == NULL) )
		goto exit;

	// open the file handle to the file
	hFile = CreateFileA((LPCSTR)pszInFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		goto exit;

	// if we requested number of bytes to read,
	// read that amount in, otherwise slurp in the whole file!
	if (dwBytesToRead > 0)
		dwMyBytesToRead = dwBytesToRead;
	else {
		dwMyBytesToRead = GetFileSize(hFile, NULL);
		if (dwMyBytesToRead == 0)
			goto exit;
	}
	// if user specified to "alloc" memory, then go grab
	// memory, otherwise just read to the passed buffer
	if (bAllocMemory == TRUE) 
	{
		// alloc a buffer for reading in the file
		pData = (uint8_t*)calloc(dwMyBytesToRead, sizeof(char));
		if (pData == NULL)
			goto exit;
	}
	else {
		pData = *ppBuffer;
	}

	// read the file into the buffer
	if (ReadFile(hFile, pData, dwMyBytesToRead, (DWORD*)&dwBytesReadIn, NULL) == 0)
		goto exit;

	// verify size read in matches the size on disk
	if (dwBytesReadIn == dwMyBytesToRead) {
		if (pdwBytesRead != NULL)
			*pdwBytesRead = dwBytesReadIn;
		if (bAllocMemory == TRUE) 
			*ppBuffer = pData;
		dwRetVal = 0x00;
	}
	else
	{   // failed, so clean up
		if (pdwBytesRead != NULL)
			*pdwBytesRead = 0x00;
		if (bAllocMemory == TRUE) 
			*ppBuffer = NULL;	
		if (pData != NULL)
			free(pData);
	}

exit:
	// close the handle
	if ( (hFile != INVALID_HANDLE_VALUE) && (hFile != NULL) )
		CloseHandle(hFile);

	// return our status
	return dwRetVal;
}
/**/
/*----------------------------------------------------------------------------------*/


/**/
/*
//
//
//
*///////////////////////////////////////////////////////////////////////////////////////

uint32_t __stdcall WriteBufferToFile(char* pszInFileName, uint8_t* pInBuffer, uint32_t dwSizeOfBuffer, uint8_t bAppend, int32_t dwFilePosition, uint32_t* pdwBytesWritten)
{
	HANDLE hFile = NULL;	
	uint32_t dwBytesWritten = 0;
	uint32_t dwRetVal = (uint32_t)(-1);
	uint32_t dwCreate = CREATE_ALWAYS;

	// verify calling params
	if ( (pszInFileName == NULL) || (pInBuffer == NULL) || (dwSizeOfBuffer == 0) )
		goto exit;

	// if we are appending, set the flag as appropriate
	if (bAppend == TRUE)
		dwCreate = OPEN_EXISTING;

	// open the file handle to the file
	hFile = CreateFileA((LPCSTR)pszInFileName, GENERIC_WRITE, NULL, NULL, dwCreate, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		goto exit;

	// if we are appending, if we specified a "file position", then
	// move to "file position", otherwise move to EOF
	if (bAppend == TRUE) {
		if (dwFilePosition != 0) {
			// set position to specified "dwFilePosition"
			if ( SetFilePointer(hFile, dwFilePosition, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER )
				goto exit;
		} else {
			// set position to EOF (since we didn't set a position)
			if ( SetFilePointer(hFile, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER )
				goto exit;
		}
	}

	// go and write the desired data
	if ( WriteFile(hFile, pInBuffer, dwSizeOfBuffer, (DWORD*)&dwBytesWritten, NULL) == 0 )
		goto exit;		

	// status success
	dwRetVal = 0x00;

exit:
	// return number of bytes written
	if (pdwBytesWritten != NULL)
		*pdwBytesWritten = dwBytesWritten;

	// close the handle
	if ( (hFile != INVALID_HANDLE_VALUE) && (hFile != NULL) )
		CloseHandle(hFile);

	// return our status
	return dwRetVal;
}
/**/
/*----------------------------------------------------------------------------------*/