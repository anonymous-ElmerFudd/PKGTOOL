/*
* Copyright (c) 2011-2013 by anonymous
* This file is released under the GPLv2.
*/

#ifndef _FILEFUNCS_H_
#define _FILEFUNCS_H_

#include <windows.h>
#include "stdint.h"



#ifdef __cplusplus
extern "C" {
#endif

	uint32_t __stdcall GetMyFileSizeA(char* pszInFileName, LARGE_INTEGER* pqwFileSize);
	uint32_t __stdcall ReadFileToBuffer(char* pszInFileName, uint8_t** ppBuffer, uint32_t dwBytesToRead, uint32_t* pdwBytesRead, uint8_t bAllocMemory);
	uint32_t __stdcall WriteBufferToFile(char* pszInFileName, uint8_t* pInBuffer, uint32_t dwSizeOfBuffer, uint8_t bAppend, int32_t dwFilePosition, uint32_t* pdwBytesWritten);


#ifdef __cplusplus
}
#endif


#endif // _FILEFUNCS_H_
