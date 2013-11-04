/*
* Copyright (c) 2011-2013 by anonymous
* This file is released under the GPLv2.
*/

#ifndef _ZLIBFUNCS_H_
#define _ZLIBFUNCS_H_




#ifdef __cplusplus
extern "C" {
#endif


	int Zlib_GetMaxCompressedLen( int nLenSrc );
	int Zlib_CompressData( unsigned char* pInBuffer, int nLenSrc, unsigned char* pOutBuffer, int nLenDst );
	int Zlib_UncompressData( unsigned char* pInBuffer, int nLenSrc, unsigned char* pOutBuffer, int nLenDst );


#ifdef __cplusplus
}
#endif


#endif // _ZLIBFUNCS_H_
