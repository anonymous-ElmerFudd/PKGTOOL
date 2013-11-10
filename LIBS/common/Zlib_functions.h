/*
* Copyright (c) 2011-2013 by anonymous
* This file is released under the GPLv2.
*/

#ifndef _ZLIBFUNCS_H_
#define _ZLIBFUNCS_H_




/* NOTE:  COMPRESSION LEVELS FROM ZLIB */
#ifndef Z_NO_COMPRESSION
#define Z_NO_COMPRESSION         0
#endif
#ifndef Z_BEST_SPEED
#define Z_BEST_SPEED             1
#endif
#ifndef Z_BEST_COMPRESSION
#define Z_BEST_COMPRESSION       9
#endif
#ifndef Z_DEFAULT_COMPRESSION
#define Z_DEFAULT_COMPRESSION  (-1)
#endif



#ifdef __cplusplus
extern "C" {
#endif



	int __stdcall Zlib_GetMaxCompressedLen( int nLenSrc );
	int __stdcall Zlib_CompressData( unsigned char* pInBuffer, int nLenSrc, unsigned char* pOutBuffer, int nLenDst, int CompressLevel );
	int __stdcall Zlib_UncompressData( unsigned char* pInBuffer, int nLenSrc, unsigned char* pOutBuffer, int nLenDst );


#ifdef __cplusplus
}
#endif


#endif // _ZLIBFUNCS_H_
