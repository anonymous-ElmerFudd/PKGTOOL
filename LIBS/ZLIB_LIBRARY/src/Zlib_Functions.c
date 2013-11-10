/*
* Copyright (c) 2011-2013 by anonymous
* This file is released under the GPLv2.
*/

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "zlib.h"  
#include "Zlib_functions.h"


#define ZLIB_BLOCK_SIZE 16384



/// function for determining the maximum size needed to 
//  guarantee adequate buffer size
int __stdcall Zlib_GetMaxCompressedLen( int nLenSrc ) 
{
    int n16kBlocks = (nLenSrc+(ZLIB_BLOCK_SIZE-1)) / ZLIB_BLOCK_SIZE; // round up any fraction of a block
    return ( nLenSrc + 6 + (n16kBlocks*5) );
}

/// Zlib compress (deflate) the buffer
int __stdcall Zlib_CompressData( unsigned char* pInBuffer, int nLenSrc, unsigned char* pOutBuffer, int nLenDst, int CompressLevel )
{
	int nErr = -1;
	int nRet = -1;
    z_stream zInfo = {0};
    zInfo.total_in=  zInfo.avail_in=  nLenSrc;
    zInfo.total_out= zInfo.avail_out= nLenDst;
    zInfo.next_in= (BYTE*)pInBuffer;
    zInfo.next_out= pOutBuffer;	

	// verify input params are valid
	if ( (pInBuffer == NULL) || (nLenSrc == 0) || (pOutBuffer == NULL) || (nLenDst == 0) )
		goto exit;

	// verify compress level is -1, or 0 to 9
	if ( (CompressLevel != -1) && (CompressLevel > 9) )
		goto exit;
    
    nErr= deflateInit( &zInfo, CompressLevel ); // zlib function
    if ( nErr == Z_OK ) {
        nErr= deflate( &zInfo, Z_FINISH );              // zlib function
        if ( nErr == Z_STREAM_END ) {
            nRet= zInfo.total_out;
        }
    }
    deflateEnd( &zInfo );    // zlib function

exit:
	// return our status
    return( nRet );
}

/// Zlib decompress (inflate) the buffer
int __stdcall Zlib_UncompressData( unsigned char* pInBuffer, int nLenSrc, unsigned char* pOutBuffer, int nLenDst )
{
	int nErr = -1;
	int nRet = -1;
    z_stream zInfo = {0};
    zInfo.total_in=  zInfo.avail_in=  nLenSrc;
    zInfo.total_out= zInfo.avail_out= nLenDst;
    zInfo.next_in= (BYTE*)pInBuffer;
    zInfo.next_out= pOutBuffer;	

	// verify input params are valid
	if ( (pInBuffer == NULL) || (nLenSrc == 0) || (pOutBuffer == NULL) || (nLenDst == 0) )
		goto exit;
    
    nErr= inflateInit( &zInfo );               // zlib function
    if ( nErr == Z_OK ) {
        nErr= inflate( &zInfo, Z_FINISH );     // zlib function
        if ( nErr == Z_STREAM_END ) {
            nRet= zInfo.total_out;
        }
    }
    inflateEnd( &zInfo );   // zlib function

exit:
	// return our status
    return( nRet ); // -1 or len of output
}
/**/
/*********************************************************************************************/