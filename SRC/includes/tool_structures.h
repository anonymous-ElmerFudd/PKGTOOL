// Copyright 2010       anonymous
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt


#ifndef TOOL_STRUCTS_H__
#define TOOL_STRUCTS_H__

#include "unistd.h"
#include "stdint.h"
#include "types.h"
#include "sce.h"



#ifdef __cplusplus
extern "C" {
#endif



#ifndef MAX_PATH
#define MAX_PATH						260
#endif
		


#define AES256_KEY_SIZE					0x20			// 256-bits
#define AES128_KEY_SIZE					0x10			// 128-bits
#define HMAC_KEY_SIZE					0x40			// 512-bits
#define SPP_HMAC_KEY_SIZE				0x20			// 256-bits


/*  DEFAULT CONFIG SETTINGS FROM 'SCETOOL' */
#define DEFAULT_PS3KEYS_ENV				"PS3_KEYS"
/*! Path configurations. */
#define CONFIG_KEYS_FILE				"keys"
#define CONFIG_KEYS_PATH				"./data"
#define CONFIG_CURVES_FILE				"ldr_curves"
#define CONFIG_CURVES_PATH				"./data"
#define CONFIG_VSH_CURVES_FILE			"vsh_curves"
#define CONFIG_VSH_CURVES_PATH			"./data"



#pragma warning (push)
#pragma warning (disable: 4201)
#pragma warning (disable: 4214)


/**************************************************************/
/**************************************************************/
/*				ECDSA STRUCTURES							  */


#define ECDSA_KEYSIZE					0x14			// 160-bits

typedef struct _my_ecp_point {
	u8 x[ECDSA_KEYSIZE];
	u8 y[ECDSA_KEYSIZE];
} my_ecp_point;

/*                                                           */
/*************************************************************/
/**************************************************************/




/**************************************************************/
/**************************************************************/
/*				PUP STRUCTURES								  */

#define PUP_SCE_HEADER_STRING			"SCEUF\0\0\0"
#define PUP_SCE_HEADER_MAGIC			0x53434555		// SCEUF
#define	PUP_MAX_FILES					10
#define PUP_HMAC_RESULT_SIZE			0x14			// 160-bits
#define PUP_KEYS_ENTRY_NAME				"PUP_hmac_key"


// struct define for the PUP HDR
// 0x30 size
typedef struct _SCE_PUP_HDR {
	u64 magic;											// sce header magic (SCEUF)
	u64 key_revision;									// unsure???
	u64 pup_build_number;								// PUP build number
	u64 num_sections;									// number of sections
	u64 header_size;									// size of this meta header
	u64 data_size;										// size of the data section
} SCE_PUP_HDR;

// struct define for the pup section hdr
// 0x20 size
typedef struct _SCE_PUP_SECTION_HDR {
	u64 entry;											// entry ID in the file name table
	u64 offset;											// offset
	u64 size;											// size of this section
	u64 unknown;										// unknown ??
} SCE_PUP_SECTION_HDR;

// struct define for the pup file record
// 0x40 size
typedef struct _SCE_PUP_FILE_RECORD {
	u64 id;												// file ID num
	u64 offset;											// offset
	u64 len;											// len of the file data
	u64 unknown0;										// unknown ??
	u64 unknown1;										// unknown ??
	u64 unknown2;										// unknown ??
	u64 unknown3;										// unknown ??
	u64 unknown4;										// unknown ??
} SCE_PUP_FILE_RECORD;
/*                                                           */
/*************************************************************/
/**************************************************************/



/**************************************************************/
/**************************************************************/
/*				COS STRUCTURES								  */

#define	COS_MAX_FILES					255
#define SIZE_COSPKG_FILERECORD_FILENAME	0x20


// struct defines for the COS PKG
// size 0x10
typedef struct _COS_PKG_HDR {
	u32 magic;											// magic signature
	u32 num_files;										// number of files within
	u64 file_size;										// total size of cos pkg
} COS_PKG_HDR;

// struct define for the COS FILE RECORD
// size 0x14
typedef struct _COS_PKG_FILE_RECORD {
	u64 raw_offset;										// raw offset into file	
	u64 file_size;										// total size of file
	char file_name[SIZE_COSPKG_FILERECORD_FILENAME];	// ASCII name of file
} COS_PKG_FILE_RECORD;
/*                                                           */
/*************************************************************/
/**************************************************************/




/**************************************************************/
/**************************************************************/
/*				PKG/SPKG STRUCTURES							  */

#define SIZE_SPKG_HDR					0x280	

#define SPKG_HDR_NAME					".spkg_hdr.1"


#define NUM_PKG_EMBEDDED_FILES			0x03						// num. of expected "files" to extract from a PKG file
#define NUM_SPKG_METADATA_SECTIONS		0x03						// num. of expected metadata sections in an SPKG
#define SIZE_INFO_FILES					sizeof(metadata_info_t)		// INFO_FILES are actually just a copy of the "metadata_info" (KEYS/IV)
																	// in the sce headers

typedef struct _PKG_HEADER_STRUCT {
	sce_header_t	sce_header;							// initial SCE header
	metadata_info_t metadata_info_header;				// metadata_info header (metadata keys/ivs)
	metadata_header_t metadata_header;					// metadata header (key count, hdr size, etc)
} PKG_HEADER_STRUCT;


typedef struct _PKG_FILE_RECORD {
	u64 raw_offset;										// raw offset into file	
	u64 file_size;										// total size of file
	u64 unknown1;										// unknown 1
	u64 unknown2;										// unknown 2
	u64 unknown3;										// unknown 3
	u64 unknown4;										// unknown 4
} PKG_FILE_RECORD;

typedef struct _INFO_FILE_HEADER {	
	sce_version_t sce_version;							// "SCE Version" structure
	u32 app_version;									// application version
	u32 unknown0;
	u64 file_size_external;								// extracted size of the file
	u64 file_size_internal;								// internal (pkg'd) size of the file
	u32 unknown1;
	u32 unknown2;
	u64 unknown3;
	u64 unknown4;
} INFO_FILE_RECORD;

////////////////////////////////////////
// struct for storing the names of the
// actual embedded PKG file names
typedef struct _FILENAME_STRING {
	char FileName[MAX_PATH];
} FILENAME_STRING;

typedef struct _PKG_FILE_NAMES {
	struct {
		FILENAME_STRING names[NUM_PKG_EMBEDDED_FILES];
	};
} PKG_FILE_NAMES;

/*                                                           */
/**************************************************************/
/*************************************************************/


// meta_hdr size for PKG
typedef struct _META_HDR {
	char data[0x260];
} META_HDR;


// meta_hdr size for SPP
typedef struct _SPP_META_HDR {
	char data[0x1E0];
} SPP_META_HDR;

// struct def. for total SPKG size
typedef struct _SPKG_STRUCT {
	char data[SIZE_SPKG_HDR];
} SPKG_STRUCT;

#pragma warning (pop)



#ifdef __cplusplus
}
#endif


#endif
// endif TOOL_STRUCTS_H__
