// Copyright 2010       anonymous
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
//
//
//	*** ALL CREDIT for the main code behind this tool goes out
//      to the real dev/hackers/etc that made the initial tools
//		behind this tool ***
//
//
//	@revision history
//
//	v1.1.0.0 
//		-- code cleanup, using 'scetool' keys
//		   format, use structure defines, etc
//         using 'sce.lib', from 'scetool' code
//         base
//
//
//  v1.0.0.0 -- initial release
//
//        


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <windows.h>
#include "tools.h"
#include "types.h"
#include "cos.h"
#include "pkg.h"
#include "spkg.h"
#include "pup.h"
#include "sce.h"
#include "tool_structures.h"
#include "file_functions.h"
#include "Zlib_functions.h"



/////////////////////////////////////////
/// update for any changes to this code
#define PKGTOOL_VERSION		"1.1.0.0"
/////////////////////////////////////////


/*** GLOBALS  *****/
//
// array contaning the embedded
// package "file names"

PKG_FILE_NAMES g_pszPkgFileNames = {0};
uint8_t b_DebugModeEnabled = FALSE;
uint8_t b_DefaultKeyListOverride = FALSE;
uint8_t b_NewKeysFilesLoaded = FALSE;
uint8_t b_OverrideFileSize = FALSE;
int32_t g_bZlibCompressLevel = Z_DEFAULT_COMPRESSION;

//
/****	END GLOBALS  *****/


// internal function declars
int select_string(char* pszInString);
void usage (char* pszInParam);



///////////////////////////////////////////////////////////////
/// select_string function ///////
int select_string(char* pszInString)
{
	int i = 0;
	int ret = -1;
	char* params_list[] = {
		"-action",
		"-key",
		"-in",
		"-out",
		"-type",
		"-debug",
		"-zliblevel",
		"-buildnum",
		"-setpkgsize"
	};

	// for loop to iterate through params list
	for (i = 0; i < (sizeof(params_list)/sizeof*params_list); i++)
	{
		if ( strcmp(pszInString, params_list[i]) == 0 ) {
			ret = i;
			break;
		}
	}

	return ret;
}
//
/////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////
//// usage function ///////
void usage (char* pszInParam)
{
	printf("\n\n************************************************\n\n");
	printf("PKGTOOL " PKGTOOL_VERSION " (C) 2013 by anonymous\n\n");	
	printf("************************************************\n\n");

	// idisplay the invalid param (if specified)
	if (pszInParam != NULL)
		printf("\nParameter: \"%s\" is invalid!\n", pszInParam);

	printf("Usage:  PKGTOOL:  -debug  -zliblevel  -action  -key  -type  -buildnum  -setpkgsize  -in  -out\n\n");
	printf("\nexample:\n<pkgtool.exe  -action PKG  -key  pkg-key-retail  -type PKG\n");
	printf("\t-in \"C:\\PS3MFW\\BUILD\\PS3MFW-MFW\\update_files\\CORE_OS_PACKAGE.unpkg\"\n");
	printf("\t-out \"C:\\PS3MFW\\BUILD\\PS3MFW-MFW\\update_files\\CORE_OS_PACKAGE.pkg\">\n\n");

	printf("Arguments:\n");
	printf("---------\n");
	printf("-debug:\t\t** optional **\n");;
	printf("\tYES:\tdebug info enabled\n");
	printf("\tNO:\tdebug info disabled ** default **\n\n");
	printf("-zliblevel:\t** optional **\n");
	printf("\t(-1 to 9): set zlib comp. level\n\n");
	printf("-action:\n");
	printf("\tPKG:\tBuild PKG/SPKG file\n");
	printf("\tUNPKG:\tDecrypt PKG/SPKG file\n");	
	printf("\tPACK:\tPack COS/PUP file\n");	
	printf("\tUNPACK:\tUnpack COS/PUP file\n\n");	
	printf("-key:\t\t** optional **\n\tspecific key file/name to override default key\n\n");	
	printf("-type:\n");
	printf("\tPKG:\ttype of file is \"PKG\" ** default **\n");
	printf("\tSPKG:\ttype of file is \"SPKG\"\n");
	printf("\tCOS:\ttype of file is \"COREOS\"\n");	
	printf("\tPUP:\ttype of file is \"PUP\"\n\n");	
	printf("-buildnum:\t** optional **\n\tbuild number (in dec) of PUP build\n\n");	
	printf("-setpkgsize:\t** optional **\n\tforce file size for pkg/cos creation (in dec)\n\n");
	printf("-in:\tfull path of input file(s)\\dir\n\n");
	printf("-out:\tfull path for output file(s)\\dir\n\n");
	printf("\n   *** Note: ***\n");
	printf("\tdebug mode turns off RNG for keygen\n");
	printf("\t(static 0x11s instead), and dumps file\n");
	printf("\t\"metadata_decrypted\" where tool is executed.\n");
	exit(-1);
}
//
///////////////////////////////////////////////////////////////


int __cdecl main(int argc, char *argv[])
{
	char szAction[MAX_PATH] = {0};
	char szInPath[MAX_PATH] = {0};
	char szOutPath[MAX_PATH] = {0};
	char szKeyName[MAX_PATH] = {0};	
	char szType[MAX_PATH] = {0};	
	u64 qwBuildNumber = 0;
	int i = 0;
	int index = 0;
	uint32_t args_mask = 0;
	uint32_t override_file_size = 0;



	// populate the global struct for the PKG file names
	strcpy_s((char*)&g_pszPkgFileNames.names[0], MAX_PATH, "content");
	strcpy_s((char*)&g_pszPkgFileNames.names[1], MAX_PATH, "info0");
	strcpy_s((char*)&g_pszPkgFileNames.names[2], MAX_PATH, "info1");
	


#ifdef TOOL_DEBUG
	//////////////////////////////// DEFAULT ARGS FOR DEBUG TESTING FROM WITHIN VISUAL STUDIO ////////////////
	//
	//
	// default setup arguments
	b_DebugModeEnabled = TRUE;

	#if defined TOOL_DEBUG_TEST_PKG
	g_bZlibCompressLevel = Z_DEFAULT_COMPRESSION;
	strcpy_s(szType, MAX_PATH, "PKG");
	strcpy_s(szAction, MAX_PATH, "pkg");	
	strcpy_s(szInPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\scratch");
	strcpy_s(szOutPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\scratch\\test_cos.pkg");
	#elif defined TOOL_DEBUG_TEST_SPKG
	g_bZlibCompressLevel = Z_DEFAULT_COMPRESSION;
	strcpy_s(szType, MAX_PATH, "SPKG");
	strcpy_s(szAction, MAX_PATH, "pkg");	
	strcpy_s(szInPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\scratch");
	strcpy_s(szOutPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\scratch\\test.pkg");
	#elif defined TOOL_DEBUG_TEST_UNPKG
	strcpy_s(szType, MAX_PATH, "PKG");
	strcpy_s(szAction, MAX_PATH, "unpkg");	
	strcpy_s(szInPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\VERIFY_FILES\\BLUETOOTH_TEST.pkg");
	strcpy_s(szOutPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\VERIFY_FILES\\BLUETOOTH\\scratch");
	#elif defined TOOL_DEBUG_TEST_UNSPKG
	strcpy_s(szType, MAX_PATH, "SPKG");
	strcpy_s(szAction, MAX_PATH, "unpkg");	
	strcpy_s(szInPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\scratch\\test.pkg.spkg_hdr.1");
	strcpy_s(szOutPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\scratch\\test.pkg.spkg_hdr.1.out");
	#elif defined TOOL_DEBUG_TEST_UNPACK_COS
	strcpy_s(szType, MAX_PATH, "COS");
	strcpy_s(szAction, MAX_PATH, "unpack");	
	strcpy_s(szInPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\CORE_OS_PACKAGE.unpkg\\content_org");
	strcpy_s(szOutPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\CORE_OS_PACKAGE");
	#elif defined TOOL_DEBUG_TEST_PACK_COS
	strcpy_s(szType, MAX_PATH, "COS");
	strcpy_s(szAction, MAX_PATH, "pack");	
	strcpy_s(szInPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\CORE_OS_PACKAGE");
	strcpy_s(szOutPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\CORE_OS_PACKAGE.unpkg\\content_test");	
	#elif defined TOOL_DEBUG_TEST_UNPACK_PUP
	strcpy_s(szType, MAX_PATH, "PUP");
	strcpy_s(szAction, MAX_PATH, "unpack");	
	strcpy_s(szInPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\PS3UPDAT_4.50.PUP");
	strcpy_s(szOutPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\BUILD\\PS3MFW-MFW");
	#elif defined TOOL_DEBUG_TEST_PACK_PUP
	strcpy_s(szType, MAX_PATH, "PUP");
	strcpy_s(szAction, MAX_PATH, "pack");	
	strcpy_s(szInPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\BUILD\\PS3MFW-MFW");
	strcpy_s(szOutPath, MAX_PATH, "C:\\_tools\\PKGTOOL_TEST\\TEST_4.50.PUP");	
	qwBuildNumber = 61890;
	#endif	

	//strcpy_s(szKeyName, MAX_PATH, "pkg-key-retail");	
	//strcpy_s(szKeyName, MAX_PATH, "SPKG-REV000");
	//b_DefaultKeyListOverride = TRUE;
	//b_OverrideFileSize = TRUE;
	//override_file_size = 0x6FFFE0;
	args_mask = 0x01;
		
	//
	//
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
#else

	// assure we have minimum args supplied
	if (argc < 3) {
		usage(NULL);
	}



	////// old code is here!!! ///////////////////

	/////

	///////////////////////		MAIN ARG PARSING LOOP	/////////////////////////////
	//
	//
	for (i = 1; i < argc; i++)
	{
		switch ( index = select_string(argv[i]) ) {

			// "-action" argument
			case 0:
				memset(szAction, 0, MAX_PATH);
				if ( (argv[i+1] == NULL) )
					usage("-action");
				if ( (argv[i+1][0] == '-') || (strlen(argv[i+1]) < 3) || (strlen(argv[i+1]) > 6) )
					usage("-action");
				if ( _stricmp(argv[i+1], "pkg") == 0 )
					strcpy_s(szAction, MAX_PATH, "pkg");
				else if ( _stricmp(argv[i+1], "unpkg") == 0 )
					strcpy_s(szAction, MAX_PATH, "unpkg");
				else if ( _stricmp(argv[i+1], "unpack") == 0 )
					strcpy_s(szAction, MAX_PATH, "unpack");
				else if ( _stricmp(argv[i+1], "pack") == 0 )
					strcpy_s(szAction, MAX_PATH, "pack");
				else 
					usage("-action");				
				i++;
				args_mask |= 0x01;
				break;

			// "-key" argument
			case 1:
				memset(szKeyName, 0, MAX_PATH);
				b_DefaultKeyListOverride = TRUE;
				if ( (argv[i+1] == NULL) )
					usage("-key");
				if ( (argv[i+1][0] == '-') || (strlen(argv[i+1]) <= 1) || (strlen(argv[i+1]) > MAX_PATH) )
					usage("-key");
				strcpy_s(szKeyName, MAX_PATH, argv[i+1]);				
				i++;
				break;		

			// "-in" argument
			case 2:
				memset(szInPath, 0, MAX_PATH);
				if ( (argv[i+1] == NULL) )
					usage("-in");
				if ( (argv[i+1][0] == '-') || (strlen(argv[i+1]) < 1) || (strlen(argv[i+1]) > MAX_PATH) )
					usage("-in");
				strcpy_s(szInPath, MAX_PATH, argv[i+1]);				
				i++;
				break;			

			// "-out" argument
			case 3:
				memset(szOutPath, 0, MAX_PATH);
				if ( (argv[i+1] == NULL) )
					usage("-out");
				if ( (argv[i+1][0] == '-') || (strlen(argv[i+1]) < 1) || (strlen(argv[i+1]) > MAX_PATH) )
					usage("-out");
				strcpy_s(szOutPath, MAX_PATH, argv[i+1]);				
				i++;
				break;	

			// "-type" argument
			case 4:
				memset(szType, 0, MAX_PATH);
				if ( (argv[i+1] == NULL) )
					usage("-type");
				if ( (argv[i+1][0] == '-') || (strlen(argv[i+1]) < 3) || (strlen(argv[i+1]) > 4) )
					usage("-type");
				if ( _stricmp(argv[i+1], "pkg") == 0 )
					strcpy_s(szType, MAX_PATH, "PKG");
				else if ( _stricmp(argv[i+1], "spkg") == 0 )
					strcpy_s(szType, MAX_PATH, "SPKG");
				else if ( _stricmp(argv[i+1], "cos") == 0 )
					strcpy_s(szType, MAX_PATH, "COS");
				else if ( _stricmp(argv[i+1], "pup") == 0 )
					strcpy_s(szType, MAX_PATH, "PUP");
				else 
					usage("-type");				
				i++;
				break;	

			// "-debug" argument
			case 5:				
				if ( (argv[i+1] == NULL) )
					usage("-debug");
				if ( (argv[i+1][0] == '-') || (strlen(argv[i+1]) < 2) || (strlen(argv[i+1]) > 3) )
					usage("-debug");
				if ( _stricmp(argv[i+1], "yes") == 0 )
					b_DebugModeEnabled = TRUE;
				else if ( _stricmp(argv[i+1], "no") == 0 )
					b_DebugModeEnabled = FALSE;
				else 
					usage("-debug");				
				i++;
				break;	

			// "-zliblevel" argument
			case 6:				
				if ( (argv[i+1] == NULL) )
					usage("-zliblevel");
				if ( (argv[i+1][0] == '-') || (strlen(argv[i+1]) < 1) || (strlen(argv[i+1]) > 2) )
					usage("-zliblevel");
				g_bZlibCompressLevel = atoi(argv[i+1]);
				if (g_bZlibCompressLevel > 9)
					usage("-zliblevel");					
				i++;
				break;	

			// "-buildnum" argument
			case 7:				
				if ( (argv[i+1] == NULL) )
					usage("-buildnum");
				if ( (argv[i+1][0] == '-') || (strlen(argv[i+1]) < 1) || (strlen(argv[i+1]) > 20) )
					usage("-buildnum");
				qwBuildNumber = atoi(argv[i+1]);
				if (qwBuildNumber == 0)
					usage("-buildnum");						
				i++;
				break;	

			// "-setpkgsize" argument
			case 8:				
				if ( (argv[i+1] == NULL) )
					usage("-setpkgsize");
				if ( (argv[i+1][0] == '-') || (strlen(argv[i+1]) < 1) || (strlen(argv[i+1]) > 20) )
					usage("-setpkgsize");
				override_file_size = atoi(argv[i+1]);				
				if (override_file_size == 0)
					usage("-setpkgsize");						
				b_OverrideFileSize = TRUE;
				i++;
				break;

			default:
				printf("\nINVALID parameter specified:%s!\n", argv[i]);
				usage(NULL);
				break;

		} // end switch{}
	}
	//
	/////////////////////////////////////////////////////////////////////////////////////////

#endif

	/////			PACKAGE 'BUILD' ROUTINE										/////////////
	///
	//	
	printf("\n\n************************************************\n\n");
	printf("PKGTOOL " PKGTOOL_VERSION " (C) 2013 by anonymous\n\n");	
	printf("************************************************\n\n");
	//printf("(credit goes to failoverflow, Evilnat, everyone else!)");


	// make sure min. arg of "-action" and param specified
	if ( (args_mask & 0x01) == 0) {
		printf("\nError!  min. arguments not specified!\n");
		usage("-action");
	}

	/* --------------------------------------------------------- */
	/*                                                           */
	// print out some optonal settings
	if ( b_DebugModeEnabled == TRUE )
		printf("   ---- DEBUG mode: enabled\n");
	else
		printf("   ---- DEBUG mode: disabled\n");
	if (g_bZlibCompressLevel == (int32_t)-1)
		printf("   ---- Zlib Compress level:Z_DEFAULT_COMPRESSION(-1)\n\n");
	else
		printf("   ---- Zlib Compress level:%d\n\n", g_bZlibCompressLevel);
	/*                                                           */
	/* --------------------------------------------------------- */


	/* -------------------------------------------  */
	/*			ATTEMPT TO LOAD THE 'NEW'			*/
	/*			KEYS FILES							*/

	if ( load_keys_files() != STATUS_SUCCESS ) {
		printf("Warning:  Unable to load the \"scetool\" compatible keys/curves/vshcurves files, \
			   \ndefaulting to old keys format....\n");
	}


	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//																													//
	//											PACKAGE SECTION															//
	//	
	// "package" operation for "PKG" or "SPKG"  types
	// ("pkg" will ONLY build the ".pkg" file, whereas "spkg" type will
	//  build the ".pkg" and the "spkg_hdr.1" files)
	if ( _stricmp(szAction, "pkg") == 0 ) 
	{		
		/// package the "PKG" types ///
		if ( (_stricmp(szType, "PKG") == 0) || (_stricmp(szType, "SPKG") == 0) ) 
		{			
			// now go and create the package file
			if ( do_pkg_create(szInPath, szOutPath, szType, szKeyName, override_file_size) != STATUS_SUCCESS ) {
				printf("Failed to create .pkg file, exiting....\n");
				goto exit;
			}
			
			// done "PKG" action
			printf("\n...%s packaging complete!\n", szType);

		}// end if type == PKG
		else {
			printf("!!ERROR!! Unsupported type:%s for %s operation!\n", szType, szAction);
			goto exit;
		}		
		
	} 
	//																													//
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//																													//
	//											UN-PACKAGE SECTION														//
	//																													//
	else if ( _stricmp(szAction, "unpkg") == 0) 
	{
		/// Unpackage the "PKG" types ///
		if ( _stricmp(szType, "PKG") == 0 ) 
		{		
			// now go and decrypt the PKG (package)
			if ( do_pkg_decrypt(szInPath, szOutPath, szKeyName) != STATUS_SUCCESS ) {
				printf("Failed to unpackage .pkg file, exiting....\n");
				goto exit;		
			}
		}
		// case for "UN-PACKAGING" SPKG files
		else if ( _stricmp(szType, "SPKG") == 0 )
		{
			// now go and decrypt the SPKG (package)
			if ( do_spkg_decrypt(szInPath, szOutPath, szKeyName) != STATUS_SUCCESS ) {
				printf("Failed to unpackage .spkg file, exiting....\n");
				goto exit;		
			}
		}
		else {
			printf("!!ERROR!! Unsupported type:%s for %s operation!\n", szType, szAction);
			goto exit;
		}

		// SUCCESS!  Done!
		printf("\n...%s unpackaging complete!\n", szType);

	} // end "unpkg" section
	//																											//
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////


	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//																													//
	//											UN-PACK SECTION															//
	//	
	else if ( _stricmp(szAction, "unpack") == 0) 
	{
		// case for unpacking "CORE OS" files
		if ( _stricmp(szType, "COS") == 0 )
		{
			if ( do_unpack_cos_package(szInPath, szOutPath) != STATUS_SUCCESS ) {
				printf("Failed to unpackage COS file, exiting....\n");
				goto exit;	
			}
		}
		// case for unpacking "PUP" files
		else if ( _stricmp(szType, "PUP") == 0 )
		{
			if ( do_pup_unpack(szInPath, szOutPath) != STATUS_SUCCESS ) {
				printf("Failed to unpackage PUP file, exiting....\n");
				goto exit;	
			}
		}
		else {
			printf("!!ERROR!! Unsupported type:%s for %s operation!\n", szType, szAction);
			goto exit;
		}

		// SUCCESS!  Done!
		printf("\n...%s unpacking Complete!\n", szType);
		
	} // end of "UNPACK" section
	//																													//
	//																													//
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//																													//
	//											PACK SECTION															//
	//	
	else if ( _stricmp(szAction, "pack") == 0) 
	{
		// case for packing "COS" files
		if ( _stricmp(szType, "COS") == 0 )
		{
			// go and "pack" up the COS package
			if ( create_cos_pkg(szInPath, szOutPath, override_file_size) != STATUS_SUCCESS ) {
				printf("failed to pack cos file:%s\n", szInPath);
				goto exit;
			}			
		}
		// case for packing "PUP files
		else if ( _stricmp(szType, "PUP") == 0 )
		{
			// go and pack the PUP file
			if ( do_pup_pack(szInPath, szOutPath, qwBuildNumber) != STATUS_SUCCESS ) {
				printf("Failed to create/pack PUP file, exiting!\n");
				goto exit;
			}
		}
		else {
			printf("!!ERROR!! Unsupported type:%s for %s operation!\n", szType, szAction);
			goto exit;
		}

		// SUCCESS!  Done!
		printf("\n...%s packing complete!\n", szType);

	} // end of "pack" section
	//																													//
	//																													//
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	
exit:		

	return 0;
}
/**/
/********************************************************************************************************/
