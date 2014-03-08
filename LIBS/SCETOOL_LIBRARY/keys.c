/*
* Copyright (c) 2011-2013 by naehrwert
* Copyright (c) 2012 by flatz
* This file is released under the GPLv2.
*/

#include <stdlib.h>
#include <string.h>

#include "types.h"
#include <sys/stat.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "config.h"
#include "types.h"
#include "list.h"
#include "sce.h"
#include "keys.h"
#include "util.h"
#include "tables.h"
#include "aes.h"

/*
[keyname]
type={SELF, RVK, PKG, SPP, OTHER}
revision={00, ..., 18, 8000}
version={..., 0001000000000000, ...}
self_type={LV0, LV1, LV2, APP, ISO, LDR, UNK_7, NPDRM}
key=...
erk=...
riv=...
pub=...
priv=...
ctype=...
*/

/*! Loaded keysets. */
list_t *_keysets = NULL;
/*! Loaded curves. */
curve_t *_curves = NULL;
/*! Loaded VSH curves. */
vsh_curve_t *_vsh_curves = NULL;

static u8 rap_init_key[0x10] = 
{
	0x86, 0x9F, 0x77, 0x45, 0xC1, 0x3F, 0xD8, 0x90, 0xCC, 0xF2, 0x91, 0x88, 0xE3, 0xCC, 0x3E, 0xDF
};

static u8 rap_pbox[0x10] = 
{
	0x0C, 0x03, 0x06, 0x04, 0x01, 0x0B, 0x0F, 0x08, 0x02, 0x07, 0x00, 0x05, 0x0A, 0x0E, 0x0D, 0x09
};

static u8 rap_e1[0x10] = 
{
	0xA9, 0x3E, 0x1F, 0xD6, 0x7C, 0x55, 0xA3, 0x29, 0xB7, 0x5F, 0xDD, 0xA6, 0x2A, 0x95, 0xC7, 0xA5
};

static u8 rap_e2[0x10] = 
{
	0x67, 0xD4, 0x5D, 0xA3, 0x29, 0x6D, 0x00, 0x6A, 0x4E, 0x7C, 0x53, 0x7B, 0xF5, 0x53, 0x8C, 0x74
};

static void __stdcall _fill_property(keyset_t *ks, s8 *prop, s8 *value)
{
	if(strcmp(prop, "type") == 0)
	{
		if(strcmp(value, "SELF") == 0)
			ks->type = KEYTYPE_SELF;
		else if(strcmp(value, "RVK") == 0)
			ks->type = KEYTYPE_RVK;
		else if(strcmp(value, "PKG") == 0)
			ks->type = KEYTYPE_PKG;
		else if(strcmp(value, "SPP") == 0)
			ks->type = KEYTYPE_SPP;
		else if(strcmp(value, "OTHER") == 0)
			ks->type = KEYTYPE_OTHER;
		else
			printf("[*] Error: Unknown type '%s'.\n", value);
	}
	else if(strcmp(prop, "revision") == 0)
		ks->key_revision = (u16)_x_to_u64(value);
	else if(strcmp(prop, "version") == 0)
		ks->version = _x_to_u64(value);
	else if(strcmp(prop, "self_type") == 0)
	{
		if(strcmp(value, "LV0") == 0)
			ks->self_type = SELF_TYPE_LV0;
		else if(strcmp(value, "LV1") == 0)
			ks->self_type = SELF_TYPE_LV1;
		else if(strcmp(value, "LV2") == 0)
			ks->self_type = SELF_TYPE_LV2;
		else if(strcmp(value, "APP") == 0)
			ks->self_type = SELF_TYPE_APP;
		else if(strcmp(value, "ISO") == 0)
			ks->self_type = SELF_TYPE_ISO;
		else if(strcmp(value, "LDR") == 0)
			ks->self_type = SELF_TYPE_LDR;
		else if(strcmp(value, "UNK_7") == 0)
			ks->self_type = SELF_TYPE_UNK_7;
		else if(strcmp(value, "NPDRM") == 0)
			ks->self_type = SELF_TYPE_NPDRM;
		else
			printf("[*] Error: unknown SELF type '%s'.\n", value);
	}
	else if(strcmp(prop, "erk") == 0 || strcmp(prop, "key") == 0)
	{
		ks->erk = _x_to_u8_buffer(value);
		ks->erklen = strlen(value) / 2;
	}
	else if(strcmp(prop, "riv") == 0)
	{
		ks->riv = _x_to_u8_buffer(value);
		ks->rivlen = strlen(value) / 2;
	}
	else if(strcmp(prop, "pub") == 0)
		ks->pub = _x_to_u8_buffer(value);
	else if(strcmp(prop, "priv") == 0)
		ks->priv = _x_to_u8_buffer(value);
	else if(strcmp(prop, "ctype") == 0)
		ks->ctype = (u8)_x_to_u64(value);
	else
		printf("[*] Error: Unknown keyfile property '%s'.\n", prop);
}

static s64 __stdcall _compare_keysets(keyset_t *ks1, keyset_t *ks2)
{
	s64 res;

	if((res = (s64)ks1->version - (s64)ks2->version) == 0)
		res = (s64)ks1->key_revision - (s64)ks2->key_revision;

	return res;
}

static void __stdcall _sort_keysets()
{
	u32 i = 0;
	u32 to = 0;
	lnode_t* max = NULL;
	lnode_t* iter = NULL;
	list_t* tmp = NULL;



	// exit if keylist is not setup
	if (_keysets == NULL)
		goto exit;
	
	i = to = _keysets->count;
	tmp = list_create();
	for(i = 0; i < to; i++)
	{
		max = _keysets->head;
//		LIST_FOREACH(iter, _keysets)
		for(iter = _keysets->head; iter != NULL; iter = iter->next)
		{
			if(_compare_keysets((keyset_t *)max->value, (keyset_t *)iter->value) < 0)
				max = iter;
		}
		list_push(tmp, max->value);
		list_remove_node(_keysets, max);
	}

	list_destroy(&_keysets);
	_keysets = tmp;

exit:
	return;
}

void __stdcall _print_key_list(FILE *fp)
{
	const s8 *name = NULL;
	s32 len = 0;
	s32 tmp = 0;
	lnode_t* iter = NULL;

	// exit if keylist is not setup
	if (_keysets == NULL) {
		printf("\nKeylist is empty!, no keys to print!\n");
		goto exit;
	}


//	LIST_FOREACH(iter, _keysets)
	for(iter = _keysets->head; iter != NULL; iter = iter->next)
	{
		if((tmp = strlen(((keyset_t *)iter->value)->name)) > len)
			len = tmp;
	}

	fprintf(fp, " Name");
	_print_align(fp, " ", len, 4);
	fprintf(fp, " Type  Revision Version SELF-Type\n");

//	LIST_FOREACH(iter, _keysets)
	for(iter = _keysets->head; iter != NULL; iter = iter->next)
	{
		keyset_t *ks = (keyset_t *)iter->value;
		fprintf(fp, " %s", ks->name);
		_print_align(fp, " ", len, strlen(ks->name));
		fprintf(fp, " %-5s 0x%04X   %s   ", _get_name(_key_types, ks->type), ks->key_revision, sce_version_to_str(ks->version));
		if(ks->type == KEYTYPE_SELF)
		{
			name = _get_name(_self_types, ks->self_type);
			if(name != NULL)
				fprintf(fp, "[%s]\n", name);
			else
				fprintf(fp, "0x%08X\n", ks->self_type);
		}
		else
			fprintf(fp, "\n");
	}

exit:
	return;
}

#define LINEBUFSIZE 512
BOOL __stdcall keys_load(const s8 *kfile)
{
	u32 i = 0, lblen = 0;
	FILE *fp = NULL;
	s8 lbuf[LINEBUFSIZE] = {0};
	keyset_t *cks = NULL;



	// create the initial list
	if((_keysets = list_create()) == NULL)
		return FALSE;

	if((fp = fopen(kfile, "r")) == NULL)
	{
		list_destroy(&_keysets);
		return FALSE;
	}

	do
	{
		//Get next line.
		lbuf[0] = 0;
		fgets(lbuf, LINEBUFSIZE, fp);
		lblen = strlen(lbuf);

		//Don't parse empty lines (ignore '\n') and comment lines (starting with '#').
		if(lblen > 1 && lbuf[0] != '#')
		{
			//Remove '\n'.
			lbuf[lblen-1] = 0;

			//Check for keyset entry.
			if(lblen > 2 && lbuf[0] == '[')
			{
				if(cks != NULL)
				{
					//Add to keyset list.
					list_push(_keysets, cks);
					cks = NULL;
				}

				//Find name end.
				for(i = 0; lbuf[i] != ']' && lbuf[i] != '\n' && i < lblen; i++);
				lbuf[i] = 0;

				//Allocate keyset and fill name.
				cks = (keyset_t *)calloc(sizeof(keyset_t), sizeof(char));
				memset(cks, 0, sizeof(keyset_t));
				cks->name = _strdup(&lbuf[1]);
			}
			else if(cks != NULL)
			{
				//Find property name end.
				for(i = 0; lbuf[i] != '=' && lbuf[i] != '\n' && i < lblen; i++);
				lbuf[i] = 0;

				//Fill property.
				_fill_property(cks, &lbuf[0], &lbuf[i+1]);
			}
		}
	} while(!feof(fp));

	//Add last keyset to keyset list.
	if(cks != NULL)
		list_push(_keysets, cks);

	//Sort keysets.
	_sort_keysets();

	return TRUE;
}
#undef LINEBUFSIZE

keyset_t* __stdcall _keyset_find_for_self(u32 self_type, u16 key_revision, u64 version)
{
	lnode_t* iter = NULL;



	// exit if keylist is not setup
	if (_keysets == NULL) {
		printf("\nKeyList is empty!\n");
		goto exit;
	}

//	LIST_FOREACH(iter, _keysets)
	for(iter = _keysets->head; iter != NULL; iter = iter->next)
	{
		keyset_t *ks = (keyset_t *)iter->value;
		if(ks->self_type == self_type)
		{
			switch(self_type)
			{
			case SELF_TYPE_LV0:
				return ks;
				break;
			case SELF_TYPE_LV1:
				if(version <= ks->version)
					return ks;
				break;
			case SELF_TYPE_LV2:
				if(version <= ks->version)
					return ks;
				break;
			case SELF_TYPE_APP:
				if(key_revision == ks->key_revision)
					return ks;
				break;
			case SELF_TYPE_ISO:
				if(version <= ks->version && key_revision == ks->key_revision)
					return ks;
				break;
			case SELF_TYPE_LDR:
				return ks;
				break;
			case SELF_TYPE_NPDRM:
				if(key_revision == ks->key_revision)
					return ks;
				break;
			}
		}
	}

exit:
	return NULL;
}

keyset_t* __stdcall _keyset_find_for_rvk(u32 key_revision)
{
	keyset_t *ks = NULL;
	lnode_t* iter = NULL;


	// exit if keylist is not setup
	if (_keysets == NULL) {
		printf("\nKeyList is empty!\n");
		goto exit;
	}

//	LIST_FOREACH(iter, _keysets)
	for(iter = _keysets->head; iter != NULL; iter = iter->next)
	{
		ks = (keyset_t*)iter->value;
		if(ks->type == KEYTYPE_RVK && key_revision <= ks->key_revision)
			return ks;
	}

exit:
	return NULL;
}

keyset_t* __stdcall _keyset_find_for_pkg(u16 key_revision)
{
	keyset_t *ks = NULL;
	lnode_t* iter = NULL;


	// exit if keylist is not setup
	if (_keysets == NULL) {
		printf("\nKeyList is empty!\n");
		goto exit;
	}

//	LIST_FOREACH(iter, _keysets)
	for(iter = _keysets->head; iter != NULL; iter = iter->next)
	{
		ks = (keyset_t*)iter->value;
		if(ks->type == KEYTYPE_PKG && key_revision <= ks->key_revision)
			return ks;
	}

exit:
	return NULL;
}

keyset_t* __stdcall _keyset_find_for_spp(u16 key_revision)
{
	keyset_t *ks = NULL;
	lnode_t* iter = NULL;


	// exit if keylist is not setup
	if (_keysets == NULL) {
		printf("\nKeyList is empty!\n");
		goto exit;
	}

//	LIST_FOREACH(iter, _keysets)
	for(iter = _keysets->head; iter != NULL; iter = iter->next)
	{
		ks = (keyset_t*)iter->value;
		if(ks->type == KEYTYPE_SPP && key_revision <= ks->key_revision)
			return ks;
	}

exit:
	return NULL;
}

keyset_t* __stdcall keyset_find(sce_buffer_ctxt_t *ctxt)
{
	keyset_t*res = NULL;

	switch(ctxt->sceh->header_type)
	{
	case SCE_HEADER_TYPE_SELF:
		res = _keyset_find_for_self(ctxt->self.ai->self_type, ctxt->sceh->key_revision, ctxt->self.ai->version);
		break;
	case SCE_HEADER_TYPE_RVK:
		res = _keyset_find_for_rvk(ctxt->sceh->key_revision);
		break;
	case SCE_HEADER_TYPE_PKG:
		res = _keyset_find_for_pkg(ctxt->sceh->key_revision);
		break;
	case SCE_HEADER_TYPE_SPP:
		res = _keyset_find_for_spp(ctxt->sceh->key_revision);
		break;
	}

	if(res == NULL)
		printf("[*] Error: Could not find keyset for %s.\n", _get_name(_sce_header_types, ctxt->sceh->header_type));

	return res;
}

keyset_t* __stdcall keyset_find_by_name(const s8 *name)
{
	lnode_t* iter = NULL;
	keyset_t *ks = NULL;


	// exit if keylist is not setup
	if (_keysets == NULL) {
		printf("\nKeyList is empty!\n");
		goto exit;
	}

//	LIST_FOREACH(iter, _keysets)
	for(iter = _keysets->head; iter != NULL; iter = iter->next)
	{
		ks = (keyset_t*)iter->value;
		if(strcmp(ks->name, name) == 0)
			return ks;
	}

	printf("[*] Error: Could not find keyset '%s'.\n", name);

exit:	
	return NULL;
}

BOOL __stdcall curves_load(const s8 *cfile)
{
	u32 len = 0;

	_curves = (curve_t *)_read_buffer(cfile, &len);
	
	if(_curves == NULL)
		return FALSE;
	
	if(len != CURVES_LENGTH)
	{
		free(_curves);
		return FALSE;
	}
	
	return TRUE;
}

curve_t* __stdcall curve_find(u8 ctype)
{
	// exit if _curves is not setup
	if (_curves == NULL) {
		printf("\nCurves is empty!\n");
		goto exit;
	}
	if(ctype > CTYPE_MAX)
		goto exit;

	// return the curves data
	return &_curves[ctype];

exit:
	return NULL;
}

BOOL __stdcall vsh_curves_load(const s8 *cfile)
{
	u32 len = 0;

	_vsh_curves = (vsh_curve_t *)_read_buffer(cfile, &len);
	
	if(_vsh_curves == NULL)
		return FALSE;
	
	if(len != VSH_CURVES_LENGTH)
	{
		free(_vsh_curves);
		return FALSE;
	}
	
	return TRUE;
}

static curve_t _tmp_curve;
curve_t* __stdcall vsh_curve_find(u8 ctype)
{

	// exit if _curves is not setup
	if (_vsh_curves == NULL) {
		printf("\vsh_curves is empty!\n");
		goto exit;
	}
	if(ctype > VSH_CTYPE_MAX)
		goto exit;

	_memcpy_inv(_tmp_curve.p, _vsh_curves[ctype].p, 20);
	_memcpy_inv(_tmp_curve.a, _vsh_curves[ctype].a, 20);
	_memcpy_inv(_tmp_curve.b, _vsh_curves[ctype].b, 20);
	_tmp_curve.N[0] = ~0x00;
	_memcpy_inv(_tmp_curve.N+1, _vsh_curves[ctype].N, 20);
	_memcpy_inv(_tmp_curve.Gx, _vsh_curves[ctype].Gx, 20);
	_memcpy_inv(_tmp_curve.Gy, _vsh_curves[ctype].Gx, 20);

	return &_tmp_curve;

exit:
	return NULL;
}

static u8* __stdcall idps_load()
{
	s8 *ps3 = NULL, path[256];
	u8 *idps;
	u32 len = 0;

	if((ps3 = getenv(CONFIG_ENV_PS3)) != NULL)
		if(_access_s(ps3, 0) != 0)
			ps3 = NULL;

	if(ps3 != NULL)
	{
		sprintf(path, "%s/%s", ps3, CONFIG_IDPS_FILE);
		if(_access_s(path, 0) != 0)
			sprintf(path, "%s/%s", CONFIG_IDPS_PATH, CONFIG_IDPS_FILE);
	}
	else
		sprintf(path, "%s/%s", CONFIG_IDPS_PATH, CONFIG_IDPS_FILE);

	idps = (u8 *)_read_buffer(path, &len);
	
	if(idps == NULL)
		return NULL;
	
	if(len != IDPS_LENGTH)
	{
		free(idps);
		return NULL;
	}
	
	return idps;
}

static act_dat_t* __stdcall act_dat_load()
{
	s8 *ps3 = NULL, path[256];
	act_dat_t *act_dat;
	u32 len = 0;
	
	if((ps3 = getenv(CONFIG_ENV_PS3)) != NULL)
		if(_access_s(ps3, 0) != 0)
			ps3 = NULL;

	if(ps3 != NULL)
	{
		sprintf(path, "%s/%s", ps3, CONFIG_ACT_DAT_FILE);
		if(_access_s(path, 0) != 0)
			sprintf(path, "%s/%s", CONFIG_ACT_DAT_PATH, CONFIG_ACT_DAT_FILE);
	}
	else
		sprintf(path, "%s/%s", CONFIG_ACT_DAT_PATH, CONFIG_ACT_DAT_FILE);

	act_dat = (act_dat_t *)_read_buffer(path, &len);
	
	if(act_dat == NULL)
		return NULL;
	
	if(len != ACT_DAT_LENGTH)
	{
		free(act_dat);
		return NULL;
	}
	
	return act_dat;
}

static rif_t* __stdcall rif_load(const s8 *content_id)
{
	s8 *ps3 = NULL, path[256];
	rif_t *rif;
	u32 len = 0;
	
	if((ps3 = getenv(CONFIG_ENV_PS3)) != NULL)
		if(_access_s(ps3, 0) != 0)
			ps3 = NULL;

	if(ps3 != NULL)
	{
		sprintf(path, "%s/%s%s", ps3, content_id, CONFIG_RIF_FILE_EXT);
		if(_access_s(path, 0) != 0)
			sprintf(path, "%s/%s%s", CONFIG_RIF_PATH, content_id, CONFIG_RIF_FILE_EXT);
	}
	else
		sprintf(path, "%s/%s%s", CONFIG_RIF_PATH, content_id, CONFIG_RIF_FILE_EXT);

	rif = (rif_t *)_read_buffer(path, &len);
	if(rif == NULL)
		return NULL;
	
	if(len < RIF_LENGTH)
	{
		free(rif);
		return NULL;
	}
	
	return rif;
}

static u8* __stdcall rap_load(const s8 *content_id)
{
	s8 *ps3 = NULL, path[256];
	u8 *rap;
	u32 len = 0;
	
	if((ps3 = getenv(CONFIG_ENV_PS3)) != NULL)
		if(_access_s(ps3, 0) != 0)
			ps3 = NULL;

	if(ps3 != NULL)
	{
		sprintf(path, "%s/%s%s", ps3, content_id, CONFIG_RAP_FILE_EXT);
		if(_access_s(path, 0) != 0)
			sprintf(path, "%s/%s%s", CONFIG_RAP_PATH, content_id, CONFIG_RAP_FILE_EXT);
	}
	else
		sprintf(path, "%s/%s%s", CONFIG_RAP_PATH, content_id, CONFIG_RAP_FILE_EXT);

	rap = (u8 *)_read_buffer(path, &len);
	
	if(rap == NULL)
		return NULL;
	
	if(len != RAP_LENGTH)
	{
		free(rap);
		return NULL;
	}
	
	return rap;
}

static BOOL __stdcall rap_to_klicensee(const s8 *content_id, u8 *klicensee)
{
	u8 *rap = NULL;
	aes_context aes_ctxt = {0};
	int round_num = 0;
	int i = 0;
	u8 kc = 0;
	u8 ec2 = 0;
	int o = 0;
	int p = 0;
	int pp = 0;



	rap = rap_load(content_id);
	if(rap == NULL)
		return FALSE;

	aes_setkey_dec(&aes_ctxt, rap_init_key, RAP_KEYBITS);
	aes_crypt_ecb(&aes_ctxt, AES_DECRYPT, rap, rap);

	for (round_num = 0; round_num < 5; ++round_num)
	{
		for (i = 0; i < 16; ++i)
		{
			int p = rap_pbox[i];
			rap[p] ^= rap_e1[p];
		}
		for (i = 15; i >= 1; --i)
		{
			p = rap_pbox[i];
			pp = rap_pbox[i - 1];
			rap[p] ^= rap[pp];
		}
		o = 0;
		for (i = 0; i < 16; ++i)
		{
			p = rap_pbox[i];
			kc = rap[p] - o;
			ec2 = rap_e2[p];
			if (o != 1 || kc != 0xFF)
			{
				o = kc < ec2 ? 1 : 0;
				rap[p] = kc - ec2;
			}
			else if (kc == 0xFF)
				rap[p] = kc - ec2;
			else
				rap[p] = kc;
		}
	}

	memcpy(klicensee, rap, RAP_LENGTH);
	free(rap);

	return TRUE;
}

BOOL __stdcall klicensee_by_content_id(const s8 *content_id, u8 *klicensee)
{
	aes_context aes_ctxt;

	if(rap_to_klicensee(content_id, klicensee) == FALSE)
	{
		keyset_t *ks_np_idps_const, *ks_np_rif_key;
		rif_t *rif;
		u8 idps_const[0x10];
		u8 act_dat_key[0x10];
		u32 act_dat_key_index;
		u8 *idps;
		act_dat_t *act_dat;

		if((idps = idps_load()) == NULL)
		{
			printf("[*] Error: Could not load IDPS.\n");
			return FALSE;
		}
		else
			_LOG_VERBOSE("IDPS loaded.\n");

		if((act_dat = act_dat_load()) == NULL)
		{
			printf("[*] Error: Could not load act.dat.\n");
			return FALSE;
		}
		else
			_LOG_VERBOSE("act.dat loaded.\n");

		ks_np_idps_const = keyset_find_by_name(CONFIG_NP_IDPS_CONST_KNAME);
		if(ks_np_idps_const == NULL)
			return FALSE;
		memcpy(idps_const, ks_np_idps_const->erk, 0x10);

		ks_np_rif_key = keyset_find_by_name(CONFIG_NP_RIF_KEY_KNAME);
		if(ks_np_rif_key == NULL)
			return FALSE;

		rif = rif_load(content_id);
		if(rif == NULL)
		{
			printf("[*] Error: Could not obtain klicensee for '%s'.\n", content_id);
			return FALSE;
		}

		aes_setkey_dec(&aes_ctxt, ks_np_rif_key->erk, RIF_KEYBITS);
		aes_crypt_ecb(&aes_ctxt, AES_DECRYPT, rif->act_key_index, rif->act_key_index);

		act_dat_key_index = _ES32(*(u32 *)(rif->act_key_index + 12));
		if(act_dat_key_index > 127)
		{
			printf("[*] Error: act.dat key index out of bounds.\n");
			return FALSE;
		}

		memcpy(act_dat_key, act_dat->primary_key_table + act_dat_key_index * BITS2BYTES(ACT_DAT_KEYBITS), BITS2BYTES(ACT_DAT_KEYBITS));

		aes_setkey_enc(&aes_ctxt, idps, IDPS_KEYBITS);
		aes_crypt_ecb(&aes_ctxt, AES_ENCRYPT, idps_const, idps_const);

		aes_setkey_dec(&aes_ctxt, idps_const, IDPS_KEYBITS);
		aes_crypt_ecb(&aes_ctxt, AES_DECRYPT, act_dat_key, act_dat_key);

		aes_setkey_dec(&aes_ctxt, act_dat_key, ACT_DAT_KEYBITS);
		aes_crypt_ecb(&aes_ctxt, AES_DECRYPT, rif->klicensee, klicensee);

		free(rif);

		_LOG_VERBOSE("klicensee decrypted.\n");
	}
	else
		_LOG_VERBOSE("klicensee converted from %s.rap.\n", content_id);

	return TRUE;
}

keyset_t* __stdcall keyset_from_buffer(u8 *keyset)
{
	keyset_t *ks;

	if((ks = (keyset_t *)calloc(sizeof(keyset_t), sizeof(char))) == NULL)
		return NULL;

	ks->erk = (u8 *)_memdup(keyset, 0x20);
	ks->erklen = 0x20;
	ks->riv = (u8 *)_memdup(keyset + 0x20, 0x10);
	ks->rivlen = 0x10;
	ks->pub = (u8 *)_memdup(keyset + 0x20 + 0x10, 0x28);
	ks->priv = (u8 *)_memdup(keyset + 0x20 + 0x10 + 0x28, 0x15);
	ks->ctype = (u8)*(keyset + 0x20 + 0x10 + 0x28 + 0x15);

	return ks;
}
