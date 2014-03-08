/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#ifndef _LIST_H_
#define _LIST_H_

#include "types.h"


#ifdef __cplusplus
extern "C" {
#endif



#define LIST_FOREACH(iter, list) for(lnode_t *iter = list->head; iter != NULL; iter = iter->next)

typedef struct _lnode
{
	void *value;
	struct _lnode *next;
} lnode_t;

typedef struct _list
{
	lnode_t *head;
	u32 count;
} list_t;

list_t* __stdcall list_create();
void __stdcall list_destroy(list_t** ppList);
BOOL __stdcall list_isempty(list_t *l);
u32 __stdcall list_count(list_t *l);
BOOL __stdcall list_push(list_t *l, void *value);
void* __stdcall list_pop(list_t *l);
BOOL __stdcall list_add_back(list_t *l, void *value);
void* __stdcall list_get(list_t *l, u32 idx);
lnode_t* __stdcall list_get_node(list_t *l, u32 idx);
BOOL __stdcall list_remove_node(list_t *l, lnode_t *node);
BOOL __stdcall list_remove_value(list_t *l, void *value);

#ifdef __cplusplus
}
#endif



#endif
