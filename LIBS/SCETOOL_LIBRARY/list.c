/*
* Copyright (c) 2011-2013 by naehrwert
* This file is released under the GPLv2.
*/

#include <stdlib.h>

#include "types.h"
#include "list.h"






list_t* __stdcall list_create()
{
	list_t *res;
	
	if((res = (list_t *)calloc(sizeof(list_t), sizeof(char))) == NULL)
		return NULL;
	
	res->head = NULL;
	res->count = 0;
	
	return res;
}

void __stdcall list_destroy(list_t** ppList)
{
	lnode_t *iter = NULL;
	lnode_t *tmp = NULL;
	list_t* pMyList = NULL;

	// validate input params
	if (ppList == NULL)
		goto exit;
	if(*ppList == NULL)
		goto exit;
	
	pMyList = (list_t*)*ppList;
	iter = pMyList->head;	
	while(iter != NULL)
	{
		tmp = iter;
		iter = iter->next;
		free(tmp);
	}
	// free the list pointer, and
	// make sure to set pointer value to NULL
	free(*ppList);
	*ppList = NULL;

exit:
	return;
}

BOOL __stdcall list_isempty(list_t *l)
{
	if(l == NULL)
		return FALSE;
	
	if(l->count == 0)
		return TRUE;
	return FALSE;
}

u32 __stdcall list_count(list_t *l)
{
	if(l == NULL)
		return 0;
	
	return l->count;
}

BOOL __stdcall list_push(list_t *l, void *value)
{	
	lnode_t *_new = NULL;



	// validate input params
	if(l == NULL)
		return FALSE;		
	
	//Allocate new node.
	if((_new = (lnode_t *)calloc(sizeof(lnode_t), sizeof(char))) == NULL)
		return FALSE;
	
	//Insert.
	_new->value = value;
	_new->next = l->head;
	l->head = _new;
	l->count++;
	
	return TRUE;
}

void* __stdcall list_pop(list_t *l)
{	
	lnode_t *tmp = NULL;
	void *res = NULL;	
		
	
	// validate input param
	if(l == NULL)
		return NULL;		
	
	if(l->head != NULL)
	{
		res = l->head->value;
		tmp = l->head;
		l->head = l->head->next;
		free(tmp);
		l->count--;
	}
	
	return res;
}

BOOL __stdcall list_add_back(list_t *l, void *value)
{	
	lnode_t* n = NULL;
	lnode_t* _new = NULL;


	// validate input params
	if(l == NULL)
		return FALSE;		
	
	//Allocate new node.
	if((_new = (lnode_t *)calloc(sizeof(lnode_t), sizeof(char))) == NULL)
		return FALSE;
	
	_new->value = value;
	_new->next = NULL;
	
	if(l->head == NULL)
		l->head = _new;
	else
	{
		//Move to the list end.
		for(n = l->head; n->next != NULL; n = n->next);
		
		//Add.
		n->next = _new;
		l->count++;
	}
	
	return TRUE;
}

void* __stdcall list_get(list_t *l, u32 idx)
{
	lnode_t *iter = NULL;
	void *res = NULL;


	// validate input params
	if(l == NULL)
		return NULL;		
	
	for(iter = l->head; idx-- != 0 && iter != NULL; iter = iter->next);
	
	if(iter == NULL)
		res = NULL;
	else
		res = iter->value;
	
	return res;
}

lnode_t* __stdcall list_get_node(list_t *l, u32 idx)
{
	lnode_t *iter = NULL;


	// validate input params
	if(l == NULL)
		return NULL;		
	
	for(iter = l->head; idx-- != 0 && iter != NULL; iter = iter->next);
	
	return iter;
}

BOOL __stdcall list_remove_node(list_t *l, lnode_t *node)
{	
	lnode_t *iter = NULL;

	// validate input params
	if(l == NULL)
		return FALSE;		
	
	if(l->head == node)
	{
		l->head = l->head->next;
		free(node);
		l->count--;
		
		return TRUE;
	}
	
	iter = l->head;
	while(iter->next != NULL)
	{
		if(iter->next == node)
		{
			iter->next = iter->next->next;
			free(node);
			l->count--;
			
			return TRUE;
		}
		iter = iter->next;
	}
	
	return FALSE;
}

BOOL __stdcall list_remove_value(list_t *l, void *value)
{	
	lnode_t *tmp = NULL;
	lnode_t *iter = NULL;

	// validate input param
	if(l == NULL)
		return FALSE;		
	
	if(l->head->value == value)
	{
		tmp = l->head;
		l->head = l->head->next;
		free(tmp);
		l->count--;
		
		return TRUE;
	}
	
	iter = l->head;
	while(iter->next != NULL)
	{
		if(iter->next->value == value)
		{
			tmp = iter->next;
			iter->next = iter->next->next;
			free(tmp);
			l->count--;
			
			return TRUE;
		}
		iter = iter->next;
	}
	
	return FALSE;
}
