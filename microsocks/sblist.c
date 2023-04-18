#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "sblist.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#define MY_PAGE_SIZE 4096

// 在堆中新建一个sblist对象
// 使用2个参数初始化一个sblist对象
// sblist_new(itemsize, blockitems)
sblist* sblist_new(size_t itemsize, size_t blockitems) {
	sblist* ret = (sblist*) malloc(sizeof(sblist)); //开辟内存
	sblist_init(ret, itemsize, blockitems);         //初始化sblist对象的块数量、块大小成员
	return ret;
}

// sblist结构体次要成员初始化为0
static void sblist_clear(sblist* l) {
	l->items = NULL;
	l->capa = 0;
	l->count = 0;
}

// 初始化sblist对象的块数量、块大小成员
void sblist_init(sblist* l, size_t itemsize, size_t blockitems) {
	if(l) {
		l->blockitems = blockitems ? blockitems : MY_PAGE_SIZE / itemsize;
		l->itemsize = itemsize;
		sblist_clear(l);
	}
}

void sblist_free_items(sblist* l) {
	if(l) {
		if(l->items) free(l->items);
		sblist_clear(l);
	}
}

void sblist_free(sblist* l) {
	if(l) {
		sblist_free_items(l);
		free(l);
	}
}

//移动sblist对象的items成员所指向的位置，指向了更高的地址idx*itemsize
char* sblist_item_from_index(sblist* l, size_t idx) {
	return l->items + (idx * l->itemsize);
}

//如果参数2的值小于参数1的count成员，移动参数1的items指针，让它指向更高的地址
void* sblist_get(sblist* l, size_t item) {
	if(item < l->count) return (void*) sblist_item_from_index(l, item);
	return NULL;
}

//item的内容复制到扩充的内存里
int sblist_set(sblist* l, void* item, size_t pos) {
	if(pos >= l->count) return 0;
	memcpy(sblist_item_from_index(l, pos), item, l->itemsize);
	return 1;
}

//当l->count == l->capa，增加items指向的内存大小
int sblist_grow_if_needed(sblist* l) {
	char* temp;
	if(l->count == l->capa) { //重新分配items指向的堆内存大小
		temp = realloc(l->items, (l->capa + l->blockitems) * l->itemsize);
		if(!temp) return 0;
		l->capa += l->blockitems;
		l->items = temp;
	}
	return 1;
}

//添加item的内容到l中
int sblist_add(sblist* l, void* item) {
	if(!sblist_grow_if_needed(l)) return 0;
	l->count++;
	return sblist_set(l, item, l->count - 1);
}
