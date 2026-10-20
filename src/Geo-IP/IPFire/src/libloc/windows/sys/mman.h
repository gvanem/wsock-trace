#pragma once

#include <sys/types.h>

#define PROT_READ      1
#define PROT_WRITE     2
#define PROT_READWRITE 3
#define MAP_SHARED     1    /* Ignored in win_misc.c */
#define MAP_PRIVATE    2    /* Ignored in win_misc.c */
#define MAP_FAILED     ((void*) -1)

extern void *mmap (void *address, size_t length, int protection, int access, int file, off_t offset);
extern int   munmap (void *map, size_t length);
