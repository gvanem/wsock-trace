#ifndef WIN_SYS_MMAN_H
#define WIN_SYS_MMAN_H

#include <sys/types.h>

#define PROT_READ      1
#define PROT_WRITE     2
#define PROT_READWRITE 3
#define MAP_SHARED     1
#define MAP_PRIVATE    2
#define MAP_FAILED     ((void*) -1)

extern void *mmap (void *address, size_t length, int protection, int access, int file, off_t offset);
extern int   munmap (void *map, size_t length);

#endif /*  WIN_SYS_MMAN_H */

