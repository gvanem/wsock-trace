#ifndef WIN_SYS_MMAN_H
#define WIN_SYS_MMAN_H

#include <sys/types.h>

#define PROT_READ      1
#define PROT_WRITE     2
#define PROT_READWRITE 3
#define MAP_SHARED     1    /* Ignored in win_mmap.c */
#define MAP_PRIVATE    2    /* Ignored in win_mmap.c */
#define MAP_FAILED     ((void*) -1)

extern void *_mmap (void *address, size_t length, int protection, int access, int file, off_t offset, const char *fname, unsigned line);
extern int   _munmap (void *map, size_t length, const char *fname, unsigned line);

#define mmap(address, length, protection, access, file, offset) \
       _mmap(address, length, protection, access, file, offset, __FILE__, __LINE__)

#define munmap(map, length) \
       _munmap(map, length, __FILE__, __LINE__)

#endif /*  WIN_SYS_MMAN_H */

