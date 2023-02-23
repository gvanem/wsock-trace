#include <libloc/libloc.h>
#include <libloc/private.h>
#include <sys/mman.h>
#include <syslog.h>
#include <io.h>
#include <errno.h>
#include <stdlib.h>
#include <windows.h>

#undef  DIM
#define DIM(arr)     (sizeof(arr) / sizeof(arr[0]))
#define DWORD_HI(x)  ((uint64_t)(x) >> 32)
#define DWORD_LO(x)  ((x) & 0xffffffff)

static SYSTEM_INFO si;

/**
 * A small array of 'mmap()' return values we need to remember
 * until we call `munmap()` on the pointer.
 */
struct mmap_info {
       void  *map;   /* the value from 'MapViewOfFile()' */
       void  *rval;  /* the value we returned to caller of 'mmap()' */
     };
static struct mmap_info mmap_storage [10];

static void *mmap_remember (void *map, uint64_t offset);
static int   mmap_forget (void *map, struct mmap_info *info);

void *mmap (void *address, size_t length, int protection, int flags, int fd, off_t offset)
{
  void     *map = NULL;
  HANDLE    handle;
  intptr_t  h = _get_osfhandle (fd);
  DWORD     access = 0;
  uint64_t  pstart, psize, poffset;

  (void) address;  /* unused args */
  (void) flags;

  if (si.dwAllocationGranularity == 0)
     GetSystemInfo (&si);

  pstart  = (offset / si.dwAllocationGranularity) * si.dwAllocationGranularity;
  poffset = offset - pstart;
  psize   = poffset + length;

  switch (protection)
  {
    case PROT_READ:
         handle = CreateFileMapping ((HANDLE)h, 0, PAGE_READONLY, 0, 0, NULL);
         access = FILE_MAP_READ;
         break;
    case PROT_WRITE:
         handle = CreateFileMapping ((HANDLE)h, 0, PAGE_READWRITE, 0, 0, NULL);
         access = FILE_MAP_WRITE;  /* Or FILE_MAP_COPY? */
         break;
    case PROT_READWRITE:
         handle = CreateFileMapping ((HANDLE)h, 0, PAGE_READWRITE, 0, 0, NULL);
         access = FILE_MAP_ALL_ACCESS;
         break;
    default:
         handle = INVALID_HANDLE_VALUE;
         break;
  }

  if (!handle || handle == INVALID_HANDLE_VALUE)
     map = MAP_FAILED;
  else
  {
    map = MapViewOfFile (handle, access, DWORD_HI(pstart), DWORD_LO(pstart), (SIZE_T)psize);
    CloseHandle (handle);
    if (!map)
       map = MAP_FAILED;
  }

  SetLastError (0);   /* clear any possible error from above */
  return mmap_remember (map, poffset);
}

int munmap (void *map, size_t length)
{
  struct mmap_info info;
  int    rc = 0;

  if (!mmap_forget(map, &info))
  {
    errno = EINVAL;
    rc = -1;
  }
  else if (!UnmapViewOfFile(info.map))
  {
    errno = EFAULT;
    SetLastError (0);
    rc = -1;
  }
  return (rc);
}

static void *mmap_remember (void *map, uint64_t offset)
{
  size_t i;

  if (map == MAP_FAILED)  /* never remember this */
  {
    errno = EFAULT;
    goto fail;
  }

  for (i = 0; i < DIM(mmap_storage); i++)
  {
    if (!mmap_storage[i].map)   /* use this vacant slot */
    {
      mmap_storage [i].map  = map;
      mmap_storage [i].rval = (char*)map + offset;
      return (mmap_storage[i].rval);
    }
  }
  errno = EAGAIN;

fail:
  return (MAP_FAILED); /* all buckets full */
}

static int mmap_forget (void *map, struct mmap_info *info)
{
  size_t i;

  for (i = 0; i < DIM(mmap_storage); i++)
  {
    if (map == mmap_storage[i].rval)
    {
      *info = mmap_storage [i];
      mmap_storage [i].map = NULL;   /* reuse this */
      SetLastError (0);
      return (1);
    }
  }
  return (0);  /* not found! */
}

