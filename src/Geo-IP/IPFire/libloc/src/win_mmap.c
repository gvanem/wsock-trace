#include <loc/libloc.h>
#include <loc/private.h>
#include <sys/mman.h>
#include <stdint.h>
#include <io.h>
#include <windows.h>

#define DWORD_HI(x)  ((uint64_t)(x) >> 32)
#define DWORD_LO(x)  ((x) & 0xffffffff)

static int debug = -1;

static void hex_dump (const char *what, const void *data_p, size_t datalen);

void *_mmap (void *address, size_t length, int protection, int flags, int fd, off_t offset,
             const char *fname, unsigned line)
{
  void        *map = NULL;
  HANDLE       handle = INVALID_HANDLE_VALUE;
  DWORD        err1 = 0;
  DWORD        err2 = 0;
  intptr_t     h = _get_osfhandle (fd);
  DWORD        access = 0;
  uint64_t     pstart, psize, poffset;
  static DWORD block_size = 0;

  (void) flags; /* Not used */

  if (block_size == 0)
  {
    SYSTEM_INFO si;

    GetSystemInfo (&si);
    block_size = si.dwAllocationGranularity;
  }
  if (debug == -1)
     debug = (getenv("LIBLOC_DEBUG") ? 1 : 0);

  pstart  = (offset / block_size) * block_size;
  poffset = offset - pstart;
  psize   = poffset + length;

  switch (protection)
  {
    case PROT_READ:
         handle = CreateFileMapping ((HANDLE)h, 0, PAGE_READONLY, 0, DWORD_LO(pstart), NULL);
         access = FILE_MAP_READ;
         break;
    case PROT_WRITE:
         handle = CreateFileMapping ((HANDLE)h, 0, PAGE_READWRITE, 0, 0, NULL);
         access = FILE_MAP_WRITE;
         break;
    case PROT_READWRITE:
         handle = CreateFileMapping ((HANDLE)h, 0, PAGE_READWRITE, 0, 0, NULL);
         access = FILE_MAP_ALL_ACCESS;
         break;
    default:
         break;
  }

  if (!handle)
  {
    map = MAP_FAILED;
    err1 = GetLastError();
  }
  else
  {
    map = MapViewOfFile (handle, access, DWORD_HI(pstart), DWORD_LO(pstart), (SIZE_T)psize);
    if (!map)
    {
      map = MAP_FAILED;
      err2 = GetLastError();
    }
  }

  if (handle && handle != INVALID_HANDLE_VALUE)
     CloseHandle (handle);

  if (!debug)
     return (map);

  if (map == MAP_FAILED)
  {
    fprintf (stderr, "%s(%u): pstart: %lld, poffset: %lld, psize: %lld\n", fname, line, pstart, poffset, psize);
    fprintf (stderr, "    address: 0x%p, length: %u, %d, err1: %lu, err2: %lu  -> 0x%p\n",
             address, length, fd, err1, err2, map);
  }
  else
  {
    char  *p = (char*) map;
    size_t len;

    fprintf (stderr, "%s(%u): address: 0x%p, length: %u, fd: %d, offset: %zu, err1: %lu, err2: %lu  -> 0x%p\n",
             fname, line, address, length, fd, offset, err1, err2, map);

    /* Now test the low and high end of the mmap'ed region to check
     * we get no exceptions. Check 'PROT_READ' only since that's the only
     * protection used in libloc.
     */
    if (protection == PROT_READ)
    {
      (void) p[0];
      (void) p[length-1];
      (void) p[length];

      len = min (length, 100);
      hex_dump ("Dumping first %zu bytes:\n", p, len);
      if (length > 100)
        hex_dump ("Dumping last %zu bytes:\n", p + length - 100, len);
      else
        fprintf (stderr, "Last chunk of data covered by the first chunk.\n\n");
    }
  }

  return (map);
}

int _munmap (void *map, size_t length, const char *fname, unsigned line)
{
  if (!UnmapViewOfFile(map) && debug)
     fprintf (stderr, "%s(%u): munmap (0x%p) failed: %lu\n", fname, line, map, GetLastError());
  (void) length;
  return (0);
}


/**
 * Do not use 'hexdump()' in 'loc/private.h'.
 */
static void hex_dump (const char *what, const void *data_p, size_t datalen)
{
  const BYTE *data = (const BYTE*) data_p;
  UINT  ofs;

  fprintf (stderr, what, datalen);
  for (ofs = 0; ofs < datalen; ofs += 16)
  {
    UINT j;

    fprintf (stderr, "  %p: ", data+ofs);
    for (j = 0; j < 16 && j+ofs < datalen; j++)
        fprintf (stderr, "%02X%c", (unsigned)data[j+ofs],
                 j == 7 && j+ofs < datalen-1 ? '-' : ' ');

    for ( ; j < 16; j++)       /* pad line to 16 positions */
        fputs ("   ", stderr);

    for (j = 0; j < 16 && j+ofs < datalen; j++)
    {
      int ch = data[j+ofs];

      if (ch < ' ')            /* non-printable */
           putc ('.', stderr);
      else putc (ch, stderr);
    }
    putc ('\n', stderr);
  }
  putc ('\n', stderr);
}

