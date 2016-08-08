#include <windows.h>
#include <malloc.h>
#include <stdio.h>
#include <tchar.h>

#if !defined(_MSC_VER)
  typedef enum _LOGICAL_PROCESSOR_RELATIONSHIP {
      RelationProcessorCore,
      RelationNumaNode,
      RelationCache,
      RelationProcessorPackage,
      RelationGroup,
      RelationAll = 0xffff
    } LOGICAL_PROCESSOR_RELATIONSHIP;

  typedef enum _PROCESSOR_CACHE_TYPE {
      CacheUnified,
      CacheInstruction,
      CacheData,
      CacheTrace
    } PROCESSOR_CACHE_TYPE;

  typedef struct _CACHE_DESCRIPTOR {
      BYTE                 Level;
      BYTE                 Associativity;
      WORD                 LineSize;
      DWORD                Size;
      PROCESSOR_CACHE_TYPE Type;
    } CACHE_DESCRIPTOR;

  typedef struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION {
      ULONG_PTR                      ProcessorMask;
      LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
      union {
          struct {
            BYTE  Flags;
          } ProcessorCore;
          struct {
            DWORD NodeNumber;
          } NumaNode;
          CACHE_DESCRIPTOR Cache;
          ULONGLONG        Reserved[2];
      };   /* anonymous union */
    } SYSTEM_LOGICAL_PROCESSOR_INFORMATION;
#endif

typedef BOOL (WINAPI *func_GetLogicalProcessorInformation) (SYSTEM_LOGICAL_PROCESSOR_INFORMATION *slpi, DWORD *len);

/* Helper function to count set bits in the processor mask.
 */
static DWORD CountSetBits (ULONG_PTR bitMask)
{
  DWORD     LSHIFT      = (8 * sizeof(ULONG_PTR)) - 1;
  DWORD     bitSetCount = 0;
  ULONG_PTR bitTest     = (ULONG_PTR)1 << LSHIFT;
  DWORD     i;

  for (i = 0; i <= LSHIFT; ++i)
  {
    bitSetCount += ((bitMask & bitTest) ? 1 : 0);
    bitTest /= 2;
  }
  return (bitSetCount);
}

int get_logical_processor_info (void)
{
  func_GetLogicalProcessorInformation p_GetLogicalProcessorInformation;
  SYSTEM_LOGICAL_PROCESSOR_INFORMATION *buffer = NULL;
  SYSTEM_LOGICAL_PROCESSOR_INFORMATION *ptr = NULL;

  BOOL    done = FALSE;
  DWORD   returnLength = 0;
  DWORD   logicalProcessorCount = 0;
  DWORD   numaNodeCount = 0;
  DWORD   processorCoreCount = 0;
  DWORD   L1CacheCount = 0;
  DWORD   L2CacheCount = 0;
  DWORD   L3CacheCount = 0;
  DWORD   L1CacheSize = 0;
  DWORD   L2CacheSize = 0;
  DWORD   L3CacheSize = 0;
  DWORD   processorPackageCount = 0;
  DWORD   byteOffset = 0;
  HMODULE k32 = GetModuleHandle ("kernel32");
  const CACHE_DESCRIPTOR *Cache;

  p_GetLogicalProcessorInformation = (func_GetLogicalProcessorInformation)
    GetProcAddress (k32, "GetLogicalProcessorInformation");

  if (!p_GetLogicalProcessorInformation)
  {
    printf ("\nGetLogicalProcessorInformation() not found.\n");
    return (1);
  }

  while (!done)
  {
    DWORD rc = (*p_GetLogicalProcessorInformation) (buffer, &returnLength);

    if (!rc)
    {
      if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
         buffer = alloca (returnLength);
      else
      {
        printf ("\nError %lu\n", GetLastError());
        return (3);
      }
    }
    else
    {
      done = TRUE;
    }
  }

  ptr = buffer;

  while (byteOffset + sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION) <= returnLength)
  {
    switch (ptr->Relationship)
    {
      case RelationNumaNode:
           /* Non-NUMA systems report a single record of this type.
            */
           numaNodeCount++;
           break;

      case RelationProcessorCore:
           processorCoreCount++;

           /* A hyperthreaded core supplies more than one logical processor.
            */
           logicalProcessorCount += CountSetBits (ptr->ProcessorMask);
           break;

      case RelationCache:
           /* Cache data is in ptr->Cache, one CACHE_DESCRIPTOR structure for each cache.
            */
           Cache = &ptr->Cache;
           if (Cache->Level == 1)
           {
             L1CacheCount++;
             L1CacheSize += Cache->Size;
           }
           else if (Cache->Level == 2)
           {
             L2CacheCount++;
             L2CacheSize += Cache->Size;
           }
           else if (Cache->Level == 3)
           {
             L3CacheCount++;
             L3CacheSize += Cache->Size;
           }
           break;

      case RelationProcessorPackage:
           /* Logical processors share a physical package.
            */
           processorPackageCount++;
           break;

      default:
           printf ("\nError: Unsupported LOGICAL_PROCESSOR_RELATIONSHIP value.\n");
           break;
    }
    byteOffset += sizeof (SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
    ptr++;
  }

  printf ("\nGetLogicalProcessorInformation results:\n");
  printf ("  Number of NUMA nodes: %lu\n", numaNodeCount);
  printf ("  Number of physical processor packages: %lu\n", processorPackageCount);
  printf ("  Number of processor cores: %lu\n", processorCoreCount);
  printf ("  Number of logical processors: %lu\n", logicalProcessorCount);
  printf ("  Number of processor L1/L2/L3 caches: %lu/%lu/%lu\n",
          L1CacheCount, L2CacheCount, L3CacheCount);

  printf ("  L1/L2/L3 cache sizes (kB): ");

  if (L1CacheCount > 0)
       printf ("%lu/", L1CacheSize/(1024 * L1CacheCount));
  else printf ("-/");

  if (L2CacheCount > 0)
       printf ("%lu/", L2CacheSize/(1024 * L2CacheCount));
  else printf ("-/");

  if (L3CacheCount > 0)
       printf ("%lu\n\n", L3CacheSize/(1024 * L3CacheCount));
  else printf ("-\n\n");

  return (0);
}
