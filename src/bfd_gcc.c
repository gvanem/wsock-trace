#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#if defined(USE_BFD)   /* Rest of file */

#include "common.h"
#include "init.h"
#include "bfd_gcc.h"

#if (BFD_ARCH_SIZE == 32)
  #define VMA_X_FMT  "0x%08" BFD_VMA_FMT "X"   /* -> "0x08lX" on Win32 */
#elif (BFD_ARCH_SIZE == 64)
  #define VMA_X_FMT  "0x%016" BFD_VMA_FMT "X"  /* -> "0x016llX" on Win64 */
#else
  #error "Unknown architecture size"
#endif

/* Missing in my Cygwin.
 */
#ifndef BFD_COMPRESS
#define BFD_COMPRESS   0x8000    /* Compress sections in this BFD.  */
#endif

#ifndef BFD_DECOMPRESS
#define BFD_DECOMPRESS 0x10000   /* Decompress sections in this BFD.  */
#endif

#ifndef SEC_ELF_REVERSE_COPY
#define SEC_ELF_REVERSE_COPY 0x4000000
#endif

#ifndef BFD_PLUGIN
#define BFD_PLUGIN     0x20000   /* BFD is a dummy, for plugins.  */
#endif

struct BFD_sym_tab {
       bfd_vma     value;
       char        stype;      /* symbol type */
       const char *name;       /* no strdup(). free() in bfd_close().  */
     };

struct BFD_table {
       const char         *module;     /* from stkwalk.c. free() it there. */
       DWORD               base_addr;  /* it's base address */
       DWORD               mod_size;   /* and size */
       struct bfd         *BFD;        /* from bfd_open(). One for each module called in BFD_load_debug_symbols(). */
       struct bfd_symbol **sym_tab;    /* from bfd_canonicalize_symtab() */
       unsigned            sym_count;  /* # of elements from above */
       struct BFD_sym_tab *sym;        /* some of the symbols copied from bfd_symbol_info() */
       unsigned            sym_top;    /* # of elements in above array */
     };

struct find_data {
       const char   *name;
       const char   *module;
       bfd_vma       address;
       long          offset;
       const char   *file;
       unsigned int  line;
     };

typedef int  (*CompareFunc) (const void *a, const void *b);
typedef void (*BFD_find_func) (const struct BFD_table *, struct bfd_section *, void *obj);

static struct BFD_table *BFD_table = NULL;    /* growable array of all local data */
static unsigned          BFD_table_top = 0;   /* top-index in above array */

static void        sort_symbol_table (struct BFD_table *BFD);
static const char *get_flavour (bfd *b);
static const char *get_file_flags (flagword flags);
static const char *get_sym_flags (flagword flags);
static const char *get_sec_flags (flagword flags);

void BFD_init (void)
{
  bfd_init();
}

void BFD_dump (void)
{
  const struct BFD_table *BFD = BFD_table;
  int   i;

  if (g_cfg.trace_level < 4)
     return;

  TRACE (4, "BFD_dump():\n");

  for (i = 0; i < BFD_table_top; i++, BFD++)
      TRACE (4, "module: %-15.15s, base_addr: 0x%08lX, mod_size: %7lu, BFD: 0x%p, BFD->BFD: 0x%p, "
                "sym_count: %4u, sym: 0x%p, sym_top: %4u, sym_tab: 0x%p\n",
             basename(BFD->module), BFD->base_addr, BFD->mod_size, BFD, BFD->BFD,
             BFD->sym_count, BFD->sym, BFD->sym_top, BFD->sym_tab);
}

int BFD_load_debug_symbols (const char *fname, bfd_vma base_addr, DWORD mod_size)
{
  BOOL               ok1, ok2;
  unsigned           i, sym_size;
  flagword           flags;
  const char        *err;
  struct BFD_table  *BFD;
  struct bfd        *_bfd = bfd_openr (fname, 0);
  struct bfd_symbol *sym;

  if (!_bfd)
  {
    TRACE (1, "Failed to open %s.\n", fname);
    return (0);
  }

  ok1   = bfd_check_format (_bfd, bfd_object);
  flags = bfd_get_file_flags (_bfd);
  ok2   = flags & HAS_SYMS;

  if (!ok1 || !ok2)
  {
    err = bfd_errmsg (bfd_get_error());
    TRACE (1, "Unable to get symbols from %s; err: %s\n", fname, err);
    bfd_close (_bfd);
    return (0);
  }

  TRACE (1, "Loaded %s. BFD flavour: %s, flags: %s.\n",
         fname, get_flavour(_bfd), get_file_flags(flags));

  /* Load symbol table */
  sym_size = bfd_get_symtab_upper_bound (_bfd);
  if (sym_size <= 0)
  {
    err = bfd_errmsg (bfd_get_error());
    TRACE (0, "Failed to get number of symbols in %s; err: %s\n", fname, err);
    bfd_close (_bfd);
    return (0);
  }

  /* Note: this realloc() is guaranteed to change the values in 'BFD_table'
   * array as we add modules. But the content is intact.
   */
  BFD_table = realloc (BFD_table, (BFD_table_top+1)*sizeof(*BFD_table));
  BFD = BFD_table + BFD_table_top;
  memset (BFD, '\0', sizeof(*BFD));
  BFD->BFD       = _bfd;
  BFD->module    = fname;
  BFD->mod_size  = mod_size;
  BFD->base_addr = base_addr;
  BFD->sym_tab   = calloc (sym_size, 1);
  BFD->sym_count = bfd_canonicalize_symtab (_bfd, BFD->sym_tab);
  BFD->sym       = calloc (BFD->sym_count, sizeof(*BFD->sym));

  TRACE (1, "BFD->sym_tab[]: adding %u symbols totaling %d bytes.\n",
            BFD->sym_count, sym_size);

  for (i = 0, sym = BFD->sym_tab[0]; i < BFD->sym_count; sym++)
  {
    struct _symbol_info ret;

    if (sym->flags == BSF_LOCAL || !strncmp(".weak",sym->name,5))
       continue;

    memset (&ret, 0, sizeof(ret));
    bfd_get_symbol_info ((struct bfd*)BFD->BFD, sym, &ret);

    /* Section name (ret.name) is mapped to these archaic POSIX/BSD
     * single-character symbol types (ret.type).
     * An incomplete table here (check 'man nm' for more):
     *  'b' ; BSS symbol, local
     *  'd' ; Data symbol, local
     *  's' ; small BSS
     *  'c' ; small common
     *  'g' ; small initialized data
     *  'T' ; text symbols, global
     *  't' ; text symbols, local
     *  '?' ; unknown symbol type
     */
#if 0
    TRACE (4, "sym->value: " VMA_X_FMT ", ret.value: " VMA_X_FMT ", ret.stype: %c, "
              "sym->flags: %s, ret.name: '%s'.\n",
              sym->value, ret.value, ret.type, get_sym_flags(sym->flags), ret.name);
#else
    TRACE (4, "sym->value: " VMA_X_FMT ", ret.value: " VMA_X_FMT ".\n",
              sym->value, ret.value);
#endif

    if (!ret.name || ret.name[0] == '.' ||  /* skip section names */
        ret.value == 0)
       continue;

    if (ret.type == 'T' || ret.type == '?')
    {
      struct BFD_sym_tab *sym2 = BFD->sym + (BFD->sym_top++);

     /* Except for debugging symbols, 'ret.value' == 'sym->value' + base_addr of module +
      * some mysterious 0x1000 value added.
      */
      sym2->value = ret.value;  /* copy over */
      sym2->stype = ret.type;
      sym2->name  = ret.name;
    }
  }

  /* We know the addresses from 2 modules are not overlapping.
   * Hence sort only the entries we added for this module.
   */
  sort_symbol_table (BFD);
  BFD_table_top++;
  return (1);
}

void BFD_unload_debug_symbols (const char *module)
{
  struct BFD_table *BFD;
  int    i, found;

  for (BFD = BFD_table, i = 0; i < BFD_table_top; i++, BFD++)
      if (!strcmp(module,BFD->module))
         break;

  found = (i < BFD_table_top);
  TRACE (2, "%s(). module: %s %s.\n",
            __FUNCTION__, module, found ? "unloaded okay" : "not loaded by BFD");
  if (found)
  {
    free (BFD->sym);
    free (BFD->sym_tab);
    BFD->sym_top = 0;
    bfd_close (BFD->BFD);
    BFD->BFD = NULL;
  }
}

void BFD_unload_all_symbols (void)
{
  struct BFD_table *BFD;
  int    i;

  for (BFD = BFD_table, i = 0; i < BFD_table_top; i++, BFD++)
      BFD_unload_debug_symbols (BFD->module);
  free (BFD_table);
  BFD_table = NULL;
  BFD_table_top = 0;
}

int BFD_demangle (const char *module, const char *raw_name, char *und_name, size_t und_size)
{
  ARGSUSED (module);
  ARGSUSED (raw_name);
  ARGSUSED (und_name);
  ARGSUSED (und_size);
  return (0);
}

/*
 * Compare on value (i.e. address).
 * Don't use unsigned arithmetic.
 */
static int compare (const struct BFD_sym_tab *a,
                    const struct BFD_sym_tab *b)
{
  return (bfd_signed_vma) (a->value - b->value);
}

static void sort_symbol_table (struct BFD_table *BFD)
{
  struct BFD_sym_tab *sym = BFD->sym;
  int    i;

  TRACE (2, "quick-sorting %4u symbols for module %-20.20s (BFD: 0x%p, BFD_table_top: %u).\n",
         BFD->sym_top, basename(BFD->module), BFD, BFD_table_top);

  qsort (sym, BFD->sym_top, sizeof(*sym), (CompareFunc)compare);
  for (i = 0; i < BFD->sym_top; i++, sym++)
  {
    char *name = g_cfg.cpp_demangle ? bfd_demangle (BFD->BFD, sym->name, -1) : NULL;

    TRACE (4, "%3u: value: " VMA_X_FMT ", stype: %c, name: %s\n",
           i, sym->value, sym->stype, name ? name :sym->name);
    if (name)
       free (name);
  }
}

#ifdef NOT_USED
/*
 * Find the BFD for an virtual address. The address in the
 * BFD->module is in [base_addr ... (base_addr+mod_size)].
 */
static const struct BFD_table *find_BFD_table_by_addr (bfd_vma address, const char **module)
{
  const struct BFD_table *BFD;
  int   i;

  if (!BFD_table)    /* Impossible! */
  {
    TRACE (4, "BFD_table == NULL!\n");
    return (NULL);
  }

  for (BFD = BFD_table, i = 0; i < BFD_table_top; i++, BFD++)
      if (address >= BFD->base_addr && address < (BFD->base_addr + BFD->mod_size))
         break;

  if (i == BFD_table_top)
  {
    TRACE (2, "address " VMA_X_FMT " not found in any module.\n", address);
    return (NULL);
  }
  *module = BFD->module;
  return (BFD);
}

/*
 * Find the symbols for an address. First find the BFD, then do a binary search
 * in it's symbol-table.
 */
static const struct BFD_sym_tab *find_BFD_sym_by_addr (bfd_vma address, const char **module)
{
  const struct BFD_table *BFD = find_BFD_table_by_addr (address, module);

  if (!BFD)
     return (NULL);

  return (const struct BFD_sym_tab*) bsearch (&address, BFD->sym,
                                              BFD->sym_top, sizeof(*BFD->sym),
                                              (CompareFunc)compare);
}

static const char *get_module_and_symbol_name (bfd_vma address)
{
  const char  *module = NULL;
  const struct BFD_sym_tab *sym = find_BFD_sym_by_addr (address, &module);
  static char  res [300];

  TRACE (4, "get_module_and_symbols_name: sym: 0x%p, module: %s\n", sym, module);
  assert (sym);
  snprintf (res, sizeof(res), "%s!%s", shorten_path(module), sym->name);
  return (res);
}
#endif  /* NOT_USED */

static const struct search_list flavours[] = {
                  { bfd_target_unknown_flavour,  "Unknown"  },
                  { bfd_target_aout_flavour,     "AOUT"     },
                  { bfd_target_coff_flavour,     "COFF"     },
                  { bfd_target_ecoff_flavour,    "ECOFF"    },
                  { bfd_target_xcoff_flavour,    "XCOFF"    },
                  { bfd_target_elf_flavour,      "ELF"      },
                  { bfd_target_ieee_flavour,     "IEEE"     },
                  { bfd_target_nlm_flavour,      "NLM"      },
                  { bfd_target_oasys_flavour,    "OASYS"    },
                  { bfd_target_tekhex_flavour,   "TekHex"   },
                  { bfd_target_srec_flavour,     "SREC"     },
                  { bfd_target_verilog_flavour,  "Verilog"  },
                  { bfd_target_ihex_flavour,     "iHex"     },
                  { bfd_target_som_flavour,      "SOM"      },
                  { bfd_target_os9k_flavour,     "OS9k"     },
                  { bfd_target_versados_flavour, "VersaDOS" },
                  { bfd_target_msdos_flavour,    "MSDOS"    },
                  { bfd_target_ovax_flavour,     "OVax"     },
                  { bfd_target_evax_flavour,     "EVax"     },
                  { bfd_target_mmo_flavour,      "MMO"      },
                  { bfd_target_mach_o_flavour,   "MACH"     },
                  { bfd_target_pef_flavour,      "PEF"      },
                  { bfd_target_pef_xlib_flavour, "PEF Xlib" },
                  { bfd_target_sym_flavour,      "SYM"      }
                };

static const char *get_flavour (bfd *b)
{
  return list_lookup_name (bfd_get_flavour(b), flavours, DIM(flavours));
}

#define ADD_VALUE(x)  { x, #x }

static const struct search_list file_flgs[] = {
                    ADD_VALUE (HAS_RELOC),
                    ADD_VALUE (HAS_RELOC),
                    ADD_VALUE (EXEC_P),
                    ADD_VALUE (HAS_LINENO),
                    ADD_VALUE (HAS_DEBUG),
                    ADD_VALUE (HAS_SYMS),
                    ADD_VALUE (HAS_LOCALS),
                    ADD_VALUE (DYNAMIC),
                    ADD_VALUE (WP_TEXT),
                    ADD_VALUE (D_PAGED),
                    ADD_VALUE (BFD_IS_RELAXABLE),
                    ADD_VALUE (BFD_TRADITIONAL_FORMAT),
                    ADD_VALUE (BFD_IN_MEMORY),
                    ADD_VALUE (HAS_LOAD_PAGE),
                    ADD_VALUE (BFD_LINKER_CREATED),
                    ADD_VALUE (BFD_DETERMINISTIC_OUTPUT),
                    ADD_VALUE (BFD_COMPRESS),
                    ADD_VALUE (BFD_DECOMPRESS),
                    ADD_VALUE (BFD_PLUGIN),
                  };

static const struct search_list sym_flgs[] = {
                    ADD_VALUE (BSF_NO_FLAGS),
                    ADD_VALUE (BSF_LOCAL),
                    ADD_VALUE (BSF_EXPORT),
                    ADD_VALUE (BSF_DEBUGGING),
                    ADD_VALUE (BSF_FUNCTION),
                    ADD_VALUE (BSF_KEEP),
                    ADD_VALUE (BSF_KEEP_G),
                    ADD_VALUE (BSF_WEAK),
                    ADD_VALUE (BSF_SECTION_SYM),
                    ADD_VALUE (BSF_OLD_COMMON),
                    ADD_VALUE (BSF_NOT_AT_END),
                    ADD_VALUE (BSF_CONSTRUCTOR),
                    ADD_VALUE (BSF_WARNING),
                    ADD_VALUE (BSF_INDIRECT),
                    ADD_VALUE (BSF_FILE),
                    ADD_VALUE (BSF_DYNAMIC),
                    ADD_VALUE (BSF_OBJECT),
                    ADD_VALUE (BSF_DEBUGGING_RELOC),
                    ADD_VALUE (BSF_THREAD_LOCAL),
                    ADD_VALUE (BSF_RELC),
                    ADD_VALUE (BSF_SRELC),
                    ADD_VALUE (BSF_SYNTHETIC),
                    ADD_VALUE (BSF_GNU_INDIRECT_FUNCTION),
                    ADD_VALUE (BSF_GNU_UNIQUE)
                  };

static const struct search_list sec_flgs[] = {
                    ADD_VALUE (SEC_NO_FLAGS),
                    ADD_VALUE (SEC_ALLOC),
                    ADD_VALUE (SEC_LOAD),
                    ADD_VALUE (SEC_RELOC),
                    ADD_VALUE (SEC_READONLY),
                    ADD_VALUE (SEC_CODE),
                    ADD_VALUE (SEC_DATA),
                    ADD_VALUE (SEC_ROM),
                    ADD_VALUE (SEC_CONSTRUCTOR),
                    ADD_VALUE (SEC_HAS_CONTENTS),
                    ADD_VALUE (SEC_NEVER_LOAD ),
                    ADD_VALUE (SEC_THREAD_LOCAL),
                    ADD_VALUE (SEC_HAS_GOT_REF),
                    ADD_VALUE (SEC_IS_COMMON),
                    ADD_VALUE (SEC_DEBUGGING),
                    ADD_VALUE (SEC_IN_MEMORY),
                    ADD_VALUE (SEC_EXCLUDE),
                    ADD_VALUE (SEC_SORT_ENTRIES),
                    ADD_VALUE (SEC_LINK_ONCE),
                    ADD_VALUE (SEC_LINK_DUPLICATES),
                    ADD_VALUE (SEC_LINK_DUPLICATES_DISCARD),
                    ADD_VALUE (SEC_LINK_DUPLICATES_ONE_ONLY),
                    ADD_VALUE (SEC_LINK_DUPLICATES_SAME_SIZE),
                    ADD_VALUE (SEC_LINK_DUPLICATES_SAME_CONTENTS),
                    ADD_VALUE (SEC_LINKER_CREATED ),
                    ADD_VALUE (SEC_KEEP),
                    ADD_VALUE (SEC_SMALL_DATA ),
                    ADD_VALUE (SEC_MERGE),
                    ADD_VALUE (SEC_STRINGS),
                    ADD_VALUE (SEC_GROUP),
                    ADD_VALUE (SEC_COFF_SHARED_LIBRARY),
                    ADD_VALUE (SEC_ELF_REVERSE_COPY),
                    ADD_VALUE (SEC_COFF_SHARED),
                    ADD_VALUE (SEC_TIC54X_BLOCK),
                    ADD_VALUE (SEC_TIC54X_CLINK),
                    ADD_VALUE (SEC_COFF_NOREAD)
                  };

static const char *get_file_flags (flagword flags)
{
  return flags_decode (flags, file_flgs, DIM(file_flgs));
}

static const char *get_sym_flags (flagword flags)
{
  return flags_decode (flags & ~BSF_NOT_AT_END, sym_flgs, DIM(sym_flgs));
}

static const char *get_sec_flags (flagword flags)
{
  return flags_decode (flags, sec_flgs, DIM(sec_flgs));
}

/*
 * Loop over all symbols in this section and find the closest
 * (nearest lower) address specified in 'find->address'.
 */
static int find_address_in_section (struct BFD_table   *BFD,
                                    struct bfd_section *sec,
                                    struct find_data   *find)
{
  struct bfd_symbol **syms;
  struct bfd_symbol  *sym;
  struct bfd_symbol  *nearest_sym = NULL;
  bfd_vma             vma, size;
  flagword            flags = bfd_get_section_flags (BFD->BFD,sec);

  TRACE (5, "section-name: %s, section-flags: %s.\n",
         bfd_get_section_name(BFD->BFD,sec), get_sec_flags(flags));

  if (!(flags & SEC_ALLOC))
     return (0);

  vma = bfd_get_section_vma (BFD->BFD, sec);
  if (find->address < vma)
     return (0);

  size = bfd_get_section_size (sec);
  if (find->address >= vma + size)
     return (0);

  syms = BFD->sym_tab;
  sym = syms[0];

#define USE_BFD_NEAREST_LINE 0

#if USE_BFD_NEAREST_LINE
  do
  {
    if (/*sec == bfd_get_section(sym) && */
        (bfd_find_line (BFD->BFD, syms, sym, &find->file, &find->line) ||
         bfd_find_nearest_line (BFD->BFD, bfd_get_section(sym), syms,
                                find->address - vma, &find->file, &find->name, &find->line)))
    {
      find->module = shorten_path (BFD->module);
      return  (1);
    }
  }
  while (sym++);

#else

  int i;

  for (i = 0; i < BFD->sym_count; i++, sym++)
  {
    bfd_vma diff;

    if (!sym->name || sym->name[0] == '.')
       continue;

    diff = find->address - vma;
    if (bfd_get_section(sym) == sec && diff >= sym->value)
    {
      if (!nearest_sym || sym->value > nearest_sym->value)
      {
//      find->offset = find->address - BFD->base_addr - sym->value;
        find->offset = find->address - vma - sym->value;
        nearest_sym  = sym;
      }
    }
  }

  if (nearest_sym)
  {
    find->name   = bfd_asymbol_name (nearest_sym);
    find->module = shorten_path (BFD->module);
    bfd_find_line (BFD->BFD, syms, nearest_sym, &find->file, &find->line);
    return (1);
  }
#endif
  return (0);
}

int BFD_get_function_name (bfd_vma address, char *ret_buf, size_t buf_size)
{
  static char buf[300];
  struct BFD_table *BFD = BFD_table;
  int    i;

  *ret_buf = '\0';

  for (i = 0; i < BFD_table_top; BFD++, i++)
  {
    struct find_data    find;
    struct bfd_section *sec;

    if (address < BFD->base_addr || address >= (BFD->base_addr + BFD->mod_size))
       continue;

    find.address = address;
    find.offset  = 0;
    find.line    = 0;
    find.file    = "?";

    /* Loop over all sections ('sec') in this BFD and find the closest
     * (nearest lower) address that has a public symbol in 'BFD->sym_tab'.
     */
    for (sec = BFD->BFD->sections; sec; sec = sec->next)
    {
      if (find_address_in_section(BFD,sec,&find))
      {
        snprintf (ret_buf, buf_size, VMA_X_FMT ": %s!%s+%lXh",
                  address, find.module, find.name, find.offset);
        return (0);
      }
    }
  }
  return (-1);
}

#ifdef NOT_USED
/*
 * Retrieves the base address of the module that contains the specified address.
 */
static DWORD get_module_base (DWORD address)
{
  MEMORY_BASIC_INFORMATION buf;

  if (VirtualQuery((LPCVOID)address, &buf, sizeof(buf)))
     return (DWORD)buf.AllocationBase;
  return (0);
}

#define SPRINTF_VMA(buf,val) sprintf (buf, VMA_X_FMT, val)

extern char _image_base__;

static bfd_vma BFD_adjust_vma (DWORD addr)
{
  bfd_vma   mod_base = (bfd_vma) &_image_base__;
  bfd_vma   adjust   = mod_base - get_module_base(addr);
  char buf1 [20];
  char buf2 [20];

  SPRINTF_VMA (buf1, mod_base);
  SPRINTF_VMA (buf2, adjust);

  TRACE (1, "mod_base: %s, adjust: %s\n", buf1, buf2);

  /* If we are adjusting section VMA's, change them all now. Changing
   * the BFD information is a hack. However, we must do it, or
   * bfd_find_nearest_line() will not do the right thing.
   */
  if (adjust)
  {
    int i;

    for (i = 0; i < BFD_table_top; i++)
    {
      struct bfd_section *s;

      for (s = BFD->BFD->sections; s; s = s->next)
      {
        s->vma += adjust;
        s->lma += adjust;
      }
    }
  }
  return (adjust);
}
#endif  /* NOT_USED */
#endif  /* USE_BFD */

