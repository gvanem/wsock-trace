/*
 *  File:
 *    stkwalk.h
 *
 *  Original author:
 *    Jochen Kalmbach
 *
 *  Heavily modified by:
 *    Gisle Vanem
 */

#ifndef __STACKWALKER_H__
#define __STACKWALKER_H__

#include "smartlist.h"

typedef struct ModuleSymbolStats {
        DWORD  num_syms;            /* # of PDB-symbols found in this module */
        DWORD  num_other_syms;
        DWORD  num_our_syms;
        DWORD  num_cpp_syms;
        DWORD  num_junk_syms;
        DWORD  num_data_syms;
        DWORD  num_syms_lines;
      } ModuleSymbolStats;

typedef struct ModuleEntry {
        char             *module_name;   /* fully qualified name of module */
        ULONG_PTR         base_addr;
        DWORD             size;
        ModuleSymbolStats stat;
      } ModuleEntry;

typedef struct SymbolEntry {
        ULONG_PTR  addr;
        char      *module;        /* points to the above 'module_name' */
        char      *func_name;
        char      *file_name;
        unsigned   line_number;
        unsigned   ofs_from_line;
      } SymbolEntry;

extern BOOL  StackWalkInit (void);
extern BOOL  StackWalkExit (void);
extern char *StackWalkShow (HANDLE thread, CONTEXT *ctx);

/* These returns smartlists for modules and symbols. A list of
 * 'struct ModuleEntry *' and 'struct SymbolEntry *' respectively.
 * 'modules_list' and 'symbols_list' can be NULL if only the return
 * value is wanted.
 *
 * The return values are the number of items in each of the lists.
 */
extern DWORD StackWalkModules (smartlist_t **modules_list);
extern DWORD StackWalkSymbols (smartlist_t **symbols_list);

#endif  /* __STACKWALKER_H__ */
