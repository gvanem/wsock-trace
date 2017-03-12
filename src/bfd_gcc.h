#ifndef _BFD_GCC_H
#define _BFD_GCC_H

#if defined(USE_BFD)
  /*
   * Recent <bfd.h> needs these defines:
   */
  #ifndef PACKAGE
  #define PACKAGE         "??"
  #endif

  #ifndef PACKAGE_VERSION
  #define PACKAGE_VERSION "??"
  #endif

  #include "bfd.h"    /* BFD: the Binary File Descriptor library. */

  extern void  BFD_init (void);
  extern int   BFD_load_debug_symbols (const char *fname, bfd_vma base_addr, DWORD mod_size);
  extern void  BFD_unload_debug_symbols (const char *fname);
  extern void  BFD_unload_all_symbols (void);
  extern void  BFD_dump (void);
  extern int   BFD_get_function_name (bfd_vma address, char *ret_buf, size_t buf_size);
  extern int   BFD_demangle (const char *module, const char *raw_name, char *und_name, size_t und_size);
#endif

#endif
