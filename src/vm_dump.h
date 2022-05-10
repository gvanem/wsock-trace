/**
 * \file vm_dump.h
 * \ingroup Misc
 */
#ifndef _VM_DUMP_H
#define _VM_DUMP_H

#include <stdio.h>

extern int   vm_bug_debug;
extern int   vm_bug_indent;
extern FILE *vm_bug_stream;

extern void vm_bug_report (void);
extern void vm_bug_list (int skip, void *list);
extern void vm_bug_abort_init (void);

#define VM_ASSERT(expression)                                       \
        do {                                                        \
          if (!(expression)) {                                      \
             fprintf (stderr, "\n%s(%u): Assertion failed: '%s'\n", \
                     __FILE__, __LINE__, #expression);              \
             if (vm_bug_debug == 0)                                 \
                vm_bug_debug = 2;                                   \
             vm_bug_list (4, NULL);                                 \
             _exit (-1);                                            \
          }                                                         \
        } while (0)

#endif
