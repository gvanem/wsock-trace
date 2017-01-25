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

#if !defined(_X86_)
//  #error Only INTEL environments are supported!
#endif

extern BOOL  StackWalkInit (void);
extern BOOL  StackWalkExit (void);
extern char *StackWalkShow (HANDLE thread, CONTEXT *c);

#endif  /* __STACKWALKER_H__ */
