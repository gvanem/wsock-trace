/**\file    idna.h
 * \ingroup Misc
 */
#ifndef _IDNA_H
#define _IDNA_H

#include <stdlib.h>
#include <windows.h>

extern int _idna_errno, _idna_winnls_errno;

enum IDNA_errors {
     IDNAERR_OK = 0,
     IDNAERR_NOT_INIT,
     IDNAERR_ALREADY_PFX,
     IDNAERR_PUNYCODE_BASE,
     IDNAERR_PUNYCODE_BAD_INPUT,
     IDNAERR_PUNYCODE_BIG_OUTBUF,
     IDNAERR_PUNYCODE_OVERFLOW,
     IDNAERR_PUNY_ENCODE,
     IDNAERR_ILL_CODEPAGE,
     IDNAERR_WINNLS       /* specific error in _idna_winnls_errno */
   };

extern BOOL        IDNA_init (WORD code_page, BOOL use_winidn);
extern void        IDNA_exit (void);
extern const char *IDNA_strerror (int err);
extern BOOL        IDNA_is_ASCII (const char *name);

extern BOOL IDNA_convert_to_ACE   (char *name, size_t *size);
extern BOOL IDNA_convert_from_ACE (char *name, size_t *size);
extern UINT IDNA_GetCodePage      (void);

#endif  /* _IDNA_H */

