/**\file    xz_decompress.h
 * \ingroup Misc
 */
#ifndef _XZ_DECOMPRESS_H
#define _XZ_DECOMPRESS_H

extern int         XZ_decompress (const char *from_file, const char *to_file);
extern const char *XZ_strerror (int rc);

#endif
