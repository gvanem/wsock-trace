/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2017 IPFire Development Team <info@ipfire.org>

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/

#ifndef LIBLOC_H
#define LIBLOC_H

#if !defined(LIBLOC_USING_WINSOCK2)    /* if not defined in makefile */
  #if defined(_WIN32)                  /* not a built-in in Cygwin */
    #define LIBLOC_USING_WINSOCK2
  #elif defined(__CYGWIN__) && defined(__USE_W32_SOCKETS)
    #define LIBLOC_USING_WINSOCK2      /* if not using POSIX sockets in Cygwin */
  #endif
#endif

#if defined(LIBLOC_USING_WINSOCK2)
  #include <sys/types.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windns.h>
  #include <libloc/compat.h>

#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
#endif

#if defined(LIBLOC_LUAJIT_HACKS)
  #include <lua.h>
  #include <lauxlib.h>
  #include <libloc/luajit-hacks.h>
#endif

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

struct loc_ctx;
struct loc_ctx *loc_ref(struct loc_ctx* ctx);
struct loc_ctx *loc_unref(struct loc_ctx* ctx);

int loc_new(struct loc_ctx** ctx);
void loc_set_log_fn(struct loc_ctx* ctx,
	void (*log_fn)(struct loc_ctx* ctx,
	int priority, const char* file, int line, const char* fn,
	const char* format, va_list args));
int loc_get_log_priority(struct loc_ctx* ctx);
void loc_set_log_priority(struct loc_ctx* ctx, int priority);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
