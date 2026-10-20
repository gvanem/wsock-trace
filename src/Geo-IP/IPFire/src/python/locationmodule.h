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

#ifndef PYTHON_LOCATION_MODULE_H
#define PYTHON_LOCATION_MODULE_H

#include <Python.h>

#include <libloc/libloc.h>

extern struct loc_ctx* loc_ctx;

// Raises an exception for an error code that the library has returned
PyObject* location_raise(int r);

// Returns a string, or None if there is none
PyObject* location_string(const char* s);

// Converts the value that is being assigned to an attribute into a string.
// If nullable, None (or deleting the attribute) becomes NULL.
int location_string_arg(PyObject* value, const char** s, int nullable);

// Opens a file object for reading. The stream has to be closed by the caller,
// which does not close the file object.
FILE* location_fopen(PyObject* object);

// Converts a Python integer into an AS number (to be used with "O&")
int location_parse_asn(PyObject* object, void* number);

#endif /* PYTHON_LOCATION_MODULE_H */
