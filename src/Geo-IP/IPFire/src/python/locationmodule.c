/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2017-2021 IPFire Development Team <info@ipfire.org>

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.

	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
*/

#include <Python.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#include <libloc/format.h>
#include <libloc/resolv.h>
#include <libloc/version.h>

#include "locationmodule.h"
#include "as.h"
#include "country.h"
#include "database.h"
#include "network.h"
#include "writer.h"

#ifndef LIBLOC_DEFAULT_DATABASE_PATH
#define LIBLOC_DEFAULT_DATABASE_PATH "."
#endif

/* Declare global context */
struct loc_ctx* loc_ctx;

PyMODINIT_FUNC PyInit__location(void);

static void location_free(void) {
	// Release context
	if (loc_ctx)
		loc_unref(loc_ctx);
}

PyObject* location_raise(int r) {
	// The library returns negative error numbers
	if (r < 0)
		errno = -r;
	else
		errno = EIO;

	return PyErr_SetFromErrno(PyExc_OSError);
}

PyObject* location_string(const char* s) {
	if (!s)
		Py_RETURN_NONE;

	return PyUnicode_FromString(s);
}

int location_string_arg(PyObject* value, const char** s, int nullable) {
	// The attribute is being deleted or set to None
	if (!value || value == Py_None) {
		if (!nullable) {
			PyErr_SetString(PyExc_TypeError, "This attribute cannot be removed");
			return -1;
		}

		*s = NULL;
		return 0;
	}

	if (!PyUnicode_Check(value)) {
		PyErr_Format(PyExc_TypeError, "Expected a string, got %s", Py_TYPE(value)->tp_name);
		return -1;
	}

	*s = PyUnicode_AsUTF8(value);
	if (!*s)
		return -1;

	return 0;
}

FILE* location_fopen(PyObject* object) {
	FILE* f = NULL;

	int fd = PyObject_AsFileDescriptor(object);
	if (fd < 0)
		return NULL;

	// The file descriptor belongs to the file object and
	// would be closed with the stream if we did not copy it.
	fd = dup(fd);
	if (fd < 0) {
		PyErr_SetFromErrno(PyExc_OSError);
		return NULL;
	}

	f = fdopen(fd, "r");
	if (!f) {
		PyErr_SetFromErrno(PyExc_OSError);
		close(fd);
	}

	return f;
}

int location_parse_asn(PyObject* object, void* number) {
	// AS numbers are unsigned and do not fit into an int
	unsigned long n = PyLong_AsUnsignedLong(object);
	if (n == (unsigned long)-1 && PyErr_Occurred())
		return 0;

	if (n > UINT32_MAX) {
		PyErr_SetString(PyExc_OverflowError, "AS number is out of range");
		return 0;
	}

	*(uint32_t*)number = n;

	return 1;
}

static PyObject* set_log_level(PyObject* m, PyObject* args) {
	int priority = LOG_INFO;

	if (!PyArg_ParseTuple(args, "i", &priority))
		return NULL;

	loc_set_log_priority(loc_ctx, priority);

	Py_RETURN_NONE;
}

static PyObject* discover_latest_version(PyObject* m, PyObject* args) {
	unsigned int version = LOC_DATABASE_VERSION_LATEST;

	if (!PyArg_ParseTuple(args, "|i", &version))
		return NULL;

	time_t t = 0;
	int r;

	// Waiting for the DNS can take a while
	Py_BEGIN_ALLOW_THREADS
	r = loc_discover_latest_version(loc_ctx, version, &t);
	Py_END_ALLOW_THREADS
	if (r)
		Py_RETURN_NONE;

	return PyLong_FromUnsignedLong(t);
}

static PyObject* country_code_is_valid(PyObject* m, PyObject* args) {
	const char* country_code = NULL;

	if (!PyArg_ParseTuple(args, "s", &country_code))
		return NULL;

	if (loc_country_code_is_valid(country_code))
		Py_RETURN_TRUE;

	Py_RETURN_FALSE;
}

static PyMethodDef location_module_methods[] = {
	{
		"country_code_is_valid",
		(PyCFunction)country_code_is_valid,
		METH_VARARGS,
		NULL,
	},
	{
		"discover_latest_version",
		(PyCFunction)discover_latest_version,
		METH_VARARGS,
		NULL,
	},
	{
		"set_log_level",
		(PyCFunction)set_log_level,
		METH_VARARGS,
		NULL,
	},
	{ NULL },
};

static struct PyModuleDef location_module = {
	.m_base = PyModuleDef_HEAD_INIT,
	.m_name = "_location",
	.m_size = -1,
	.m_doc = "Python module for libloc",
	.m_methods = location_module_methods,
	.m_free = (freefunc)location_free,
};

PyMODINIT_FUNC PyInit__location(void) {
	// Initialise loc context
	int r = loc_new(&loc_ctx);
	if (r)
		return NULL;

	PyObject* m = PyModule_Create(&location_module);
	if (!m)
		return NULL;

	// Version
	if (PyModule_AddStringConstant(m, "__version__", PACKAGE_VERSION))
		return NULL;

	// Default Database Path
	if (PyModule_AddStringConstant(m, "DATABASE_PATH", LIBLOC_DEFAULT_DATABASE_PATH))
		return NULL;

	// AS
	if (PyType_Ready(&ASType) < 0)
		return NULL;

	Py_INCREF(&ASType);
	PyModule_AddObject(m, "AS", (PyObject *)&ASType);

	// Country
	if (PyType_Ready(&CountryType) < 0)
		return NULL;

	Py_INCREF(&CountryType);
	PyModule_AddObject(m, "Country", (PyObject *)&CountryType);

	// Database
	if (PyType_Ready(&DatabaseType) < 0)
		return NULL;

	Py_INCREF(&DatabaseType);
	PyModule_AddObject(m, "Database", (PyObject *)&DatabaseType);

	// Database Enumerator
	if (PyType_Ready(&DatabaseEnumeratorType) < 0)
		return NULL;

	Py_INCREF(&DatabaseEnumeratorType);
	PyModule_AddObject(m, "DatabaseEnumerator", (PyObject *)&DatabaseEnumeratorType);

	// Network
	if (PyType_Ready(&NetworkType) < 0)
		return NULL;

	Py_INCREF(&NetworkType);
	PyModule_AddObject(m, "Network", (PyObject *)&NetworkType);

	// Writer
	if (PyType_Ready(&WriterType) < 0)
		return NULL;

	Py_INCREF(&WriterType);
	PyModule_AddObject(m, "Writer", (PyObject *)&WriterType);

	// Add flags
	if (PyModule_AddIntConstant(m, "NETWORK_FLAG_ANONYMOUS_PROXY", LOC_NETWORK_FLAG_ANONYMOUS_PROXY))
		return NULL;

	if (PyModule_AddIntConstant(m, "NETWORK_FLAG_SATELLITE_PROVIDER", LOC_NETWORK_FLAG_SATELLITE_PROVIDER))
		return NULL;

	if (PyModule_AddIntConstant(m, "NETWORK_FLAG_ANYCAST", LOC_NETWORK_FLAG_ANYCAST))
		return NULL;

	if (PyModule_AddIntConstant(m, "NETWORK_FLAG_DROP", LOC_NETWORK_FLAG_DROP))
		return NULL;

	// Add latest database version
	if (PyModule_AddIntConstant(m, "DATABASE_VERSION_LATEST", LOC_DATABASE_VERSION_LATEST))
		return NULL;

	return m;
}
