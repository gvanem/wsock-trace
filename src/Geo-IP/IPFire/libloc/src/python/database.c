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

#include <Python.h>

#include <loc/libloc.h>
#include <loc/database.h>

// #undef  LIBLOC_PRIVATE
// #define LIBLOC_PRIVATE
#include <loc/private.h>

#include "locationmodule.h"
#include "as.h"
#include "country.h"
#include "database.h"
#include "network.h"

static PyObject* Database_new(PyTypeObject* type, PyObject* args, PyObject* kwds) {
	DatabaseObject* self = (DatabaseObject*)type->tp_alloc(type, 0);

	return (PyObject*)self;
}

static void Database_dealloc(DatabaseObject* self) {
	if (self->db)
		loc_database_unref(self->db);

	if (self->path)
		free(self->path);

	Py_TYPE(self)->tp_free((PyObject* )self);
}

static int Database_init(DatabaseObject* self, PyObject* args, PyObject* kwargs) {
	const char* path = NULL;

	if (!PyArg_ParseTuple(args, "s", &path))
		return -1;

	self->path = strdup(path);

	// Open the file for reading
	FILE* f = fopen(self->path, "rb");
	if (!f) {
		PyErr_SetFromErrno(PyExc_IOError);
		return -1;
	}

	// Load the database
	int r = loc_database_new(loc_ctx, &self->db, f);
	fclose(f);

	// Return on any errors
	if (r)
		return -1;

	return 0;
}

static PyObject* Database_repr(DatabaseObject* self) {
	return PyUnicode_FromFormat("<Database %s>", self->path);
}

static PyObject* Database_verify(DatabaseObject* self, PyObject* args) {
	PyObject* public_key = NULL;
	FILE* f = NULL;

	// Parse arguments
	if (!PyArg_ParseTuple(args, "O", &public_key))
		return NULL;

	// Convert into FILE*
	int fd = PyObject_AsFileDescriptor(public_key);
	if (fd < 0)
		return NULL;

	// Re-open file descriptor
	f = fdopen(fd, "rb");
	if (!f) {
		PyErr_SetFromErrno(PyExc_IOError);
		return NULL;
	}

	int r = loc_database_verify(self->db, f);

	if (r == 0)
		Py_RETURN_TRUE;

	Py_RETURN_FALSE;
}

static PyObject* Database_get_description(DatabaseObject* self) {
	const char* description = loc_database_get_description(self->db);

	return PyUnicode_FromString(description);
}

static PyObject* Database_get_vendor(DatabaseObject* self) {
	const char* vendor = loc_database_get_vendor(self->db);

	return PyUnicode_FromString(vendor);
}

static PyObject* Database_get_license(DatabaseObject* self) {
	const char* license = loc_database_get_license(self->db);

	return PyUnicode_FromString(license);
}

static PyObject* Database_get_created_at(DatabaseObject* self) {
	time_t created_at = loc_database_created_at(self->db);

	return PyLong_FromLong(created_at);
}

static PyObject* Database_get_as(DatabaseObject* self, PyObject* args) {
	struct loc_as* as = NULL;
	uint32_t number = 0;

	if (!PyArg_ParseTuple(args, "i", &number))
		return NULL;

	// Try to retrieve the AS
	int r = loc_database_get_as(self->db, &as, number);

	// We got an AS
	if (r == 0) {
		PyObject* obj = new_as(&ASType, as);
		loc_as_unref(as);

		return obj;

	// Nothing found
	} else if (r == 1) {
		Py_RETURN_NONE;
	}

	// Unexpected error
	return NULL;
}

static PyObject* Database_get_country(DatabaseObject* self, PyObject* args) {
	const char* country_code = NULL;

	if (!PyArg_ParseTuple(args, "s", &country_code))
		return NULL;

	struct loc_country* country;
	int r = loc_database_get_country(self->db, &country, country_code);
	if (r) {
		Py_RETURN_NONE;
	}

	PyObject* obj = new_country(&CountryType, country);
	loc_country_unref(country);

	return obj;
}

static PyObject* Database_lookup(DatabaseObject* self, PyObject* args) {
	struct loc_network* network = NULL;
	const char* address = NULL;

	if (!PyArg_ParseTuple(args, "s", &address))
		return NULL;

	// Try to retrieve a matching network
	int r = loc_database_lookup_from_string(self->db, address, &network);

	// We got a network
	if (r == 0) {
		PyObject* obj = new_network(&NetworkType, network);
		loc_network_unref(network);

		return obj;

	// Nothing found
	} else if (r == 1) {
		Py_RETURN_NONE;

	// Invalid input
	} else if (r == -EINVAL) {
		PyErr_Format(PyExc_ValueError, "Invalid IP address: %s", address);
		return NULL;
	}

	// Unexpected error
	return NULL;
}

static PyObject* new_database_enumerator(PyTypeObject* type, struct loc_database_enumerator* enumerator) {
	DatabaseEnumeratorObject* self = (DatabaseEnumeratorObject*)type->tp_alloc(type, 0);
	if (self) {
		self->enumerator = loc_database_enumerator_ref(enumerator);
	}

	return (PyObject*)self;
}

static PyObject* Database_iterate_all(DatabaseObject* self, enum loc_database_enumerator_mode what) {
	struct loc_database_enumerator* enumerator;

	int r = loc_database_enumerator_new(&enumerator, self->db, what);
	if (r) {
		PyErr_SetFromErrno(PyExc_SystemError);
		return NULL;
	}

	PyObject* obj = new_database_enumerator(&DatabaseEnumeratorType, enumerator);
	loc_database_enumerator_unref(enumerator);

	return obj;
}

static PyObject* Database_ases(DatabaseObject* self) {
	return Database_iterate_all(self, LOC_DB_ENUMERATE_ASES);
}

static PyObject* Database_search_as(DatabaseObject* self, PyObject* args) {
	const char* string = NULL;

	if (!PyArg_ParseTuple(args, "s", &string))
		return NULL;

	struct loc_database_enumerator* enumerator;

	int r = loc_database_enumerator_new(&enumerator, self->db, LOC_DB_ENUMERATE_ASES);
	if (r) {
		PyErr_SetFromErrno(PyExc_SystemError);
		return NULL;
	}

	// Search string we are searching for
	loc_database_enumerator_set_string(enumerator, string);

	PyObject* obj = new_database_enumerator(&DatabaseEnumeratorType, enumerator);
	loc_database_enumerator_unref(enumerator);

	return obj;
}

static PyObject* Database_networks(DatabaseObject* self) {
	return Database_iterate_all(self, LOC_DB_ENUMERATE_NETWORKS);
}

static PyObject* Database_search_networks(DatabaseObject* self, PyObject* args, PyObject* kwargs) {
	char* kwlist[] = { "country_code", "asn", "flags", "family", NULL };
	const char* country_code = NULL;
	unsigned int asn = 0;
	int flags = 0;
	int family = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|siii", kwlist, &country_code, &asn, &flags, &family))
		return NULL;

	struct loc_database_enumerator* enumerator;
	int r = loc_database_enumerator_new(&enumerator, self->db, LOC_DB_ENUMERATE_NETWORKS);
	if (r) {
		PyErr_SetFromErrno(PyExc_SystemError);
		return NULL;
	}

	// Set country code we are searching for
	if (country_code) {
		r = loc_database_enumerator_set_country_code(enumerator, country_code);

		if (r) {
			PyErr_SetFromErrno(PyExc_SystemError);
			return NULL;
		}
	}

	// Set the ASN we are searching for
	if (asn) {
		r = loc_database_enumerator_set_asn(enumerator, asn);

		if (r) {
			PyErr_SetFromErrno(PyExc_SystemError);
			return NULL;
		}
	}

	// Set the flags we are searching for
	if (flags) {
		r = loc_database_enumerator_set_flag(enumerator, flags);

		if (r) {
			PyErr_SetFromErrno(PyExc_SystemError);
			return NULL;
		}
	}

	// Set the family we are searching for
	if (family) {
		r = loc_database_enumerator_set_family(enumerator, family);

		if (r) {
			PyErr_SetFromErrno(PyExc_SystemError);
			return NULL;
		}
	}

	PyObject* obj = new_database_enumerator(&DatabaseEnumeratorType, enumerator);
	loc_database_enumerator_unref(enumerator);

	return obj;
}

static PyObject* Database_countries(DatabaseObject* self) {
	return Database_iterate_all(self, LOC_DB_ENUMERATE_COUNTRIES);
}

static struct PyMethodDef Database_methods[] = {
	{
		"get_as",
		(PyCFunction)Database_get_as,
		METH_VARARGS,
		NULL,
	},
	{
		"get_country",
		(PyCFunction)Database_get_country,
		METH_VARARGS,
		NULL,
	},
	{
		"lookup",
		(PyCFunction)Database_lookup,
		METH_VARARGS,
		NULL,
	},
	{
		"search_as",
		(PyCFunction)Database_search_as,
		METH_VARARGS,
		NULL,
	},
	{
		"search_networks",
		(PyCFunction)Database_search_networks,
		METH_VARARGS|METH_KEYWORDS,
		NULL,
	},
	{
		"verify",
		(PyCFunction)Database_verify,
		METH_VARARGS,
		NULL,
	},
	{ NULL },
};

static struct PyGetSetDef Database_getsetters[] = {
	{
		"ases",
		(getter)Database_ases,
		NULL,
		NULL,
		NULL,
	},
	{
		"countries",
		(getter)Database_countries,
		NULL,
		NULL,
		NULL,
	},
	{
		"created_at",
		(getter)Database_get_created_at,
		NULL,
		NULL,
		NULL,
	},
	{
		"description",
		(getter)Database_get_description,
		NULL,
		NULL,
		NULL,
	},
	{
		"license",
		(getter)Database_get_license,
		NULL,
		NULL,
		NULL,
	},
	{
		"networks",
		(getter)Database_networks,
		NULL,
		NULL,
		NULL,
	},
	{
		"vendor",
		(getter)Database_get_vendor,
		NULL,
		NULL,
		NULL,
	},
	{ NULL },
};

PyTypeObject DatabaseType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name =               "location.Database",
	.tp_basicsize =          sizeof(DatabaseObject),
	.tp_flags =              Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
	.tp_new =                Database_new,
	.tp_dealloc =            (destructor)Database_dealloc,
	.tp_init =               (initproc)Database_init,
	.tp_doc =                "Database object",
	.tp_methods =            Database_methods,
	.tp_getset =             Database_getsetters,
	.tp_repr =               (reprfunc)Database_repr,
};

static PyObject* DatabaseEnumerator_new(PyTypeObject* type, PyObject* args, PyObject* kwds) {
	DatabaseEnumeratorObject* self = (DatabaseEnumeratorObject*)type->tp_alloc(type, 0);

	return (PyObject*)self;
}

static void DatabaseEnumerator_dealloc(DatabaseEnumeratorObject* self) {
	loc_database_enumerator_unref(self->enumerator);

	Py_TYPE(self)->tp_free((PyObject* )self);
}

static PyObject* DatabaseEnumerator_next(DatabaseEnumeratorObject* self) {
	struct loc_network* network = NULL;

	// Enumerate all networks
	int r = loc_database_enumerator_next_network(self->enumerator, &network);
	if (r) {
		PyErr_SetFromErrno(PyExc_ValueError);
		return NULL;
	}

	// A network was found
	if (network) {
		PyObject* obj = new_network(&NetworkType, network);
		loc_network_unref(network);

		return obj;
	}

	// Enumerate all ASes
	struct loc_as* as = NULL;

	r = loc_database_enumerator_next_as(self->enumerator, &as);
	if (r) {
		PyErr_SetFromErrno(PyExc_ValueError);
		return NULL;
	}

	if (as) {
		PyObject* obj = new_as(&ASType, as);
		loc_as_unref(as);

		return obj;
	}

	// Enumerate all countries
	struct loc_country* country = NULL;

	r = loc_database_enumerator_next_country(self->enumerator, &country);
	if (r) {
		PyErr_SetFromErrno(PyExc_ValueError);
		return NULL;
	}

	if (country) {
		PyObject* obj = new_country(&CountryType, country);
		loc_country_unref(country);

		return obj;
	}

	// Nothing found, that means the end
	PyErr_SetNone(PyExc_StopIteration);
	return NULL;
}

PyTypeObject DatabaseEnumeratorType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name =               "location.DatabaseEnumerator",
	.tp_basicsize =          sizeof(DatabaseEnumeratorObject),
	.tp_flags =              Py_TPFLAGS_DEFAULT,
	.tp_alloc =              PyType_GenericAlloc,
	.tp_new =                DatabaseEnumerator_new,
	.tp_dealloc =            (destructor)DatabaseEnumerator_dealloc,
	.tp_iter =               PyObject_SelfIter,
	.tp_iternext =           (iternextfunc)DatabaseEnumerator_next,
};
