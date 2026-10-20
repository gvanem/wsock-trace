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

#include <libloc/libloc.h>
#include <libloc/as.h>
#include <libloc/as-list.h>
#include <libloc/database.h>
//#include <libloc/private.h>

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
	int r;

	// Parse arguments
	if (!PyArg_ParseTuple(args, "s", &path))
		return -1;

	// Copy path
	self->path = strdup(path);
	if (!self->path) {
		PyErr_NoMemory();
		return -1;
	}

	// Open the database. It knows where its file is, and
	// reads it again every once in a while if it has been replaced.
	r = loc_database_open(loc_ctx, &self->db, self->path);
	if (r) {
		// The library returns negative error numbers
		errno = -r;

		PyErr_SetFromErrnoWithFilename(PyExc_OSError, path);
		return -1;
	}

	return 0;
}

static PyObject* Database_repr(DatabaseObject* self) {
	return PyUnicode_FromFormat("<Database %s>", self->path);
}

static PyObject* Database_reload(DatabaseObject* self) {
	int r;

	// Reading a new database takes a moment, and other threads can use
	// the database in the meantime
	Py_BEGIN_ALLOW_THREADS
	r = loc_database_reload(self->db);
	Py_END_ALLOW_THREADS

	// There was a new file
	if (r == 0)
		Py_RETURN_TRUE;

	// Nothing has changed
	else if (r > 0)
		Py_RETURN_FALSE;

	return location_raise(r);
}

static PyObject* Database_verify(DatabaseObject* self, PyObject* args) {
	PyObject* public_key = NULL;
	FILE* f = NULL;

	// Parse arguments
	if (!PyArg_ParseTuple(args, "O", &public_key))
		return NULL;

	// Open the key
	f = location_fopen(public_key);
	if (!f)
		return NULL;

	int r;

	// Verifying reads the entire database, and other threads can use it in the meantime
	Py_BEGIN_ALLOW_THREADS

	r = loc_database_verify(self->db, f);
	fclose(f);
	Py_END_ALLOW_THREADS

	// The signature is valid
	if (r == 0)
		Py_RETURN_TRUE;

	// The signature is not valid, there is no signature, or the key is not a key
	else if (r > 0 || r == -EINVAL)
		Py_RETURN_FALSE;

	// Anything else has gone wrong
	return location_raise(r);
}

static PyObject* Database_get_description(DatabaseObject* self) {
	const char* description = loc_database_get_description(self->db);
	if (!description)
		Py_RETURN_NONE;

	return location_string(description);
}

static PyObject* Database_get_vendor(DatabaseObject* self) {
	const char* vendor = loc_database_get_vendor(self->db);
	if (!vendor)
		Py_RETURN_NONE;

	return location_string(vendor);
}

static PyObject* Database_get_license(DatabaseObject* self) {
	const char* license = loc_database_get_license(self->db);
	if (!license)
		Py_RETURN_NONE;

	return location_string(license);
}

static PyObject* Database_get_created_at(DatabaseObject* self) {
	time_t created_at = loc_database_created_at(self->db);

	return PyLong_FromLongLong(created_at);
}

static PyObject* Database_get_as(DatabaseObject* self, PyObject* args) {
	struct loc_as* as = NULL;
	uint32_t number = 0;

	if (!PyArg_ParseTuple(args, "O&", location_parse_asn, &number))
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
	return location_raise(r);
}

static PyObject* Database_get_country(DatabaseObject* self, PyObject* args) {
	struct loc_country* country = NULL;
	const char* country_code = NULL;

	if (!PyArg_ParseTuple(args, "s", &country_code))
		return NULL;

	// Fetch the country
	int r = loc_database_get_country(self->db, &country, country_code);
	if (r) {
		switch (r) {
			case -EINVAL:
				PyErr_SetString(PyExc_ValueError, "Invalid country code");
				break;

			default:
				location_raise(r);
				break;
		}

		return NULL;
	}

	// No result
	if (!country)
		Py_RETURN_NONE;

	PyObject* obj = new_country(&CountryType, country);
	loc_country_unref(country);

	return obj;
}

static PyObject* Database_lookup(DatabaseObject* self, PyObject* args) {
	struct loc_network* network = NULL;
	const char* address = NULL;
	int r;

	if (!PyArg_ParseTuple(args, "s", &address))
		return NULL;

	// Try to retrieve a matching network
	r = loc_database_lookup_from_string(self->db, address, &network);
	if (r) {
		// Handle any errors
		switch (r) {
			case -EINVAL:
				PyErr_Format(PyExc_ValueError, "Invalid IP address: %s", address);
				break;

			default:
				location_raise(r);
				break;
		}

		return NULL;
	}

	// Nothing found
	if (!network)
		Py_RETURN_NONE;

	// We got a network
	PyObject* obj = new_network(&NetworkType, network);
	loc_network_unref(network);

	return obj;
}

static PyObject* new_database_enumerator(PyTypeObject* type, struct loc_database_enumerator* enumerator) {
	DatabaseEnumeratorObject* self = (DatabaseEnumeratorObject*)type->tp_alloc(type, 0);
	if (self) {
		self->enumerator = loc_database_enumerator_ref(enumerator);
	}

	return (PyObject*)self;
}

static PyObject* Database_iterate_all(DatabaseObject* self,
		enum loc_database_enumerator_mode what, int family, int flags) {
	struct loc_database_enumerator* enumerator;

	int r = loc_database_enumerator_new(&enumerator, self->db, what, flags);
	if (r) {
		location_raise(r);
		return NULL;
	}

	// Set family
	if (family)
		loc_database_enumerator_set_family(enumerator, family);

	PyObject* obj = new_database_enumerator(&DatabaseEnumeratorType, enumerator);
	loc_database_enumerator_unref(enumerator);

	return obj;
}

static PyObject* Database_ases(DatabaseObject* self) {
	return Database_iterate_all(self, LOC_DB_ENUMERATE_ASES, AF_UNSPEC, 0);
}

static PyObject* Database_search_as(DatabaseObject* self, PyObject* args) {
	const char* string = NULL;

	if (!PyArg_ParseTuple(args, "s", &string))
		return NULL;

	struct loc_database_enumerator* enumerator;

	int r = loc_database_enumerator_new(&enumerator, self->db, LOC_DB_ENUMERATE_ASES, 0);
	if (r) {
		location_raise(r);
		return NULL;
	}

	// Search string we are searching for
	loc_database_enumerator_set_string(enumerator, string);

	PyObject* obj = new_database_enumerator(&DatabaseEnumeratorType, enumerator);
	loc_database_enumerator_unref(enumerator);

	return obj;
}

static PyObject* Database_networks(DatabaseObject* self) {
	return Database_iterate_all(self, LOC_DB_ENUMERATE_NETWORKS, AF_UNSPEC, 0);
}

static PyObject* Database_networks_flattened(DatabaseObject *self) {
	return Database_iterate_all(self, LOC_DB_ENUMERATE_NETWORKS, AF_UNSPEC,
		LOC_DB_ENUMERATOR_FLAGS_FLATTEN);
}

static PyObject* Database_search_networks(DatabaseObject* self, PyObject* args, PyObject* kwargs) {
	const char* kwlist[] = { "country_codes", "asns", "flags", "family", "flatten", NULL };
	PyObject* country_codes = NULL;
	PyObject* asn_list = NULL;
	int flags = 0;
	int family = 0;
	int flatten = 0;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|O!O!iip", (char**)kwlist,
			&PyList_Type, &country_codes, &PyList_Type, &asn_list, &flags, &family, &flatten))
		return NULL;

	struct loc_database_enumerator* enumerator;
	int r = loc_database_enumerator_new(&enumerator, self->db, LOC_DB_ENUMERATE_NETWORKS,
		(flatten) ? LOC_DB_ENUMERATOR_FLAGS_FLATTEN : 0);
	if (r) {
		location_raise(r);
		return NULL;
	}

	// Set country code we are searching for
	if (country_codes) {
		struct loc_country_list* countries;
		r = loc_country_list_new(loc_ctx, &countries);
		if (r) {
			PyErr_SetString(PyExc_SystemError, "Could not create country list");
			return NULL;
		}

		for (int i = 0; i < PyList_Size(country_codes); i++) {
			PyObject* item = PyList_GetItem(country_codes, i);

			if (!PyUnicode_Check(item)) {
				PyErr_SetString(PyExc_TypeError, "Country codes must be strings");
				loc_country_list_unref(countries);
				return NULL;
			}

			const char* country_code = PyUnicode_AsUTF8(item);

			struct loc_country* country;
			r = loc_country_new(loc_ctx, &country, country_code);
			if (r) {
				if (r == -EINVAL) {
					PyErr_Format(PyExc_ValueError, "Invalid country code: %s", country_code);
				} else {
					PyErr_SetString(PyExc_SystemError, "Could not create country");
				}

				loc_country_list_unref(countries);
				return NULL;
			}

			// Append it to the list
			r = loc_country_list_append(countries, country);
			if (r) {
				PyErr_SetString(PyExc_SystemError, "Could not append country to the list");

				loc_country_list_unref(countries);
				loc_country_unref(country);
				return NULL;
			}

			loc_country_unref(country);
		}

		r = loc_database_enumerator_set_countries(enumerator, countries);
		if (r) {
			location_raise(r);

			loc_country_list_unref(countries);
			return NULL;
		}

		loc_country_list_unref(countries);
	}

	// Set the ASN we are searching for
	if (asn_list) {
		struct loc_as_list* asns;
		r = loc_as_list_new(loc_ctx, &asns);
		if (r) {
			location_raise(r);
			return NULL;
		}

		for (int i = 0; i < PyList_Size(asn_list); i++) {
			PyObject* item = PyList_GetItem(asn_list, i);

			if (!PyLong_Check(item)) {
				PyErr_SetString(PyExc_TypeError, "ASNs must be numbers");

				loc_as_list_unref(asns);
				return NULL;
			}

			uint32_t number = 0;

			if (!location_parse_asn(item, &number)) {
				loc_as_list_unref(asns);
				return NULL;
			}

			struct loc_as* as = NULL;
			r = loc_as_new(loc_ctx, &as, number);
			if (r) {
				location_raise(r);

				loc_as_list_unref(asns);
				return NULL;
			}

			r = loc_as_list_append(asns, as);
			if (r) {
				location_raise(r);

				loc_as_list_unref(asns);
				loc_as_unref(as);
				return NULL;
			}

			loc_as_unref(as);
		}

		r = loc_database_enumerator_set_asns(enumerator, asns);
		if (r) {
			location_raise(r);

			loc_as_list_unref(asns);
			return NULL;
		}

		loc_as_list_unref(asns);
	}

	// Set the flags we are searching for
	if (flags) {
		r = loc_database_enumerator_set_flag(enumerator, flags);

		if (r) {
			location_raise(r);
			return NULL;
		}
	}

	// Set the family we are searching for
	if (family) {
		r = loc_database_enumerator_set_family(enumerator, family);

		if (r) {
			location_raise(r);
			return NULL;
		}
	}

	PyObject* obj = new_database_enumerator(&DatabaseEnumeratorType, enumerator);
	loc_database_enumerator_unref(enumerator);

	return obj;
}

static PyObject* Database_countries(DatabaseObject* self) {
	return Database_iterate_all(self, LOC_DB_ENUMERATE_COUNTRIES, AF_UNSPEC, 0);
}

static PyObject* Database_list_bogons(DatabaseObject* self, PyObject* args, PyObject* kwargs) {
	const char* kwlist[] = { "family", NULL };
	int family = AF_UNSPEC;

	// Parse arguments
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|i", (char**)kwlist, &family))
		return NULL;

	return Database_iterate_all(self, LOC_DB_ENUMERATE_BOGONS, family, 0);
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
		"list_bogons",
		(PyCFunction)Database_list_bogons,
		METH_VARARGS|METH_KEYWORDS,
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
		"reload",
		(PyCFunction)Database_reload,
		METH_NOARGS,
		"Reads the database again if its file has been replaced, and returns whether it has",
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
		"networks_flattened",
		(getter)Database_networks_flattened,
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
		location_raise(r);
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
		location_raise(r);
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
		location_raise(r);
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
