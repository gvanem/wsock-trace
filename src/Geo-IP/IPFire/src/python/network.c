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

#include <errno.h>
#include <limits.h>

#include <libloc/libloc.h>
#include <libloc/address.h>
#include <libloc/network.h>
#include <libloc/network-list.h>

#include "locationmodule.h"
#include "network.h"

static PyObject* PyList_FromNetworkList(struct loc_network_list* networks) {
	PyObject* list = PyList_New(0);
	if (!networks)
		return list;

	while (!loc_network_list_empty(networks)) {
		struct loc_network* network = loc_network_list_pop(networks);

		PyObject* n = new_network(&NetworkType, network);
		PyList_Append(list, n);

		loc_network_unref(network);
		Py_DECREF(n);
	}

	return list;
}

PyObject* new_network(PyTypeObject* type, struct loc_network* network) {
	NetworkObject* self = (NetworkObject*)type->tp_alloc(type, 0);
	if (self) {
		self->network = loc_network_ref(network);
	}

	return (PyObject*)self;
}

static PyObject* Network_new(PyTypeObject* type, PyObject* args, PyObject* kwds) {
	NetworkObject* self = (NetworkObject*)type->tp_alloc(type, 0);

	return (PyObject*)self;
}

static void Network_dealloc(NetworkObject* self) {
	if (self->network)
		loc_network_unref(self->network);

	Py_TYPE(self)->tp_free((PyObject* )self);
}

static int Network_init(NetworkObject* self, PyObject* args, PyObject* kwargs) {
	const char* network = NULL;

	if (!PyArg_ParseTuple(args, "s", &network))
		return -1;

	// Load the Network
	int r = loc_network_new_from_string(loc_ctx, &self->network, network);
	if (r) {
		PyErr_Format(PyExc_ValueError, "Invalid network: %s", network);
		return -1;
	}

	return 0;
}

static PyObject* Network_repr(NetworkObject* self) {
	const char* network = loc_network_str(self->network);

	return PyUnicode_FromFormat("<location.Network %s>", network);
}

static PyObject* Network_str(NetworkObject* self) {
	const char* network = loc_network_str(self->network);

	return PyUnicode_FromString(network);
}

static PyObject* Network_get_country_code(NetworkObject* self) {
	const char* country_code = loc_network_get_country_code(self->network);

	return PyUnicode_FromString(country_code);
}

static int Network_set_country_code(NetworkObject* self, PyObject* value) {
	const char* country_code = PyUnicode_AsUTF8(value);

	int r = loc_network_set_country_code(self->network, country_code);
	if (r) {
		if (r == -EINVAL)
			PyErr_Format(PyExc_ValueError,
				"Invalid country code: %s", country_code);

		return -1;
	}

	return 0;
}

static PyObject* Network_get_asn(NetworkObject* self) {
	uint32_t asn = loc_network_get_asn(self->network);

	if (asn)
		return PyLong_FromLong(asn);

	Py_RETURN_NONE;
}

static int Network_set_asn(NetworkObject* self, PyObject* value) {
	long int asn = PyLong_AsLong(value);

	// Check if the ASN is within the valid range
	if (asn <= 0) {
		PyErr_Format(PyExc_ValueError, "Invalid ASN %ld", asn);
		return -1;
	}

#if (__WORDSIZE > 32)
	// Check whether the input was longer than 32 bit
	if (asn > UINT32_MAX) {
		PyErr_Format(PyExc_ValueError, "Invalid ASN %ld", asn);
		return -1;
	}
#endif

	int r = loc_network_set_asn(self->network, asn);
	if (r)
		return -1;

	return 0;
}

static PyObject* Network_has_flag(NetworkObject* self, PyObject* args) {
	enum loc_network_flags flag = 0;

	if (!PyArg_ParseTuple(args, "i", &flag))
		return NULL;

	if (loc_network_has_flag(self->network, flag))
		Py_RETURN_TRUE;

	Py_RETURN_FALSE;
}

static PyObject* Network_set_flag(NetworkObject* self, PyObject* args) {
	enum loc_network_flags flag = 0;

	if (!PyArg_ParseTuple(args, "i", &flag))
		return NULL;

	int r = loc_network_set_flag(self->network, flag);

	if (r) {
		// What exception to throw here?
		return NULL;
	}

	Py_RETURN_NONE;
}

static PyObject* Network_exclude(NetworkObject* self, PyObject* args) {
	NetworkObject* other = NULL;

	if (!PyArg_ParseTuple(args, "O!", &NetworkType, &other))
		return NULL;

	struct loc_network_list* list = loc_network_exclude(self->network, other->network);

	// Convert to Python objects
	PyObject* obj = PyList_FromNetworkList(list);
	loc_network_list_unref(list);

	return obj;
}

static PyObject* Network_is_subnet_of(NetworkObject* self, PyObject* args) {
	NetworkObject* other = NULL;

	if (!PyArg_ParseTuple(args, "O!", &NetworkType, &other))
		return NULL;

	if (loc_network_is_subnet(other->network, self->network))
		Py_RETURN_TRUE;

	Py_RETURN_FALSE;
}

static PyObject* Network_get_family(NetworkObject* self) {
	int family = loc_network_address_family(self->network);

	return PyLong_FromLong(family);
}

static PyObject* Network_get_first_address(NetworkObject* self) {
	const char* address = loc_network_format_first_address(self->network);

	return PyUnicode_FromString(address);
}

static PyObject* PyBytes_FromAddress(const struct in6_addr* address6) {
	struct in_addr address4;

	// Convert IPv4 addresses to struct in_addr
	if (IN6_IS_ADDR_V4MAPPED(address6)) {
		address4.s_addr = IN6_DWORD(address6, 3);

		return PyBytes_FromStringAndSize((const char*)&address4, sizeof(address4));
	}

	// Return IPv6 addresses as they are
	return PyBytes_FromStringAndSize((const char*)address6, sizeof(*address6));
}

static PyObject* Network_get__first_address(NetworkObject* self) {
	const struct in6_addr* address = loc_network_get_first_address(self->network);

	return PyBytes_FromAddress(address);
}

static PyObject* Network_get_last_address(NetworkObject* self) {
	const char* address = loc_network_format_last_address(self->network);

	return PyUnicode_FromString(address);
}

static PyObject* Network_get__last_address(NetworkObject* self) {
	const struct in6_addr* address = loc_network_get_last_address(self->network);

	return PyBytes_FromAddress(address);
}

static PyObject* Network_richcompare(NetworkObject* self, PyObject* other, int op) {
	int r;

	// Check for type
	if (!PyObject_IsInstance(other, (PyObject *)&NetworkType))
		Py_RETURN_NOTIMPLEMENTED;

	NetworkObject* o = (NetworkObject*)other;

	r = loc_network_cmp(self->network, o->network);

	switch (op) {
		case Py_EQ:
			if (r == 0)
				Py_RETURN_TRUE;

			Py_RETURN_FALSE;

		case Py_LT:
			if (r < 0)
				Py_RETURN_TRUE;

			Py_RETURN_FALSE;

		default:
			break;
	}

	Py_RETURN_NOTIMPLEMENTED;
}

static struct PyMethodDef Network_methods[] = {
	{
		"exclude",
		(PyCFunction)Network_exclude,
		METH_VARARGS,
		NULL,
	},
	{
		"has_flag",
		(PyCFunction)Network_has_flag,
		METH_VARARGS,
		NULL,
	},
	{
		"is_subnet_of",
		(PyCFunction)Network_is_subnet_of,
		METH_VARARGS,
		NULL,
	},
	{
		"set_flag",
		(PyCFunction)Network_set_flag,
		METH_VARARGS,
		NULL,
	},
	{ NULL },
};

static struct PyGetSetDef Network_getsetters[] = {
	{
		"asn",
		(getter)Network_get_asn,
		(setter)Network_set_asn,
		NULL,
		NULL,
	},
	{
		"country_code",
		(getter)Network_get_country_code,
		(setter)Network_set_country_code,
		NULL,
		NULL,
	},
	{
		"family",
		(getter)Network_get_family,
		NULL,
		NULL,
		NULL,
	},
	{
		"first_address",
		(getter)Network_get_first_address,
		NULL,
		NULL,
		NULL,
	},
	{
		"_first_address",
		(getter)Network_get__first_address,
		NULL,
		NULL,
		NULL,
	},
	{
		"last_address",
		(getter)Network_get_last_address,
		NULL,
		NULL,
		NULL,
	},
	{
		"_last_address",
		(getter)Network_get__last_address,
		NULL,
		NULL,
		NULL,
	},
	{ NULL },
};

PyTypeObject NetworkType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name =               "location.Network",
	.tp_basicsize =          sizeof(NetworkObject),
	.tp_flags =              Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
	.tp_new =                Network_new,
	.tp_dealloc =            (destructor)Network_dealloc,
	.tp_init =               (initproc)Network_init,
	.tp_doc =                "Network object",
	.tp_methods =            Network_methods,
	.tp_getset =             Network_getsetters,
	.tp_repr =               (reprfunc)Network_repr,
	.tp_str =                (reprfunc)Network_str,
	.tp_richcompare =        (richcmpfunc)Network_richcompare,
};
