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
#include <libloc/compat.h>
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
	if (!network)
		return PyErr_SetFromErrno(PyExc_OSError);

	return PyUnicode_FromString(network);
}

static PyObject* Network_get_country_code(NetworkObject* self) {
	const char* country_code = loc_network_get_country_code(self->network);

	return location_string(country_code);
}

static int Network_set_country_code(NetworkObject* self, PyObject* value) {
	const char* country_code = NULL;

	if (location_string_arg(value, &country_code, 1))
		return -1;

	int r = loc_network_set_country_code(self->network, country_code);
	if (r) {
		if (r == -EINVAL)
			PyErr_Format(PyExc_ValueError,
				"Invalid country code: %s", country_code);
		else
			location_raise(r);

		return -1;
	}

	return 0;
}

static PyObject* Network_get_asn(NetworkObject* self) {
	uint32_t asn = loc_network_get_asn(self->network);

	if (asn)
		return PyLong_FromUnsignedLong(asn);

	Py_RETURN_NONE;
}

static int Network_set_asn(NetworkObject* self, PyObject* value) {
	uint32_t asn = 0;
	int r;

	// None (or deleting the attribute) removes the ASN, which is what we return
	// for networks that do not have one
	if (!value || value == Py_None) {
		r = loc_network_set_asn(self->network, 0);
		if (r) {
			location_raise(r);
			return -1;
		}

		return 0;
	}

	// Check if the ASN is within the valid range
	if (!location_parse_asn(value, &asn)) {
		// Everything that is out of range is an invalid value
		if (PyErr_ExceptionMatches(PyExc_OverflowError)) {
			PyErr_Clear();
			PyErr_Format(PyExc_ValueError, "Invalid ASN %R", value);
		}

		return -1;
	}

	// AS0 is reserved and must not be used (RFC 7607). We use
	// zero to say that a network does not have any AS number.
	if (!asn) {
		PyErr_Format(PyExc_ValueError, "Invalid ASN %R", value);
		return -1;
	}

	r = loc_network_set_asn(self->network, asn);
	if (r) {
		location_raise(r);
		return -1;
	}

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

	if (r)
		return location_raise(r);

	Py_RETURN_NONE;
}

static PyObject* Network_exclude(NetworkObject* self, PyObject* args) {
	NetworkObject* other = NULL;

	if (!PyArg_ParseTuple(args, "O!", &NetworkType, &other))
		return NULL;

	struct loc_network_list* list = loc_network_exclude(self->network, other->network);
	if (!list)
		return PyErr_SetFromErrno(PyExc_OSError);

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
	if (!address)
		return PyErr_SetFromErrno(PyExc_OSError);

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
	if (!address)
		return PyErr_SetFromErrno(PyExc_OSError);

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

static PyObject* Network_reverse_pointer(NetworkObject* self, PyObject* args, PyObject* kwargs) {
	const char* kwlist[] = { "suffix", NULL };
	const char* suffix = NULL;
	char* rp = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|z", (char**)kwlist, &suffix))
		return NULL;

	rp = loc_network_reverse_pointer(self->network, suffix);
	if (!rp) {
		switch (errno) {
			case ENOTSUP:
				Py_RETURN_NONE;

			default:
				PyErr_SetFromErrno(PyExc_OSError);
				return NULL;
		}
	}

	PyObject* ret = PyUnicode_FromString(rp);
	free(rp);

	return ret;
}

static PyObject* Network_get_subnets(NetworkObject* self) {
	struct loc_network* subnet1 = NULL;
	struct loc_network* subnet2 = NULL;
	PyObject* result = NULL;
	PyObject* s1 = NULL;
	PyObject* s2 = NULL;
	int r;

	// Make subnets
	r = loc_network_subnets(self->network, &subnet1, &subnet2);
	if (r) {
		// A network that is a single address has no subnets
		if (r == -EINVAL)
			PyErr_SetString(PyExc_ValueError, "The network cannot be split any further");
		else
			location_raise(r);

		goto ERROR;
	}

	// Determine the length of the tuple
	Py_ssize_t l = 0;

	if (subnet1)
		l++;

	if (subnet2)
		l++;

	// Create a new result tuple
	result = PyTuple_New(l);
	if (!result)
		goto ERROR;

	Py_ssize_t pos = 0;

	// Convert the subnets into Python objects
	if (subnet1) {
		s1 = new_network(&NetworkType, subnet1);
		if (!s1)
			goto ERROR;

		// Append it to the list
		PyTuple_SET_ITEM(result, pos++, s1);
		Py_INCREF(s1);
	}

	if (subnet2) {
		s2 = new_network(&NetworkType, subnet2);
		if (!s2)
			goto ERROR;

		// Append it to the list
		PyTuple_SET_ITEM(result, pos++, s2);
		Py_INCREF(s2);
	}

	// Cleanup
	if (subnet1)
		loc_network_unref(subnet1);
	if (subnet2)
		loc_network_unref(subnet2);
	if (s1)
		Py_DECREF(s1);
	if (s2)
		Py_DECREF(s2);

	return result;

ERROR:
	if (subnet1)
		loc_network_unref(subnet1);
	if (subnet2)
		loc_network_unref(subnet2);
	if (result)
		Py_DECREF(result);
	if (s1)
		Py_DECREF(s1);
	if (s2)
		Py_DECREF(s2);

	return NULL;
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
		"reverse_pointer",
		(PyCFunction)Network_reverse_pointer,
		METH_VARARGS|METH_KEYWORDS,
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
	{
		"subnets",
		(getter)Network_get_subnets,
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
