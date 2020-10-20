/*
	libloc - A library to determine the location of someone on the Internet

	Copyright (C) 2019 IPFire Development Team <info@ipfire.org>

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
#include <loc/country.h>

#include "locationmodule.h"
#include "country.h"

PyObject* new_country(PyTypeObject* type, struct loc_country* country) {
	CountryObject* self = (CountryObject*)type->tp_alloc(type, 0);
	if (self) {
		self->country = loc_country_ref(country);
	}

	return (PyObject*)self;
}

static PyObject* Country_new(PyTypeObject* type, PyObject* args, PyObject* kwds) {
	CountryObject* self = (CountryObject*)type->tp_alloc(type, 0);

	return (PyObject*)self;
}

static void Country_dealloc(CountryObject* self) {
	if (self->country)
		loc_country_unref(self->country);

	Py_TYPE(self)->tp_free((PyObject* )self);
}

static int Country_init(CountryObject* self, PyObject* args, PyObject* kwargs) {
	const char* country_code = NULL;

	if (!PyArg_ParseTuple(args, "s", &country_code))
		return -1;

	// Create the country object
	int r = loc_country_new(loc_ctx, &self->country, country_code);
	if (r)
		return -1;

	return 0;
}

static PyObject* Country_repr(CountryObject* self) {
	const char* code = loc_country_get_code(self->country);
	const char* name = loc_country_get_name(self->country);

	if (name)
		return PyUnicode_FromFormat("<Country %s (%s)>", code, name);

	return PyUnicode_FromFormat("<Country %s>", code);
}

static PyObject* Country_get_code(CountryObject* self) {
	const char* code = loc_country_get_code(self->country);

	return PyUnicode_FromString(code);
}

static PyObject* Country_str(CountryObject* self) {
	return Country_get_code(self);
}

static PyObject* Country_get_name(CountryObject* self) {
	const char* name = loc_country_get_name(self->country);

	return PyUnicode_FromString(name);
}

static int Country_set_name(CountryObject* self, PyObject* value) {
	const char* name = PyUnicode_AsUTF8(value);

	int r = loc_country_set_name(self->country, name);
	if (r) {
		PyErr_Format(PyExc_ValueError, "Could not set name: %s", name);
		return r;
	}

	return 0;
}

static PyObject* Country_get_continent_code(CountryObject* self) {
	const char* code = loc_country_get_continent_code(self->country);

	return PyUnicode_FromString(code);
}

static int Country_set_continent_code(CountryObject* self, PyObject* value) {
	const char* code = PyUnicode_AsUTF8(value);

	int r = loc_country_set_continent_code(self->country, code);
	if (r) {
		PyErr_Format(PyExc_ValueError, "Could not set continent code: %s", code);
		return r;
	}

	return 0;
}

static PyObject* Country_richcompare(CountryObject* self, CountryObject* other, int op) {
	int r = loc_country_cmp(self->country, other->country);

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

static struct PyGetSetDef Country_getsetters[] = {
	{
		"code",
		(getter)Country_get_code,
		NULL,
		NULL,
		NULL,
	},
	{
		"name",
		(getter)Country_get_name,
		(setter)Country_set_name,
		NULL,
		NULL,
	},
	{
		"continent_code",
		(getter)Country_get_continent_code,
		(setter)Country_set_continent_code,
		NULL,
		NULL,
	},
	{ NULL },
};

PyTypeObject CountryType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name =               "location.Country",
	.tp_basicsize =          sizeof(CountryObject),
	.tp_flags =              Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
	.tp_new =                Country_new,
	.tp_dealloc =            (destructor)Country_dealloc,
	.tp_init =               (initproc)Country_init,
	.tp_doc =                "Country object",
	.tp_getset =             Country_getsetters,
	.tp_repr =               (reprfunc)Country_repr,
	.tp_str =                (reprfunc)Country_str,
	.tp_richcompare =        (richcmpfunc)Country_richcompare,
};
