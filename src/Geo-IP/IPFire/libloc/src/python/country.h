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

#ifndef PYTHON_LOCATION_COUNTRY_H
#define PYTHON_LOCATION_COUNTRY_H

#include <Python.h>

//#include <loc/libloc.h>
#include <loc/country.h>

typedef struct {
	PyObject_HEAD
	struct loc_country* country;
} CountryObject;

extern PyTypeObject CountryType;

PyObject* new_country(PyTypeObject* type, struct loc_country* country);

#endif /* PYTHON_LOCATION_COUNTRY_H */
