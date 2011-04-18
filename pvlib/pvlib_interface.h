/*
 *   Pvlib - Pvlib interface
 *
 *   Copyright (C) 2011
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *****************************************************************************/

#ifndef PVLIB_PRIVATE_H
#define PVLIB_PRIVATE_H

#include "pvlib.h"

typedef struct pvlib_interface_s pvlib_interface_t;

struct pvlib_interface_s {
    pvlib_protocol_t protocol;
    void    *handle;

    int (*open)(pvlib_interface_t *);
    int (*connect)(pvlib_interface_t *, const char *);
    int (*string_inverter_num)(pvlib_interface_t *);
    void (*close)(pvlib_interface_t *);
    //int (*refresh_dc_values)(pvlib_interface_t *);
    int (*get_dc)(pvlib_interface_t *, int num, uint32_t *id, pvlib_dc_t *);
    //int (*refresh_ac_values)(pvlib_interface_t *);
    int (*get_ac)(pvlib_interface_t *, int num, uint32_t *id, pvlib_ac_t *);
    int (*get_stats)(pvlib_interface_t *, int num, uint32_t *id, pvlib_stats_t *);
};

#endif /* PVLIB_PRIVATE_H */
