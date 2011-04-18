/*
 *   Pvlib - PV logging library
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


#include "pvlib.h"

#include <stdlib.h>
#include <malloc.h>

#include "pvlib_interface.h"
#include "smadata2plus.h"

#include "connection.h"
#include "rfcomm.h"

#include "log.h"

struct pvlib_s {
    pvlib_interface_t **interfaces;
    int     interfaces_available;
    int     interfaces_used;
    connection_t *con;
};

static connection_t *open_connection(pvlib_connection_t connection, const char *addr)
{
    connection_t *con = NULL;

    switch (connection) {
    case PVLIB_RFCOMM :
        con = rfcomm_open(addr);
        break;
    default : con = NULL; break;
    }

    return con;
}

static pvlib_interface_t *open_interface(pvlib_protocol_t protocol, connection_t *con)
{
    pvlib_interface_t *interface;

    switch (protocol) {
    case PVLIB_SMADATA2PLUS :
        interface = smadata2plus_init(con);
        break;
    default :
        interface = NULL;
        break;
    }

    return interface;
}

pvlib_t *pvlib_init() {
    pvlib_t *pvlib;

    pvlib = malloc(sizeof(*pvlib));
    pvlib->interfaces = malloc(sizeof(*pvlib->interfaces));
    pvlib->interfaces_available = 1;
    pvlib->interfaces_used = 0;

    log_enable(LOG_ALL);

    return pvlib;
}

int pvlib_open_connection(pvlib_t *pvlib, pvlib_connection_t connection, pvlib_protocol_t protocol, const char *addr, const char *passwd)
{
    pvlib_interface_t *interface;

    pvlib->con = open_connection(connection, addr);
    if (pvlib->con == NULL) return -1;

    interface = open_interface(protocol, pvlib->con);
    if (interface == NULL) return -1;

    if (interface->connect(interface, passwd) < 0) return -1;


    if (pvlib->interfaces_used >= pvlib->interfaces_available) {
        pvlib->interfaces = realloc(pvlib->interfaces, ++pvlib->interfaces_available);
    }

    pvlib->interfaces[pvlib->interfaces_used++] = interface;

    return 0;
}

int pvlib_num_string_inverter(pvlib_t *pvlib)
{
    int num = 0;
    int i;

    for (i = 0; i < pvlib->interfaces_used; i++) {
        int ret = pvlib->interfaces[i]->string_inverter_num(pvlib->interfaces[i]);
        if (ret < 0) return -1;

        num += ret;
    }

    return num;
}

static pvlib_interface_t *get_interface(pvlib_t *pvlib, int num, int *index)
{
    int i = 0;
    int pos = 0;
    int inv_num;

    if (pvlib_num_string_inverter(pvlib) < num) {
        LOG_ERROR("Failed getting interface.");
        return NULL;
    }

    for (i = 0; i < pvlib->interfaces_used; i++) {
        inv_num = pvlib->interfaces[i]->string_inverter_num(pvlib->interfaces[i]);
        pos += inv_num;

        if (num < pos) break;
    }

    *index = inv_num + num - pos - 1;

    return pvlib->interfaces[i];
}

int pvlib_get_ac_values(pvlib_t *pvlib, int num, uint32_t *id, pvlib_ac_t *ac)
{
    int index;
    pvlib_interface_t *interface;

    interface = get_interface(pvlib, num, &index);
    if (interface == NULL) return -1;

    return interface->get_ac(interface, index, id, ac);
}

int pvlib_get_dc_values(pvlib_t *pvlib, int num, uint32_t *id, pvlib_dc_t *dc)
{
    int index;
    pvlib_interface_t *interface;

    interface = get_interface(pvlib, num, &index);
    if (interface == NULL) return -1;

    return interface->get_dc(interface, index, id, dc);
}

int pvlib_get_stats(pvlib_t *pvlib, int num, uint32_t *id, pvlib_stats_t *stats)
{
    int index;
    pvlib_interface_t *interface;

    interface = get_interface(pvlib, num, &index);
    if (interface == NULL) return -1;

    return interface->get_stats(interface, index, id, stats);
}

pvlib_interface_t *pvlib_get_interface(pvlib_t *pvlib, int num)
{
    int index;
    return get_interface(pvlib, num, &index);
}

void pvlib_close(pvlib_t *pvlib)
{
    int i;
    for (i = 0; i < pvlib->interfaces_used; i++) {
        pvlib->interfaces[i]->close(pvlib->interfaces[i]);
    }
}
