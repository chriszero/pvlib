/*
 *   Pvlib - Connection interface
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

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "pvlib.h"
#include "smadata2plus.h"

static void print_usage()
{
    printf("Usage: pvlib MAC PASSWORD\n");
    printf("Example: pvlib \"00:11:22:33:44:55\" \"0000\"\n");
}

int main(int argc, char **argv) {
    pvlib_t *pvlib;
    uint32_t serial;
    pvlib_ac_t ac;
    pvlib_dc_t dc;
    pvlib_stats_t stats;
    int i;

    if (argc < 3) {
        print_usage();
        return -1;
    }

    pvlib = pvlib_init();
    if (pvlib == NULL) {
        fprintf(stderr, "pvlibinit failed!");
        return -1;
    }

    if (pvlib_open_connection(pvlib, PVLIB_RFCOMM, PVLIB_SMADATA2PLUS, argv[1], argv[2]) < 0) {
        fprintf(stderr, "Connection failed!");
        pvlib_close(pvlib);
        return -1;
    }

    for (i = 0; i < 2; i++) {
        if (pvlib_get_ac_values(pvlib, 0, &serial, &ac) < 0) {
            fprintf(stderr, "get live values failed!");
            pvlib_close(pvlib);
            return -1;
        }

        if (pvlib_get_dc_values(pvlib, 0, &serial, &dc) < 0) {
            fprintf(stderr, "get live values failed!");
            pvlib_close(pvlib);
            return -1;
        }

        if (pvlib_get_stats(pvlib, 0, &serial, &stats) < 0) {
            fprintf(stderr, "get stats failed!");
            pvlib_close(pvlib);
            return -1;
        }

        usleep(1 * 1000 * 1000);
    }
    return 0;
}
