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

#ifndef PVLIB_H
#define PVLIB_H

#include <stdint.h>

#if defined __cplusplus
extern "C" {
#endif

struct pvlib_interface_s;

enum {
    PVLIB_UNSUPPORTED_CONNECTION,
    PVLIB_ERROR
};

typedef enum {
    PVLIB_RFCOMM
}pvlib_connection_t;

typedef enum {
    PVLIB_SMADATA2PLUS,
    PVLIB_SMADATA
}pvlib_protocol_t;

typedef struct pvlib_ac_s {
    uint32_t    current_power; ///< current power of string inverter in watts

    uint32_t    power[3];   ///< current power of phase in watss
    uint32_t    voltage[3]; ///< current voltage in millivolts
    uint32_t    current[3]; ///< current current in milliampere

    uint32_t    frequence;  ///< frequence in milliherz

    uint8_t     num_lines;  ///< number of output phases
}pvlib_ac_t;

typedef struct pvlib_dc_s {
    uint32_t    current_power; ///<current power in watts

    uint32_t    power[3];   ///<current power in watts
    uint32_t    voltage[3]; ///<current voltage in millivolts
    uint32_t    current[3]; ///<current current in milliampere

    uint8_t     num_lines;  ///<number of input strings
}pvlib_dc_t;

typedef struct pvlib_stats_s {
    uint32_t    total_yield; ///<total produced power in  watt-hours
    uint32_t    day_yield;   ///<total produced power today in  watt-hours

    uint32_t    operation_time; /// <operation time in seconds
    uint32_t    feed_in_time;   ///<feed in time in seconds
}pvlib_stats_t;

typedef struct pvlib_s pvlib_t;

/**
 * Initialize pvlib.
 *
 * @return pvlib_t handle.
 */
pvlib_t *pvlib_init();

/**
 * Close pvlib and all open connections.
 *
 * @param pvlib pvlib_t handle
 */
void pvlib_close(pvlib_t *pvlib);

/**
 * Connect to string inverter or pv plant.
 *
 * @param pvlib pvlib_t handle
 * @param connection connection type
 * @param protocol protocol type
 * @param depends on connection type, for SMADATA2PLUS string inverter mac.
 * @param passwd passwd for string inverter or plant.
 *
 * @return on success: interface num, can be used for closing connection.
           on error: @see error.
 */
int pvlib_open_connection(pvlib_t *pvlib, pvlib_connection_t connection, pvlib_protocol_t protocol, const char *addr, const char *passwd);

/**
 * Close connection to plant or string inverterr.
 *
 * @param pvlib pvlib_t handle
 * @param num
 */
int pvlib_close_connection(pvlib_t *pvlib, int num);

/**
 * Returns total number of stringconverter.
 *
 * @param pvlib pvlib_t handle
 * @return number of string inverter.
 */
int pvlib_num_string_inverter(pvlib_t *pvlib);

/**
 * Get dc values from string converter.
 *
 * @param pvlib pvlib_t handle
 * @param[out] dc dc values
 * @param[out] id string inverter id
 * @param num number of string converter.
 */
int pvlib_get_dc_values(pvlib_t *pvlib, int num, uint32_t *id, pvlib_dc_t *dc);

/**
 * Get dc values from string converter.
 *
 * @param pvlib pvlib_t handle
 * @param[out] ac dc values
 * @param[out] id string inverterr id
 * @param num number of string converter.
 */
int pvlib_get_ac_values(pvlib_t *pvlib, int num, uint32_t *id, pvlib_ac_t *ac);

/**
 * Get dc values from string converter.
 *
 * @param pvlib pvlib_t handle
 * @param[out] stats statistics of string inverter
 * @param[out] id string converter id
 * @param num number of string converter.
 */
int pvlib_get_stats(pvlib_t *pvlib, int num, uint32_t *id, pvlib_stats_t *stats);

/**
 * Get interface
 *
 * @param pvlib pvlib_t handle
 * @param num number of connection.
 */
struct pvlib_interface_s *pvlib_get_interface(pvlib_t *pvlib, int num);

#if defined __cplusplus
}
#endif

#endif /* #ifndef PVLIB_H */
