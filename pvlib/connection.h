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

#ifndef CONNECTION_H
#define CONNECTION_H

#include <stdint.h>

#define CONNECTION_MAX_NAME 128

/** different availabel connection types */
typedef enum {
    CONNECTION_RFCOMM ///< Bluetooth rfcomm connection
}connection_type_t;

typedef struct connection_info_s {
    connection_type_t connection;       ///< @see connection_type_t

    char src_name[CONNECTION_MAX_NAME]; ///< Our name.
    uint8_t src_address[6];             ///< Our address.

    uint8_t dst_address[6];             ///< Address of destination.
    char dst_name[CONNECTION_MAX_NAME]; ///< Name of destination.

    int address_len;                    ///< Length of address, depends on connection type.
}connection_info_t;

/** connection handle */
typedef struct connection_s connection_t;

struct connection_s {
    void *handle;

    int (*write)(connection_t *con, const uint8_t *data, int len);
    int (*read)(connection_t *con, uint8_t *data, int max_len);
    int (*info)(connection_t *con, connection_info_t * info);
    void (*close)(connection_t *con);
};

/**
 * Write data.
 *
 * @param con connection handle.
 * @param data data to write.
 * @param len length of data.
 *
 * @return < 0 if error occurs.
 */
int connection_write(connection_t *con, const uint8_t *data, int len);

/**
 * Read data.
 *
 * @param con connection handle.
 * @param data buffer to read to.
 * @param len length of data to read.
 *
 * @return < 0 if error occurs, else amount of bytes read.
 */
int connection_read(connection_t *con, uint8_t *data, int max_len);

/**
 * Give some usefull connection info.
 *
 * @param con connection handle.
 * @param[out] info @see connection_info_t.
 *
 * @return < 0, if error occurs.
 */
int connection_info(connection_t *con, connection_info_t *info);

/**
 * Close connection.
 *
 * @param con connection handle.
 */
void connection_close(connection_t *con);

#endif /* #ifndef CONNNECTION_H */
