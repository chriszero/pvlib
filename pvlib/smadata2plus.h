/*
 *   Pvlib - Smadata2plus implementation
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

#ifndef SMADATA2PLUS_H
#define SMADATA2PLUS_H

#include <stdint.h>

#define SMADATA2PLUS_BROADCAST 0xffffffff

struct connection_s;
struct pvilb_interface_s;

typedef struct smadata2plus_s smadata2plus_t;

typedef struct smadata2plus_packet_s {
    uint8_t     cmd;
    uint8_t     ctrl;
    uint32_t    dst;
    uint32_t    src;
    uint8_t     flag; /* unknown */
    uint8_t     pkt_cnt;
    uint8_t     pkt_start;
    uint8_t     *data;
    int         len;
}smadata2plus_packet_t;

struct pvlib_interface_s *smadata2plus_init(struct connection_s *con);

#endif /* #ifndef SMADATA2PLUS_H */
