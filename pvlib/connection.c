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

#include "connection.h"

int connection_write(connection_t *con, const uint8_t *data, int len)
{
    return con->write(con, data, len);
}

int connection_read(connection_t *con, uint8_t *data, int len)
{
    return con->read(con, data, len);
}

int connection_info(connection_t *con, connection_info_t *info)
{
    return con->info(con, info);
}

void connection_close(connection_t *con)
{
    con->close(con);
}
