/*
 *   Pvlib - Log implementation
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

#ifndef LOG_H
#define LOG_H

#include <stdint.h>

typedef enum {
    LOG_DISABLE = 0,
    LOG_INFO    = 1,
    LOG_ERROR   = 2,
    LOG_DEBUG   = 4,
    LOG_WARNING = 8,
    LOG_ALL     = 0xffffffff
}log_severity_t;

void log_enable(int severity);

void log_disable();

void log_log(log_severity_t severity, const char *file, int line, const char *format, ...);

void log_hex(log_severity_t severity, const char *file, int line, const char *message, uint8_t *data, int len);

#define LOG_ERROR(MESSAGE, ...) log_log(LOG_ERROR, __FILE__, __LINE__, MESSAGE, ##__VA_ARGS__)
#define LOG_INFO(MESSAGE, ...) log_log(LOG_INFO, __FILE__, __LINE__, MESSAGE, ##__VA_ARGS__)
#define LOG_WARNIN(MESSAGE, ...) log_log(LOG_WARNING, __FILE__, __LINE__, MESSAGE, ##__VA_ARGS__)
#define LOG_DEBUG(MESSAGE, ...) log_log(LOG_DEBUG, __FILE__, __LINE__, MESSAGE, ##__VA_ARGS__)
#define LOG_HEX(MESSAGE, DATA, LEN) log_hex(LOG_DEBUG, __FILE__, __LINE__, MESSAGE, DATA, LEN)

#endif /* #ifndef LOG_H */
