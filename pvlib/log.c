
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

#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int log_severity = 0;

void log_enable(int severity)
{
    log_severity = severity;
}

void log_disable()
{
   log_severity = 0;
}

static const char *filename(const char *file)
{
    const char *i;
    int len = strlen(file);

    for (i = &file[len - 1]; i != file; i--) {
        if (*i == '/' || *i == '\\') {
            return &i[1];
        }
    }
    return file;
}

void log_hex(log_severity_t severity, const char *file, int line, const char *message, uint8_t *data, int len)
{
    if (log_severity & severity) {
        int i = 0;

        fprintf(stderr, "%s, %d: %s:\n", filename(file), line, message);

        for (i = 0; i < len; i++) {
            fprintf(stderr, "%02X ", data[i]);
            if (!((i + 1) % 16)) fprintf(stderr, "\n");
        }

        fprintf(stderr, "\n\n");
    }
}

void log_log(log_severity_t severity, const char *file, int line, const char *format, ...)
{
    if (log_severity & severity) {
        va_list args;

        if (severity == LOG_ERROR) {
            // red
            fprintf(stderr, "\e[31m%s, %d: ", filename(file), line);
        } else if (severity == LOG_WARNING) {
            // yellow
            fprintf(stderr, "\e[33m%s, %d :", filename(file), line);
        } else if (severity == LOG_INFO) {
            // green
            fprintf(stderr, "\e[32m%s, %d: ", filename(file), line);
        } else {
            fprintf(stderr, "%s, %d: ", filename(file), line);
        }

        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);

        fprintf(stderr, "\e[0m\n");
    }
}
