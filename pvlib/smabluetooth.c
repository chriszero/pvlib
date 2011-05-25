  /*
 *   Pvlib - Smabluetooth implementation
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

#include "smabluetooth.h"

#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include "log.h"

#define HEADER_SIZE 18

struct smabluetooth_s {
    connection_t        *con;
    connection_info_t   info;
    int                 connected;
};

static int smabluetooth_encapsulate(smabluetooth_packet_t *packet, uint8_t *buf)
{
    uint16_t size;
    uint8_t  i;

    size = HEADER_SIZE + packet->data_len;

    if (size > 255) {
        return -1;
    }

    buf[0] = 0x7e;
    buf[1] = (uint8_t)size;
    buf[2] = 0x00;
    buf[3] = buf[0] ^ buf[1] ^ buf[2] ^ buf[3];

    for (i = 0; i < 6; i++) {
        buf[4 + i] = packet->header.mac_src[i];
    }

    for (i = 0; i < 6; i++) {
        buf[10 + i] = packet->header.mac_dst[i];
    }

    buf[16] = packet->header.cmd;
    buf[17] = 0x00;

    memcpy(&buf[18], packet->data, packet->data_len);

    return 0;
}

static int parse_header(smabluetooth_header_t *header, uint8_t *buf, int buf_len)
{
    uint8_t len;
    uint8_t i;

    if (buf_len < HEADER_SIZE) {
        LOG_ERROR("Buffer does not contain complete header");
        return -1;
    }

    if (buf[0] != 0x7e) {
        LOG_ERROR("Invalid header!");
        return -1;
    }


    if (buf[0] ^ buf[1] ^ buf[2] ^ buf[3]) {
        LOG_ERROR("Broken header!");
        return -1;
    }

    len = buf[1];
    if (len < HEADER_SIZE) {
        LOG_ERROR("Broken header!");
        return -1;
    }
    header->len = len;

    for (i = 0; i < 6; i++) {
        header->mac_src[i] = buf[4 + i];
    }

    for (i = 0; i < 6; i++) {
        header->mac_dst[i] = buf[10 + i];
    }

    header->cmd = buf[16];

    return 0;
}

static int start_connection(smabluetooth_t *sma)
{
    smabluetooth_packet_t packet;
    uint8_t buf[13];

    memset(&packet, 0x00, sizeof(packet));
    packet.data     = buf;
    packet.data_len = 13;

    if (smabluetooth_read(sma, &packet) < 0) return -1;

    if (packet.header.cmd != SMABLUETOOTH_CONNECT) {
        LOG_ERROR("Recivied wrong command: %d", packet.header.cmd);
        return -1;
    }

    // send same data back
    memcpy(packet.header.mac_dst, packet.header.mac_src, 6);
    memset(packet.header.mac_src, 0x00, 6);
    packet.unknown_src = 1;

    if (smabluetooth_write(sma, &packet) < 0) return -1;

    return 0;
}

static int receive_address(smabluetooth_t *sma)
{
    uint8_t buf[16];
    smabluetooth_packet_t packet;

    memset(&packet, 0x00, sizeof(packet));
    packet.data     = buf;
    packet.data_len = 13;

    if (smabluetooth_read(sma, &packet) < 0) return -1;

    if (packet.header.cmd == SMABLUETOOTH_ADDRESS) {
        LOG_INFO("Received address.");

        memset(&packet, 0x00, sizeof(packet));
        packet.data     = buf;
        packet.data_len = 13;

        if (smabluetooth_read(sma, &packet) < 0) return -1;

        LOG_INFO("Received address command: %d", packet.header.cmd);

        memset(&packet, 0x00, sizeof(packet));
        packet.data     = buf;
        packet.data_len = 16;

        if (smabluetooth_read(sma, &packet) < 0) return -1;

    }

    if (packet.header.cmd != SMABLUETOOTH_ADDRESS2) return -1;

    return 0;
}

smabluetooth_t *smabluetooth_init(connection_t *con)
{
    smabluetooth_t *sma;

    sma      = calloc(1, sizeof(*sma));
    sma->con = con;

    if (connection_info(con, &sma->info) < 0) {
        LOG_ERROR("Failed getting connection info!");
        free(sma);
        return NULL;
    }

    return sma;
}

void smabluetooth_close(smabluetooth_t *sma)
{
    free(sma);
}

int smabluetooth_write(smabluetooth_t *sma, smabluetooth_packet_t *packet)
{
    uint8_t  buf[0xff];
    uint16_t len;

    len = packet->data_len + HEADER_SIZE;
    if (len > 0xff) {
        LOG_ERROR("smabluetooth: data_len to big");
        return -1;
    }

    if (packet->unknown_src) {
        memset(packet->header.mac_src, 0x00, 6);
    } else {
        memcpy(packet->header.mac_src, sma->info.src_address, 6);
    }

    if (packet->broadcast) {
        memset(packet->header.mac_dst, 0xff, 6);
    } else {
        memcpy(packet->header.mac_dst, sma->info.dst_address, 6);
    }

    if (smabluetooth_encapsulate(packet, buf) < 0) {
        LOG_ERROR("smabluetooth: invalid packet!");
        return -1;
    }

    //LOG_HEX("smabluetooth, write", buf, len);
    if (connection_write(sma->con, buf, len) < 0) {
        LOG_ERROR("Failed writing data.");
        return -1;
    }
    return 0;
}

int smabluetooth_read(smabluetooth_t *sma, smabluetooth_packet_t *packet)
{
    uint8_t buf[0xff];
    uint8_t size;
    uint8_t data_len;

    if (connection_read(sma->con, buf, HEADER_SIZE) < 0) {
        LOG_ERROR("Failed reading header!");
        return -1;
    }
    //LOG_HEX("smabluetooth, read, header", buf, HEADER_SIZE);

    if (parse_header(&packet->header, buf, HEADER_SIZE) < 0) {
        LOG_ERROR("Failed parsing header!");
        return -1;
    }

    data_len = packet->header.len - HEADER_SIZE;
    if (data_len > packet->data_len) {
        size = packet->data_len;
    } else {
        size = data_len;
    }

    if (size > 0) {
        if (connection_read(sma->con, packet->data, size) < 0) {
            LOG_ERROR("Failed reading data!");
            return -1;
        }
        //LOG_HEX("smabluetooth, read", packet->data, size);
    } else {
        LOG_DEBUG("smabluetooth: no data to read!");
        packet->data = NULL;
    }

    packet->data_len = size;

    // remove left smabluetooth data.
    if (data_len > size) {
        connection_read(sma->con, buf, data_len - size);
    }

    return 0;
}

int smabluetooth_connect(smabluetooth_t *sma)
{
    LOG_INFO("Trying to connect to string converter.");

    if (start_connection(sma) < 0) {
        LOG_ERROR("Failed establishing connection.");
        return -1;
    }

    if (receive_address(sma) < 0) {
        LOG_ERROR("Failed receiving addresses.");
        return -1;
    }

    LOG_INFO("Connection successfully established!");
    sma->connected = 1;

    return 0;
}

int smabluetooth_signal(smabluetooth_t *sma)
{
    smabluetooth_packet_t packet;
    uint8_t buf[6];
    int signal;

    if (!sma->connected) {
        LOG_ERROR("Not connected!");
        return -1;
    }

    packet.data        = buf;
    packet.data_len    = 2;
    packet.unknown_src = 1;
    packet.broadcast   = 0;
    packet.header.cmd  = SMABLUETOOTH_ASKSIGNAL;
    memcpy(packet.header.mac_dst, sma->info.dst_address, 6);

    buf[0] = 0x05;
    buf[1] = 0x00;

    if (smabluetooth_write(sma, &packet) < 0) {
        return -1;
    }

    memset(&packet, 0x00, sizeof(packet));
    packet.data     = buf;
    packet.data_len = 6;

    if (smabluetooth_read(sma, &packet) < 0) {
        return -1;
    }

    if (packet.header.cmd != SMABLUETOOTH_ANSWERSIGNAL) {
        LOG_ERROR("Unexpected command: %d!", packet.header.cmd);
        return -1;
    }

    signal = buf[4] * 100 / 0xff;

    return signal;
}
