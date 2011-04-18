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

#include "smadata2plus.h"

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "smabluetooth.h"
#include "smanet.h"
#include "log.h"
#include "byte.h"
#include "pvlib.h"
#include "pvlib_interface.h"

#define PROTOCOL 0x6560
#define HEADER_SIZE 24

/* commands */
#define CMD_CHANNEL_REQUEST 0x09
#define CMD_PASSWORD        0x0e
#define CMD_TIME            0x10
#define CMD_SYNC_ONLINE     0x0a
#define CMD_UNKNOWN         0x08

/* ctrl */
#define CTRL_MASTER         (1 << 7 | 1 << 5)
#define CTRL_NO_BROADCAST   (1 << 6)
#define CTRL_UNKNOWN        (1 << 3)

/* address */
#define ADDR_BROADCAST 0xffffffff;

#define VOLTAGE_DIVISOR 100     //to volts
#define CURRENT_DIVISOR 1000    // to ampere
#define FREQUENCE_DIVISOR 100   // to herz

typedef enum {
    PASSWORD_USER,
    PASSWORD_INSTALLER
}user_type_t;

enum {
    TOTAL_POWER    = 0x263f,

    MAX_PHASE1     = 0x411e,
    MAX_PHASE2     = 0x411f,
    MAX_PHASE3     = 0x4120,

    UNKNOWN_1      = 0x4166,
    UNKNWON_2      = 0x417f,

    POWER_PHASE1   = 0x4640,
    POWER_PHASE2   = 0x4641,
    POWER_PHASE3   = 0x4642,

    VOLTAGE_PHASE1 = 0x4648,
    VOLTAGE_PHASE2 = 0x4649,
    VOLTAGE_PHASE3 = 0x464a,

    CURRENT_PHASE1 = 0x4650,
    CURRENT_PHASE2 = 0x4651,
    CURRENT_PHASE3 = 0x4652,

    FREQUENCE      = 0x4657
};

enum  {
    DC_POWER   = 0x251e,
    DC_VOLTAGE = 0x451f,
    DC_CURRENT = 0x4521
};

enum {
    STAT_OPERATION_TIME = 0x462E,
    STAT_FEED_IN_TIME   = 0x462F,
    STAT_TOTAL_YIELD    = 0x2601,
    STAT_DAY_YIELD      = 0x2622,
};

static const uint32_t smadata2plus_serial = 0x3b225946;

typedef struct serial_s {
    uint8_t serial[4];
}serial_t;

struct smadata2plus_s {
    connection_t    *con;
    smabluetooth_t  *sma;
    smanet_t        *smanet;
    uint8_t         counter;
    serial_t        serial[1];
    uint32_t        start_time;

    pvlib_dc_t      dc_data;
};

static int connect_bluetooth(smadata2plus_t *sma)
{
    int signal;

    if (smabluetooth_connect(sma->sma) < 0) return -1;

    signal = smabluetooth_signal(sma->sma);

    if (signal < 0) return -1;

    LOG_INFO("Signal strength: %d percent.", signal);

    return 0;
}

static int test = 0;
static int smadata2plus_write(smadata2plus_t *sma, smadata2plus_packet_t *packet)
{
    uint8_t buf[511 + HEADER_SIZE];
    uint8_t size = HEADER_SIZE;

    assert(packet->len + HEADER_SIZE <= sizeof(buf));

    buf[0] = packet->cmd;
    buf[1] = packet->ctrl;

    if (packet->dst == SMADATA2PLUS_BROADCAST) {
        buf[2] = 0xff;
        buf[3] = 0xff;
    } else {
        buf[2] = 0x4e;
        buf[3] = 0x00;
    }
    byte_store_u32_little(&buf[4], packet->dst);

    buf[8] = 0x00;
    buf[9] = packet->flag;

    buf[10] = 0x78;
    buf[11] = 0x00;
    byte_store_u32_little(&buf[12], smadata2plus_serial);

    buf[16] = 0x00;

    if (packet->ctrl== 0xe8) buf[17] = 0;
    else buf[17] = packet->flag;

    buf[18] = 0x00;
    buf[19] = 0x00;

    //FIXME: HACK
    if (packet->pkt_cnt != 0xff) buf[20] = packet->pkt_cnt;
    else size -= 2;buf[20] = 0;

    buf[21] = 0x00;

/*
    if (sma->counter == 0) buf[22] = 1;
    else if (sma->counter == 1) buf[22] = 0;
  */  if (sma->counter == 2 && !test) {
        buf[22] = sma->counter--;
        test = 1;
    }
    else buf[22] = sma->counter;
    sma->counter++;


    if (packet->pkt_start) buf[23] = 0x80;
    else buf[23] = 0x00;

    memcpy (&buf[size], packet->data, packet->len);

    return smanet_write(sma->smanet, buf, size + packet->len, packet->dst == SMADATA2PLUS_BROADCAST);
}

static int smadata2plus_read(smadata2plus_t *sma, smadata2plus_packet_t *packet)
{
    uint8_t buf[512 + HEADER_SIZE];
    int     size = HEADER_SIZE;
    int     len;

    assert(packet->len <= 512);

    len = smanet_read(sma->smanet, buf, packet->len + HEADER_SIZE);
    if (len < 0) {
        LOG_ERROR("smanet_read failed.");
        return -1;
    }

    packet->cmd  = buf[0];
    packet->ctrl = buf[1];
    packet->dst  = byte_parse_u32_little(&buf[4]);
    packet->src  = byte_parse_u32_little(&buf[12]);
    packet->flag = buf[9];
    packet->pkt_cnt   = buf[20];
    packet->pkt_start = (buf[23] == 0x80) ? 1 : 0;

    //FIXME: HACK!
    if (buf[23] != 0x80 && buf[23] != 0x00) {
        len++;
        size -= 2;
    }

    len -= HEADER_SIZE;
    if (len < packet->len) packet->len = len;

    memcpy(packet->data, &buf[size], packet->len);

    return 0;
}

static int sync_online(smadata2plus_t *sma)
{
    smadata2plus_packet_t packet;
    uint8_t buf[16];

    packet.cmd  = CMD_SYNC_ONLINE;
    packet.ctrl = CTRL_MASTER;
    packet.dst  = ADDR_BROADCAST;
    packet.flag = 0x05;
    packet.data = buf;
    packet.len  = sizeof(buf);
    packet.pkt_cnt   = 0;
    packet.pkt_start = 1;

    memset(buf, 0x00, sizeof(buf));

    buf[0] = 0x0c;
    buf[2] = 0xfd;
    buf[3] = 0xff;

    return smadata2plus_write(sma, &packet);
}

static int send_time(smadata2plus_t *sma)
{
    uint8_t buf[40];
    smadata2plus_packet_t packet;
    time_t cur_time;

    memset(buf, 0x00, sizeof(buf));

    buf[0] = 0x0a;
    buf[1] = 0x02;
    buf[3] = 0xf0;
    buf[5] = 0x6d;
    buf[6] = 0x23;
    buf[9] = 0x6d;
    buf[10] = 0x23;
    buf[13] = 0x6d;
    buf[14] = 0x23;

    cur_time = time(NULL);
    LOG_INFO("send_time: %s", ctime(&cur_time));

    /* FIXME: time ??? */
    byte_store_u32_little(&buf[16], cur_time);
    byte_store_u32_little(&buf[20], cur_time - 10);
    byte_store_u32_little(&buf[24], cur_time);

    buf[32] = 1;
    buf[36] = 1;

    packet.cmd  = CMD_TIME;
    packet.ctrl = CTRL_MASTER;
    packet.dst  = ADDR_BROADCAST;
    packet.flag = 0x00;
    packet.data = buf;
    packet.len  = sizeof(buf);
    packet.pkt_cnt   = 0;
    packet.pkt_start = 1;

    return smadata2plus_write(sma, &packet);
}

static int read_archiv_channel(smadata2plus_t *sma, uint32_t address, uint32_t time_from, uint32_t time_to)
{
    smadata2plus_packet_t packet;
    uint8_t buf[16];

    packet.cmd  = CMD_CHANNEL_REQUEST;
    packet.ctrl = CTRL_MASTER | CTRL_NO_BROADCAST;
    packet.dst  = address;
    packet.flag = 0x00;
    packet.data = buf;
    packet.len  = sizeof(buf);
    packet.pkt_cnt   = 0;
    packet.pkt_start = 1;

    memset(buf, 0x00, sizeof(buf));

    buf[1] = 0x02;
    buf[3] = 0x70;

    byte_store_u32_little(&buf[4], time_from);
    byte_store_u32_little(&buf[8], time_to);

    return smadata2plus_write(sma, &packet);
}

static int read_channel(smadata2plus_t *sma, uint8_t type, uint8_t channel, uint16_t from_idx, uint16_t to_idx)
{
    smadata2plus_packet_t packet;
    uint8_t buf[12];

    memset(buf, 0x00, sizeof(buf));

    packet.cmd  = CMD_CHANNEL_REQUEST;
    packet.ctrl = CTRL_MASTER;
    packet.dst  = ADDR_BROADCAST;
    packet.flag = 0x00;
    packet.data = buf;
    packet.len  = sizeof(buf);
    packet.pkt_cnt   = 0;
    packet.pkt_start = 1;

    buf[0] = 0x00;
    buf[1] = 0x02;
    buf[2] = type;
    buf[3] = channel;

    byte_store_u16_little(&buf[5], from_idx);
    byte_store_u16_little(&buf[9], to_idx);

    if (to_idx || from_idx) buf[8] = 0xff;

    return smadata2plus_write(sma, &packet);
}

static int send_password(smadata2plus_t *sma, const char *password, user_type_t user)
{
    smadata2plus_packet_t packet;
    uint8_t buf[32];
    int i = 0;
    time_t cur_time;

    packet.cmd  = CMD_PASSWORD;
    packet.ctrl = CTRL_MASTER;
    packet.dst  = ADDR_BROADCAST;
    packet.flag = 0x01;
    packet.data = buf;
    packet.len  = sizeof(buf);
    packet.pkt_cnt   = 0;
    packet.pkt_start = 1;

    memset(buf, 0x00, sizeof(buf));

    buf[0] = 0x0c;
    buf[1] = 0x04;
    buf[2] = 0xfd;
    buf[3] = 0xff;
    buf[4] = 0x07;
    buf[8] = 0x84;
    buf[9] = 0x03;

    cur_time = time(NULL);
    LOG_INFO("Sending password %s at %s.", password, ctime(&cur_time));

    byte_store_u32_little(&buf[12], cur_time);

    memset(&buf[20], 0x88, 12);
    for (i = 0; (i < 12) && (password[i] != '\0'); i++) {
        buf[20 + i] = password[i] ^ 0x88;
    }

    return smadata2plus_write(sma, &packet);
}

static int cmd_A008(smadata2plus_t *sma)
{
    uint8_t buf[8];
    smadata2plus_packet_t packet;

    buf[0] = 0x0e;
    buf[1] = 0x01;
    buf[2] = 0xfd;
    memset(&buf[3], 0xff, 5);

    packet.cmd  = CMD_UNKNOWN;
    packet.ctrl = CTRL_MASTER;
    packet.dst  = ADDR_BROADCAST;
    packet.flag = 0x03;
    packet.data = buf;
    packet.len  = sizeof(buf);
    packet.pkt_cnt   = 0;
    packet.pkt_start = 1;

    return smadata2plus_write(sma, &packet);
}

static int cmd_E808(smadata2plus_t *sma, uint32_t serial)
{
    uint8_t buf[8];
    smadata2plus_packet_t packet;

    memset(buf, 0x00, 8);
    buf[0] = 0x0d;
    buf[1] = 0x04;
    buf[2] = 0xfd;
    buf[3] = 0xff;
    buf[4] = 0x01;

    packet.cmd  = CMD_UNKNOWN;
    packet.ctrl = CTRL_MASTER | CTRL_NO_BROADCAST | CTRL_UNKNOWN;
    packet.dst  = serial;
    packet.flag = 0x01;
    packet.data = buf;
    packet.len  = sizeof(buf);
    packet.pkt_cnt   = 0;
    packet.pkt_start = 1;

    return smadata2plus_write(sma, &packet);
}


static int time_setup(smadata2plus_t *sma)
{
    smadata2plus_packet_t packet;
    uint8_t buf[42];
    uint8_t unknown[6];
    uint8_t unknown2[5];
    uint32_t time1;
    uint32_t time2;
    uint32_t serial;


    if (send_time(sma) < 0) return -1;

    packet.len  = sizeof(buf);
    packet.data = buf;


    if (smadata2plus_read(sma, &packet) < 0) {
        LOG_ERROR("smadata2plus_read failed!");
        return -1;
    }

    if (packet.cmd != CMD_TIME) {
        LOG_ERROR("Invalid packet cmd!");
        return -1;
    }

    memcpy(unknown, buf, 6);
    time1 = byte_parse_u32_little(&buf[18]);
    time2 = byte_parse_u32_little(&buf[22]);
    memcpy(unknown2, &buf[30], 5);

    serial = packet.src;

    LOG_INFO("time answer1: %s", ctime((time_t*)&time1));
    LOG_INFO("time answer2: %s", ctime((time_t*)&time2));

    memset(&packet, 0x00, sizeof(packet));
    memset(buf, 0x00, 10);

    memcpy(buf, unknown, 6);
    buf[6] = 0x01;

    packet.cmd  = CMD_UNKNOWN;
    packet.ctrl = CTRL_MASTER | CTRL_UNKNOWN | CTRL_NO_BROADCAST;
    packet.dst  = serial;
    packet.flag = 0x00;
    packet.data = buf;
    packet.len  = 10;
    packet.pkt_cnt   = 0xff;
    packet.pkt_start = 0;

    if (smadata2plus_write(sma, &packet) < 0) {
        LOG_ERROR("smadata2plus_write failed!");
        return -1;
    }

    memset(&packet, 0x00, sizeof(packet));
    memset(buf, 0x00, 40);


    packet.cmd  = CMD_TIME;
    packet.ctrl = CTRL_MASTER;
    packet.dst  = ADDR_BROADCAST;
    packet.flag = 0x00;
    packet.data = buf;
    packet.len  = 40;
    packet.pkt_cnt   = 0;
    packet.pkt_start = 1;

    buf[0] = 0x0a;
    buf[1] = 0x02;
    buf[3] = 0xf0;
    buf[5] = 0x6d;
    buf[6] = 0x23;
    buf[9] = 0x6d;
    buf[10] = 0x23;
    buf[13] = 0x6d;
    buf[14] = 0x23;

    byte_store_u32_little(&buf[16], time1);
    byte_store_u32_little(&buf[20], time2);
    byte_store_u32_little(&buf[24], time1);

    memcpy(&buf[28], unknown2, 5);
    buf[33] = 0xfe;
    buf[34] = 0x7e;
    buf[36] = 0x01;

    if (smadata2plus_write(sma, &packet) < 0) {
        LOG_ERROR("smadata2plus_write failed!");
        return -1;
    }
    return 0;
}

static int authenticate(smadata2plus_t *sma, const char *password, user_type_t user)
{
    uint8_t buf[52];
    int     i = 0;
    smadata2plus_packet_t packet;

    packet.data = buf;
    packet.len  = 52;

    if (send_password(sma, password, user) < 0) {
        LOG_ERROR("Failed sending password!");
        return -1;
    }

    if (smadata2plus_read(sma, &packet) < 0) {
        return -1;
    }

    for (i = 0; i <  (i < 12) && (password[i] != '\0'); i++) {
        if ((buf[20 + i] ^ 0x88) != password[i]) {
            LOG_ERROR("Plant authentication error!");
            //return -1;
            printf("pos: %d, password: %s, buf: %X\n", i, password, buf[20 + i]);
        }
    }

    return 0;
}

static int read_status(smadata2plus_t *sma)
{
    smadata2plus_packet_t packet;

    packet.len  = 0;
    packet.data = NULL;

    read_channel(sma, 0x00, 0x58, 0x821e, 0x8221);
    read_channel(sma, 0x00, 0x58, 0xa21e, 0xa21e);
    read_channel(sma, 0x80, 0x51, 0x2148, 0x2148);

    return 0;
}


static smadata2plus_t *init(connection_t *con)
{
    smadata2plus_t *sma;
    smabluetooth_t *smabluetooth;
    smanet_t *smanet;

    smabluetooth = smabluetooth_init(con);
    if (smabluetooth == NULL) return NULL;

    smanet = smanet_init(PROTOCOL, NULL, smabluetooth);
    if (smanet == NULL) return NULL;

    sma = malloc(sizeof(*sma));

    sma->con        = con;
    sma->sma        = smabluetooth;
    sma->smanet     = smanet;
    sma->counter    = 0;
    sma->start_time = (uint32_t)time(NULL);

    return sma;
}


void smadata2plus_close(smadata2plus_t *sma)
{
    smabluetooth_close(sma->sma);
    smanet_close(sma->smanet);

    free(sma);
}

int smadata2plus_connect(pvlib_interface_t *interface, const char *password)
{
    smadata2plus_packet_t packet;
    smadata2plus_t *sma;
    uint32_t serial = 0x7d2d131f;

    sma = (smadata2plus_t*)interface->handle;

    packet.len  = 0;
    packet.data = NULL;

    if (connect_bluetooth(sma) < 0) return -1;

    if (cmd_A008(sma) < 0) {
        LOG_ERROR("cmd A008 failed!");
        return -1;
    }

    if (read_channel(sma, 0x00, 0x00, 0x00, 0x00) < 0) {
        LOG_ERROR("read_channel failed!");
    }

    if (smadata2plus_read(sma, &packet) < 0) {
        LOG_ERROR("Read failed!");
    }

    if (authenticate(sma, password, PASSWORD_USER) < 0) {
        LOG_ERROR("Authentication failed!");
        return -1;
    }

    if (cmd_E808(sma, serial) < 0) return -1;

    if (time_setup(sma) < 0) {
        LOG_ERROR("Time setup failed!");
        return -1;
    }

    if (read_status(sma) < 0) {
        LOG_ERROR("read status failed!");
        return -1;
    }

    packet.len  = 0;
    packet.data = NULL;

    if (smadata2plus_read(sma, &packet) < 0) {
        LOG_ERROR("Read failed!");
        return -1;
    }

    packet.len  = 0;
    packet.data = NULL;

    if (smadata2plus_read(sma, &packet) < 0) {
        LOG_ERROR("Read failed!");
        return -1;
    }

    packet.len  = 0;
    packet.data = NULL;

    if (smadata2plus_read(sma, &packet) < 0) {
        LOG_ERROR("Read failed!");
        return -1;
    }

    return 0;
}

static int smadata2plus_open(pvlib_interface_t *interface) { return 0; }

static int parse_ac(uint8_t *data, int len, pvlib_ac_t *ac)
{
    int pos = 0;

    memset(ac, 0xff, sizeof(*ac));

    pos = 13;
    while (pos + 11 < len) {
        uint32_t value = byte_parse_u32_little(&data[pos + 7]);
        switch (byte_parse_u16_little(&data[pos])) {
            case TOTAL_POWER    : LOG_INFO("TOTAL_POWER, type: %02X,  %d", data[pos + 2], value); break;

            case MAX_PHASE1     : LOG_INFO("MAX_PHASE_1, type: %02X : %d", data[pos + 2], value); break;
            case MAX_PHASE2     : LOG_INFO("MAX_PHASE_2, type: %02X : %d", data[pos + 2], value); break;
            case MAX_PHASE3     : LOG_INFO("MAX_PHASE_3, type: %02X : %d", data[pos + 2], value); break;

            case UNKNOWN_1      : LOG_INFO("UNKNOWN_1, type: %02X : %d", data[pos + 2], value); break;
            case UNKNWON_2      : LOG_INFO("UNKNOWN_2, type: %02X : %d", data[pos + 2], value); break;

            case POWER_PHASE1   :
                LOG_INFO("POWER PHASE 1, type: %02X : %d", data[pos + 2], value);
                ac->power[0] = value;
                break;
            case POWER_PHASE2   :
                LOG_INFO("POWER PHASE 2, type: %02X : %d", data[pos + 2], value);
                ac->power[1] = value;
                break;
            case POWER_PHASE3   :
                LOG_INFO("POWER PHASE 3, type: %02X : %d", data[pos + 2], value);
                ac->power[2] = value;
                break;

            case VOLTAGE_PHASE1 :
                LOG_INFO("VOLTAGE PHASE 1, type: %02X : %f", data[pos + 2], (float)value / VOLTAGE_DIVISOR);
                ac->voltage[0] = value * 1000 / VOLTAGE_DIVISOR;
                break;
            case VOLTAGE_PHASE2 :
                LOG_INFO("VOLTAGE PHASE 2, type: %02X : %f", data[pos + 2], (float)value / VOLTAGE_DIVISOR);
                ac->voltage[1] = value * 1000 / VOLTAGE_DIVISOR;
                break;
            case VOLTAGE_PHASE3 :
                LOG_INFO("VOLTAGE PHASE 3, type: %02X : %f", data[pos + 2], (float)value / VOLTAGE_DIVISOR);
                ac->voltage[2] = value * 1000 / VOLTAGE_DIVISOR;
                break;

            case CURRENT_PHASE1 :
                LOG_INFO("CURRENT PHASE 1, type: %02X : %f", data[pos + 2], (float)value / CURRENT_DIVISOR);
                ac->current[0] = value * 1000 / CURRENT_DIVISOR;
                break;
            case CURRENT_PHASE2 :
                LOG_INFO("CURRENT PHASE 2, type: %02X : %f", data[pos + 2], (float)value / CURRENT_DIVISOR);
                ac->current[1] = value * 1000 / CURRENT_DIVISOR;
                break;
            case CURRENT_PHASE3 :
                LOG_INFO("CURRENT PHASE 3, type: %02X : %f", data[pos + 2], (float)value / CURRENT_DIVISOR);
                ac->current[2] = value * 1000 / CURRENT_DIVISOR;
                break;

            case FREQUENCE      :
                LOG_INFO("Frequence, type: %02X : %f", data[pos + 2], (float)value / FREQUENCE_DIVISOR);
                break;
            default : break;
        }

        pos += 28;
    }

    return 0;
}

static int get_ac(pvlib_interface_t *interface, int num, uint32_t *id, pvlib_ac_t *ac)
{
    smadata2plus_packet_t packet;
    uint8_t data[512];
    smadata2plus_t *sma;

    sma = (smadata2plus_t*)interface->handle;

    if (sync_online(sma) < 0) return -1;

    if (read_channel(sma, 0x00, 0x51, 0x2000, 0x50ff) < 0) return -1;

    memset(&packet, 0x00, sizeof(packet));
    packet.data = data;
    packet.len  = sizeof(data);

    if (smadata2plus_read(sma, &packet) < 0) {
        return -1;
    }

    *id = packet.src;
    return parse_ac(data, packet.len, ac);
}

static int parse_dc(uint8_t *data, int len, pvlib_dc_t *dc)
{
    int pos;

    pos = 13;
    while (pos + 11 < len) {
        uint32_t value = byte_parse_u32_little(&data[pos + 7]);
        uint32_t value_time = byte_parse_u32_little(&data[pos + 3]);

        switch (byte_parse_u16_little(&data[pos])) {
        case DC_POWER   :
            LOG_INFO("POWER_LINE_%d type: %02X : %d, time %s", data[pos - 1], data[pos + 2], value, ctime((time_t *)&value_time));
            dc->power[data[pos] - 1] = value;
            break;
        case DC_VOLTAGE :
            LOG_INFO("VOLLTAGE_LINE_%d: %02X : %f, time %s", data[pos - 1], data[pos + 2], (float)value / VOLTAGE_DIVISOR, ctime((time_t *)&value_time));
            dc->power[data[pos] - 1] = value * 1000 / VOLTAGE_DIVISOR;
            break;
        case DC_CURRENT :
            LOG_INFO("CURRENT_LINE_%d: %02X : %f, time %s", data[pos - 1], data[pos + 2], (float)value / CURRENT_DIVISOR, ctime((time_t *)&value_time));
            dc->current[data[pos] - 1] = value * 1000 / CURRENT_DIVISOR;
            break;
        default : break;
        }

        pos += 28;
    }

    return 0;
}

static int get_dc(pvlib_interface_t *interface, int num, uint32_t *id, pvlib_dc_t *dc)
{
    smadata2plus_t *sma;
    smadata2plus_packet_t packet;
    uint8_t buf[512];

    sma = (smadata2plus_t*)interface->handle;

    if (read_channel(sma, 0x80, 0x53, 0x2000, 0x5000) < 0) return -1;

    memset(&packet, 0x00, sizeof(packet));
    packet.data = buf;
    packet.len  = sizeof(buf);

    if (smadata2plus_read(sma, &packet) < 0) {
        return -1;
    }

    *id = packet.src;
    return parse_dc(packet.data, packet.len, dc);
}

static int parse_stats(uint8_t *data, int len, pvlib_stats_t *stats)
{
    int pos = 13;

    while (pos + 11 < len) {
        uint32_t value = byte_parse_u32_little(&data[pos + 7]);

        switch (byte_parse_u16_little(&data[pos])) {
        case STAT_TOTAL_YIELD :
            LOG_INFO("TOTAL_YIELD type: %02X : %f", data[pos + 2], (float)value / 1000);
            stats->total_yield = value;
            break;
        case STAT_DAY_YIELD :
            LOG_INFO("DAY_YIELD type: %02X : %f", data[pos + 2], (float)value  / 1000);
            stats->day_yield = value;
            break;
        case STAT_OPERATION_TIME :
            LOG_INFO("OPERATION_TIME type: %02X, hours : %d", data[pos + 2], value / 3600);
            stats->operation_time = value;
            break;
        case STAT_FEED_IN_TIME :
            LOG_INFO("FEED_IN_TIME type: %02X, hours : %d", data[pos + 2], value / 3600);
            stats->feed_in_time = value;
            break;
        default : break;
        }

        pos += 16;
    }

    return 0;
}
static int get_stats(pvlib_interface_t *interface, int num, uint32_t *id, pvlib_stats_t *stats)
{
    smadata2plus_t *sma;
    smadata2plus_packet_t packet;
    uint8_t data[512];

    sma = (smadata2plus_t*)interface->handle;

    memset(&packet, 0x00, sizeof(packet));
    packet.data = data;
    packet.len  = sizeof(data);

    if (read_channel(sma, 0x00, 0x54, 0x2000, 0x50ff) < 0) return -1;

    if (smadata2plus_read(sma, &packet) < 0) return -1;

    parse_stats(packet.data, packet.len, stats);
    *id = packet.src;
    return 0;
}

int smadata2plus_test(smadata2plus_t *sma)
{
    smadata2plus_packet_t packet;
    uint8_t data[512];
    int pos = 0;
    int i = 0;

//    sync_online(sma);

    if (read_channel(sma, 0x80, 0x54, 0x2000, 0x50ff) < 0) return -1;

    memset(&packet, 0x00, sizeof(packet));
    packet.data = data;
    packet.len  = sizeof(data);

    if (smadata2plus_read(sma, &packet) < 0) {
        return -1;
    }

    pos = 13;
    i = 0;
    while (pos + 11 < packet.len) {
        uint32_t value = byte_parse_u32_little(&data[pos + 7]);
        uint32_t value_time = byte_parse_u32_little(&data[pos + 3]);

        LOG_INFO("value unknwon_%d, time: %s : %d", i++, ctime((time_t *)&value_time), value);
        pos += 16;
    }
    return 0;
}

static int string_inverter_num(pvlib_interface_t *interface)
{
    return 1;
}

pvlib_interface_t  *smadata2plus_init(connection_t *con)
{
    pvlib_interface_t *interface;
    smadata2plus_t *sma;

    sma = init(con);

    if (sma == NULL) return NULL;

    interface = malloc(sizeof(*interface));
    interface->protocol = PVLIB_SMADATA2PLUS;
    interface->handle   = sma;
    interface->open     = smadata2plus_open;
    interface->string_inverter_num = string_inverter_num;
    interface->connect  = smadata2plus_connect;
    interface->get_stats = get_stats;
    interface->get_ac   = get_ac;
    interface->get_dc   = get_dc;

    return interface;
}
