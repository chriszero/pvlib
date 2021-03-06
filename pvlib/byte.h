/*
 *   Pvlib - big, little endian conversion
 *
 *   Copyright (C) 2011 pvlogdev@gmail.com
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

#ifndef BYTE_H
#define BYTE_H

#ifdef __cplusplus
#define __STDC_CONSTANT_MACROS
#endif

#include <stdint.h>

#ifdef _MSC_VER
#   define BYTE_FAST_SWAP
#	include <stdlib.h>
#	define BSWAP_16(X) _byteswap_ushort(X)
#	define BSWAP_32(X) _byteswap_ulong(X)
#	define BSWAP_64(X) _byteswap_uint64(X)
#elif (((__GNUC__ >= 4) && (__GNUC_MINOR__ >= 3))  | (__GNUC__ > 4))
#   define BYTE_FAST_SWAP
#	define BSWAP_16(X) (((uint16_t)(X) << 8) | ((uint16_t)(X) >> 8))
#	define BSWAP_32(X) __builtin_bswap32(X)
#	define BSWAP_64(X) __builtin_bswap64(X)
#else
#   define BYTE_SLOW_SWAP
#	define BSWAP_16(X) (((uint16_t)(X) << 8) | ((uint16_t)(X) >> 8))
#	define BSWAP_32(X) (((uint32_t)(X) << 24)              | \
					   (((uint32_t)(X) << 8) & 0x00FF0000) | \
					   (((uint32_t)(X) >> 8) & 0x0000FF00) | \
					   (((uint32_t)(X) >> 24)))
#	define BSWAP_64(X) (((uint64_t)(X) << 56) | \
                       (((uint64_t)(X) << 40) & UINT64_C(0x00ff000000000000)) | \
                       (((uint64_t)(X) << 24) & UINT64_C(0x0000ff0000000000)) | \
                       (((uint64_t)(X) << 8)  & UINT64_C(0x000000ff00000000)) | \
                       (((uint64_t)(X) >> 8)  & UINT64_C(0x00000000ff000000)) | \
                       (((uint64_t)(X) >> 24) & UINT64_C(0x0000000000ff0000)) | \
                       (((uint64_t)(X) >> 40) & UINT64_C(0x000000000000ff00)) | \
                       ((uint64_t)(X)  >> 56))
#endif

#ifdef __cplusplus
#undef __STDC_CONSTANT_MACROS
#endif

#if defined (__GLIBC__)
#   include <endian.h>
#   if (__BYTE_ORDER == __LITTLE_ENDIAN)
#       define BYTE_LITTLE_ENDIAN
#   elif (__BYTE_ORDER == __BIG_ENDIAN)
#      define BYTE_BIG_ENDIAN
#   else
#       define BYTE_UNKNOWN_ENDIAN
#   endif
#elif defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN)
#   define BYTE_BIG_ENDIAN
#elif defined (_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
#   define BYTE_LITTLE_ENDIAN
#elif defined (BIG_ENDIAN) && !defined(BIG_ENDIAN)
#   define  define BYTE_BIG_ENDIAN
#elif defined (LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
#   define BYTE_LITTLE_ENDIAN
#else
#   define BYTE_UNKNOWN_ENDIAN
#endif

/**
 * Parse little endian stored unsigned 16 bit integer.
 *
 * @param data to parse.
 * @return parsed integer.
 */
static inline uint16_t byte_parse_u16_little(uint8_t *data)
{
    return (uint16_t)data[1] << 8 | (uint16_t)data[0];
}

/**
 * Parse big endian stored unsigned 16 bit integer.
 *
 * @param data to parse.
 * @return parsed integer.
 */
static inline uint16_t byte_parse_u16_big(uint8_t *data)
{
    return (uint16_t)data[0] << 8 | (uint16_t)data[1];
}

/**
 * Parse little endian stored unsigned 32 bit integer.
 *
 * @param data to parse.
 * @return parsed integer.
 */
static inline uint32_t byte_parse_u32_little(uint8_t *data)
{
#ifdef LITTLE_ENDIAN
    return *((uint32_t*)data);
#else
    return BSWAP_32(*((uint32_t*)data));
#endif
}

/**
 * Parse big endian stored unsigned 32 bit integer.
 *
 * @param data to parse.
 * @return parsed integer.
 */
static inline uint32_t byte_parse_u32_big(uint8_t *data)
{
#ifdef LITTLE_ENDIAN
    return BSWAP_32(*((uint32_t*)data));
#else
    return *((uint32_t*)data);
#endif
}

/**
 * Parse little endian stored unsigned 64 bit integer.
 *
 * @param data to parse.
 * @return parsed integer.
 */
static inline uint64_t byte_parse_u64_little(uint8_t *data)
{
#ifdef LITTLE_ENDIAN
    return *((uint64_t*)data);
#else
    return BSWAP_64(*((uint64_t*)data));
#endif
}

/**
 * Parse big endian stored unsigned 64 bit integer.
 *
 * @param data to parse.
 * @return parsed integer.
 */
static inline uint64_t byte_parse_u64_big(uint8_t *data)
{
#ifdef LITTLE_ENDIAN
    return BSWAP_64(*((uint64_t*)data));
#else
    return *((uint64_t*)data);
#endif
}

/**
 * Store 16 bit integer in little endian format.
 *
 * @param data buf to store integer.
 * @param word integer to store.
 */
static inline void byte_store_u16_little(uint8_t *data, uint16_t word)
{
    data[0] = (uint8_t)(word & 0xff);
    data[1] = (uint8_t)((word >> 8) & 0xff);
}

/**
 * Store 16 bit integer in big endian format.
 *
 * @param data buf to store integer.
 * @param word integer to store.
 */
static inline void byte_store_u16_big(uint8_t *data, uint16_t word)
{
    data[0] = (uint8_t)((word >> 8) & 0xff);
    data[1] = (uint8_t)(word & 0xff);
}

/**
 * Store 32 bit integer in little endian format.
 *
 * @param data buf to store integer.
 * @param dword integer to store.
 */
static inline void byte_store_u32_little(uint8_t *data, uint32_t dword)
{
#ifdef LITTLE_ENDIAN
    (*(uint32_t*)data) = dword;
#else
    (*(uint32_t*)data) = BSWAP_32(dword);
#endif
}

/**
 * Store 32 bit integer in big endian format.
 *
 * @param data buf to store integer.
 * @param dword integer to store.
 */
static inline void byte_store_u32_big(uint8_t *data, uint32_t dword)
{
#ifdef LITTLE_ENDIAN
    (*(uint32_t*)data) = BSWAP_32(dword);
#else
    (*(uint32_t*)data) = dword;
#endif
}

/**
 * Store 64 bit integer in little endian format.
 *
 * @param data buf to store integer.
 * @param qword integer to store.
 */
static inline void byte_store_u64_little(uint8_t *data, uint64_t qword)
{
#ifdef LITTLE_ENDIAN
    (*(uint64_t*)data) = qword;
#else
    (*(uint64_t*)data) = BSWAP_64(qword);
#endif
}

/**
 * Store 64 bit integer in big endian format.
 *
 * @param data buf to store integer.
 * @param qword integer to store.
 */
static inline void byte_store_u64_big(uint8_t *data, uint64_t qword)
{
#ifdef LITTLE_ENDIAN
    (*(uint64_t*)data) = BSWAP_64(qword);
#else
    (*(uint64_t*)data) = qword;
#endif
}

#endif /* #ifndef BYTE_H */
