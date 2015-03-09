/*
 * bitcoin.h
 *
 * Copyright (C) 2015, Kevin Pan <bit.kevin@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */
#ifndef _BITCOIN_H
#define _BITCOIN_H

#include <stddef.h>

//
// address prefix
// @see https://en.bitcoin.it/wiki/List_of_address_prefixes
//
#define BITCOIN_ADDRESS_PREFIX_PUBKEY         0x00
#define BITCOIN_ADDRESS_PREFIX_PUBKEY_TESTNET 0x6F

#define BITCOIN_PUBKEY_UNCOMPRESSED 0x00
#define BITCOIN_PUBKEY_COMPRESSED   0x01

extern int bitcoin_sign_message(char *signature, size_t signature_size,
                                const char *msg, const size_t msg_len,
                                const char *priv_key_b58, int is_compressed_pubkey);

#endif
