/*
 * bitcoin.c
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
#include "bitcoin.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define skip_char(c) \
(((c) == '\r') || ((c) == '\n') || ((c) == ' ') || ((c) == '\t'))

const char *vg_b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const signed char vg_b58_reverse_map[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
    -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
    -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
    47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};


static int vg_b58_decode_check(const char *input, void *buf, size_t len) {
    int i, l, c;
    unsigned char *xbuf = NULL;
    BIGNUM bn, bnw, bnbase;
    BN_CTX *bnctx;
    unsigned char hash1[32], hash2[32];
    int zpfx;
    int res = 0;

    BN_init(&bn);
    BN_init(&bnw);
    BN_init(&bnbase);
    BN_set_word(&bnbase, 58);
    bnctx = BN_CTX_new();

    /* Build a bignum from the encoded value */
    l = strlen(input);
    for (i = 0; i < l; i++) {
        if (skip_char(input[i]))
            continue;
        c = vg_b58_reverse_map[(int)input[i]];
        if (c < 0)
            goto out;
        BN_clear(&bnw);
        BN_set_word(&bnw, c);
        BN_mul(&bn, &bn, &bnbase, bnctx);
        BN_add(&bn, &bn, &bnw);
    }

    /* Copy the bignum to a byte buffer */
    for (i = 0, zpfx = 0; input[i]; i++) {
        if (skip_char(input[i]))
            continue;
        if (input[i] != vg_b58_alphabet[0])
            break;
        zpfx++;
    }
    c = BN_num_bytes(&bn);
    l = zpfx + c;
    if (l < 5)
        goto out;
    xbuf = (unsigned char *) malloc(l);
    if (!xbuf)
        goto out;
    if (zpfx)
        memset(xbuf, 0, zpfx);
    if (c)
        BN_bn2bin(&bn, xbuf + zpfx);

    /* Check the hash code */
    l -= 4;
    SHA256(xbuf, l, hash1);
    SHA256(hash1, sizeof(hash1), hash2);
    if (memcmp(hash2, xbuf + l, 4))
        goto out;
    /* Buffer verified */
    if (len) {
        if (len > l)
            len = l;
        memcpy(buf, xbuf, len);
    }
    res = l;

out:
    if (xbuf)
        free(xbuf);
    BN_clear_free(&bn);
    BN_clear_free(&bnw);
    BN_clear_free(&bnbase);
    BN_CTX_free(bnctx);
    return res;
}


/**
 * ASCII <-> Base64 conversion as described in RFC1421.
 *
 * Copyright 2006-2010 Willy Tarreau <w@1wt.eu>
 * Copyright 2009-2010 Krzysztof Piotr Oledzki <ole@ans.pl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */
#define B64BASE	'#'		/** arbitrary chosen base value */
#define B64CMIN	'+'
#define B64CMAX	'z'
#define B64PADV	64		/** Base64 chosen special pad value */

const char base64tab[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char base64rev[] = "b###cXYZ[\\]^_`a###d###$%&'()*+,-./0123456789:;<=######>?@ABCDEFGHIJKLMNOPQRSTUVW";

/** Encodes <ilen> bytes from <in> to <out> for at most <olen> chars (including
 * the trailing zero). Returns the number of bytes written. No check is made
 * for <in> or <out> to be NULL. Returns negative value if <olen> is too short
 * to accept <ilen>. 4 output bytes are produced for 1 to 3 input bytes.
 */
static int base64_encode(char *in, int ilen, char *out, int olen) {
    int convlen;

    convlen = ((ilen + 2) / 3) * 4;

    if (convlen >= olen)
        return -1;

    /** we don't need to check olen anymore */
    while (ilen >= 3) {
        out[0] = base64tab[(((unsigned char)in[0]) >> 2)];
        out[1] = base64tab[(((unsigned char)in[0] & 0x03) << 4) | (((unsigned char)in[1]) >> 4)];
        out[2] = base64tab[(((unsigned char)in[1] & 0x0F) << 2) | (((unsigned char)in[2]) >> 6)];
        out[3] = base64tab[(((unsigned char)in[2] & 0x3F))];
        out += 4;
        in += 3; ilen -= 3;
    }

    if (!ilen) {
        out[0] = '\0';
    } else {
        out[0] = base64tab[((unsigned char)in[0]) >> 2];
        if (ilen == 1) {
            out[1] = base64tab[((unsigned char)in[0] & 0x03) << 4];
            out[2] = '=';
        } else {
            out[1] = base64tab[(((unsigned char)in[0] & 0x03) << 4) |
                               (((unsigned char)in[1]) >> 4)];
            out[2] = base64tab[((unsigned char)in[1] & 0x0F) << 2];
        }
        out[3] = '=';
        out[4] = '\0';
    }

    return convlen;
}


/** Decodes <ilen> bytes from <in> to <out> for at most <olen> chars.
 * Returns the number of bytes converted. No check is made for
 * <in> or <out> to be NULL. Returns -1 if <in> is invalid or ilen
 * has wrong size, -2 if <olen> is too short.
 * 1 to 3 output bytes are produced for 4 input bytes.
 */
static int base64_decode(const char *in, size_t ilen, char *out, size_t olen) {

    unsigned char t[4];
    signed char b;
    int convlen = 0, i = 0, pad = 0;

    if (ilen % 4)
        return -1;

    if (olen < ilen / 4 * 3)
        return -2;

    while (ilen) {

        /** if (*p < B64CMIN || *p > B64CMAX) */
        b = (signed char)*in - B64CMIN;
        if ((unsigned char)b > (B64CMAX-B64CMIN))
            return -1;

        b = base64rev[b] - B64BASE - 1;

        /** b == -1: invalid character */
        if (b < 0)
            return -1;

        /** padding has to be continous */
        if (pad && b != B64PADV)
            return -1;

        /** valid padding: "XX==" or "XXX=", but never "X===" or "====" */
        if (pad && i < 2)
            return -1;

        if (b == B64PADV)
            pad++;

        t[i++] = b;

        if (i == 4) {
            /**
             * WARNING: we allow to write little more data than we
             * should, but the checks from the beginning of the
             * functions guarantee that we can safely do that.
             */
            
            /** xx000000 xx001111 xx111122 xx222222 */
            out[convlen]   = ((t[0] << 2) + (t[1] >> 4));
            out[convlen+1] = ((t[1] << 4) + (t[2] >> 2));
            out[convlen+2] = ((t[2] << 6) + (t[3] >> 0));
            
            convlen += 3-pad;
            
            pad = i = 0;
        }
        
        in++;
        ilen--;
    }
    
    return convlen;
}

static size_t write_compact_size(const uint64_t val, uint8_t *dest) {
    if (val < 0xfd) {
        *dest++ = (unsigned char)val;
        return 1;
    } else if (val <= 0xffff) {
        *dest++ = 0xfd;
        *(uint16_t *)dest = (uint16_t)val;
        return 2;
    } else if (val <= 0xffffffff) {
        *dest++ = 0xfe;
        *(uint32_t *)dest = (uint32_t)val;
        return 4;
    } else {
        *dest++ = 0xff;
        *(uint64_t *)dest = (uint64_t)val;
        return 8;
    }
    return 0;
}

static void dsha265_message(uint8_t *hash,
                            const uint8_t *msg, const size_t len_msg) {
    const char *magic = "Bitcoin Signed Message:\n";  // bitcoin message magic
    const size_t len_magic = strlen(magic);
    size_t buf_size = len_magic + len_msg + 9/*max_compact_size*/ * 2;

    char *buf = (char *)malloc(buf_size);
    size_t buf_len = 0;
    memset(buf, 0, buf_size);

    buf_len += write_compact_size(len_magic, (uint8_t *)buf);
    memcpy(buf + buf_len, magic, len_magic);
    buf_len += len_magic;

    buf_len += write_compact_size(len_msg, (uint8_t *)buf + buf_len);
    memcpy(buf + buf_len, msg, len_msg);
    buf_len += len_msg;
    assert(buf_len <= buf_size);

    uint8_t hash1[32];
    SHA256((uint8_t *)buf, buf_len, hash1);
    SHA256(hash1, sizeof(hash1), hash);
    free(buf);
}

static int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key) {
    int ok = 0;
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL;

    if (!eckey) return 0;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    pub_key = EC_POINT_new(group);
    if (pub_key == NULL)
        goto err;

    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    EC_KEY_set_private_key(eckey,priv_key);
    EC_KEY_set_public_key(eckey,pub_key);
    ok = 1;

err:
    if (pub_key)
        EC_POINT_free(pub_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);
    return ok;
}

// Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
// recid selects which key is recovered
// if check is non-zero, additional checks are performed
static int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig,
                                     const unsigned char *msg,
                                     int msglen, int recid, int check) {
    if (!eckey) return 0;

    int ret = 0;
    BN_CTX *ctx = NULL;

    BIGNUM *x = NULL;
    BIGNUM *e = NULL;
    BIGNUM *order = NULL;
    BIGNUM *sor = NULL;
    BIGNUM *eor = NULL;
    BIGNUM *field = NULL;
    EC_POINT *R = NULL;
    EC_POINT *O = NULL;
    EC_POINT *Q = NULL;
    BIGNUM *rr = NULL;
    BIGNUM *zero = NULL;
    int n = 0;
    int i = recid / 2;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
    x = BN_CTX_get(ctx);
    if (!BN_copy(x, order)) { ret=-1; goto err; }
    if (!BN_mul_word(x, i)) { ret=-1; goto err; }
    if (!BN_add(x, x, ecsig->r)) { ret=-1; goto err; }
    field = BN_CTX_get(ctx);
    if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) { ret=-2; goto err; }
    if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
    if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret=0; goto err; }
    if (check) {
        if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
        if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-2; goto err; }
        if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
    }
    if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    n = EC_GROUP_get_degree(group);
    e = BN_CTX_get(ctx);
    if (!BN_bin2bn(msg, msglen, e)) { ret=-1; goto err; }
    if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
    zero = BN_CTX_get(ctx);
    if (!BN_zero(zero)) { ret=-1; goto err; }
    if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-1; goto err; }
    rr = BN_CTX_get(ctx);
    if (!BN_mod_inverse(rr, ecsig->r, order, ctx)) { ret=-1; goto err; }
    sor = BN_CTX_get(ctx);
    if (!BN_mod_mul(sor, ecsig->s, rr, order, ctx)) { ret=-1; goto err; }
    eor = BN_CTX_get(ctx);
    if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-1; goto err; }
    if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-2; goto err; }
    if (!EC_KEY_set_public_key(eckey, Q)) { ret=-2; goto err; }

    ret = 1;

err:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (R != NULL) EC_POINT_free(R);
    if (O != NULL) EC_POINT_free(O);
    if (Q != NULL) EC_POINT_free(Q);
    return ret;
}

int sign_message(char *signature, size_t signature_size,
                 const char *msg, const size_t msg_len,
                 const char *priv_key_b58, int is_compressed_pubkey) {
    EC_KEY *pkey   = NULL;
    ECDSA_SIG *sig = NULL;
    EC_KEY *eckey  = NULL;  // recover key

    uint8_t pubKey[65];  // public key max size is 65 bytes
    uint8_t pubKey_rc[65];
    int pubkey_size, pubkey_rc_size;
    uint8_t sigbuf[65];

    unsigned char *pbegin = NULL;
    unsigned char buf[128] = {0};
    int res, fOK = -1;
    int nBitsR, nBitsS;
    unsigned char hash[32];

    dsha265_message(hash, (uint8_t *)msg, msg_len);  // message double sha256

    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_conv_form(pkey, is_compressed_pubkey ?
                         POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);

    // import secret
    vg_b58_decode_check(priv_key_b58, buf, 33);
    BIGNUM *bn = BN_bin2bn(buf + 1, 32, BN_new());
    res = EC_KEY_regenerate_key(pkey, bn);
    BN_clear_free(bn);
    if (!res){ goto error; }

    // get pubkey
    pubkey_size = i2o_ECPublicKey(pkey, NULL);
    if (!pubkey_size) { goto error; }

    pbegin = pubKey;
    if (i2o_ECPublicKey(pkey, &pbegin) != pubkey_size) { goto error; }
    
    // do sign
    sig = ECDSA_do_sign(hash, sizeof(hash), pkey);
    if (!sig) { goto error; }

    nBitsR = BN_num_bits(sig->r);
    nBitsS = BN_num_bits(sig->s);
    if (nBitsR <= 256 && nBitsS <= 256) {
        int nRecId = -1;
        eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
        EC_KEY_set_conv_form(eckey, is_compressed_pubkey ?
                             POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);

        for (int i = 0; i < 4; i++) {
            if (ECDSA_SIG_recover_key_GFp(eckey, sig, (unsigned char*)hash,
                                          sizeof(hash), i, 1) == 1) {
                // get recover pubkey
                pubkey_rc_size = i2o_ECPublicKey(pkey, NULL);
                if (!pubkey_rc_size) { goto error; }

                pbegin = pubKey_rc;
                if (i2o_ECPublicKey(eckey, &pbegin) != pubkey_rc_size) {
                    goto error;
                }
                // check recover key
                if (pubkey_size == pubkey_rc_size &&
                    memcmp(pubKey, pubKey_rc, pubkey_rc_size) == 0) {
                    nRecId = i;
                    break;
                }
            }
        }
        if (nRecId == -1) { goto error; }

        sigbuf[0] = nRecId + 27 + (is_compressed_pubkey ? 4 : 0);
        BN_bn2bin(sig->r, sigbuf + 33 - (nBitsR+7)/8);
        BN_bn2bin(sig->s, sigbuf + 65 - (nBitsS+7)/8);
        fOK = 0;
    }

    // convent to base64
    base64_encode((char *)sigbuf, sizeof(sigbuf), signature, (int)signature_size);
    
error:
    if (pkey)  { EC_KEY_free(pkey); }
    if (eckey) { EC_KEY_free(eckey); }
    if (sig)   { ECDSA_SIG_free(sig); }
    
    return fOK;
}

int verify_message(const char *address,
                   const uint8_t *hash, const int hashlen,
                   const uint8_t *sigbuf, const int siglen) {
    EC_KEY *pkey = NULL;
    // -1 = error, 0 = bad sig, 1 = good
    if (ECDSA_verify(0, hash, hashlen, sigbuf, siglen, pkey) == 1)
        return 1;
    return 0;
}
