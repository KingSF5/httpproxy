#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sm4.h"


static const uint8_t SM4_S[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2,
    0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4,
    0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA,
    0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2,
    0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B,
    0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2,
    0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30,
    0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45,
    0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41,
    0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A,
    0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E,
    0xD7, 0xCB, 0x39, 0x48
};

int sm4_set_key(const uint8_t *key , sm4_ctx * const ctx) {
    static const uint32_t FK[4] =
        { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

    static const uint32_t CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    };

    uint32_t K[4];
    K[0] = load_uint32_be(key, 0) ^ FK[0];
    K[1] = load_uint32_be(key, 1) ^ FK[1];
    K[2] = load_uint32_be(key, 2) ^ FK[2];
    K[3] = load_uint32_be(key, 3) ^ FK[3];

    for(int i=0;i<SM4_KEY_SCHEDULE;i++) {
	    uint32_t X = K[(i+1) %4] ^ K[(i+2) %4] ^ K[(i+3) %4] ^ CK[i];
	    uint32_t t = 0;

	    t |= (uint32_t)(SM4_S[(uint8_t) (X>>24)]) << 24;
	    t |= (uint32_t)(SM4_S[(uint8_t) (X>>16)]) << 16;
	    t |= (uint32_t)(SM4_S[(uint8_t) (X>>8)]) << 8;
	    t |= (uint32_t)SM4_S[(uint8_t) X];
	    t = t ^ ROT32L(t, 13) ^ ROT32L(t, 23);
	    K[i %4] = K[i % 4] ^ t;
	    ctx->rk[i] = K[i %4];
    }
    return 1;
    
}

void SM4_F(uint32_t * const blks, const uint32_t *rkg) {
	blks[0] ^= SM4_T(blks[1] ^ blks[2] ^ blks[3] ^ rkg[0]);
	blks[1] ^= SM4_T(blks[2] ^ blks[3] ^ blks[0] ^ rkg[1]);
	blks[2] ^= SM4_T(blks[3] ^ blks[0] ^ blks[1] ^ rkg[2]);
	blks[3] ^= SM4_T(blks[0] ^ blks[1] ^ blks[2] ^ rkg[3]);

}

uint32_t SM4_T(uint32_t X) {
	uint32_t t = 0;
	t |= ((uint32_t)SM4_S[(uint8_t)(X>>24)]) << 24;
	t |= ((uint32_t)SM4_S[(uint8_t)(X>>16)]) << 16;
	t |= ((uint32_t)SM4_S[(uint8_t)(X>>8)]) << 8;
	t |= ((uint32_t)SM4_S[(uint8_t)(X)]);
	t ^= ROT32L(t, 2) ^ ROT32L(t, 10) ^ ROT32L(t, 18) ^ ROT32L(t, 24);
	return t;

}

uint32_t load_uint32_be(const uint8_t *b, int n) {
	return ( ((uint32_t)b[n*4] << 24) |
		 ((uint32_t)b[n*4+1] << 16) |
		 ((uint32_t)b[n*4+2] << 8) |
		 ((uint32_t)b[n*4+3]));
}

void store_uint32_be(uint32_t n, uint8_t * const b) {
	b[0] = (uint8_t)(n>>24);
	b[1] = (uint8_t)(n>>16);
	b[2] = (uint8_t)(n>>8);
	b[3] = (uint8_t)(n);
}

void sm4_encrypt_single_block(const uint8_t *in, uint8_t *out, const sm4_ctx *ctx) {
	uint32_t blks[4];
	blks[0] = load_uint32_be(in, 0);
	blks[1] = load_uint32_be(in, 1);
	blks[2] = load_uint32_be(in, 2);
	blks[3] = load_uint32_be(in, 3);

	for (int i=0;i<SM4_KEY_SCHEDULE>>2;i++) {
		SM4_F(blks, &ctx->rk[i*4]);
	}
	store_uint32_be(blks[3], out);
	store_uint32_be(blks[2], out+4);
	store_uint32_be(blks[1], out+8);
	store_uint32_be(blks[0], out+12);
}

void sm4_decrypt_single_block(const uint8_t *in, uint8_t *out, const sm4_ctx * ctx) {
	uint32_t blks[4];
	uint32_t decrypt_key[SM4_KEY_SCHEDULE];
	for(int i=0;i<SM4_KEY_SCHEDULE;i++) {
		decrypt_key[i] = ctx->rk[SM4_KEY_SCHEDULE-i-1];
	}
	blks[0] = load_uint32_be(in, 0);
	blks[1] = load_uint32_be(in, 1);
	blks[2] = load_uint32_be(in, 2);
	blks[3] = load_uint32_be(in, 3);

	for (int i=0;i<SM4_KEY_SCHEDULE>>2;i++) {
		SM4_F(blks, &decrypt_key[i*4]);
	}
	store_uint32_be(blks[3], out);
	store_uint32_be(blks[2], out+4);
	store_uint32_be(blks[1], out+8);
	store_uint32_be(blks[0], out+12);

}

void xor_blk(uint8_t *a, uint8_t *b) {
	uint32_t A[4], B[4];
	A[0] = load_uint32_be(a, 0);
	A[1] = load_uint32_be(a, 1);
	A[2] = load_uint32_be(a, 2);
	A[3] = load_uint32_be(a, 3);

	B[0] = load_uint32_be(b, 0);
	B[1] = load_uint32_be(b, 1);
	B[2] = load_uint32_be(b, 2);
	B[3] = load_uint32_be(b, 3);

	A[0] ^= B[0];
	A[1] ^= B[1];
	A[2] ^= B[2];
	A[3] ^= B[3];

	store_uint32_be(A[0], a);
	store_uint32_be(A[1], a+4);
	store_uint32_be(A[2], a+8);
	store_uint32_be(A[3], a+12);
}

void padding(const uint8_t *in, uint8_t *out)
{
    int len,padlen;
    len = strlen((char*)in);
    padlen = SM4_BLOCK_SIZE-len%SM4_BLOCK_SIZE;
    strncpy((char *)out, (char *)in, len);
    for (int i=0; i<padlen; i++)
    {
        strncat((char *)(out+len),(char *)&padlen, 1);
    }
}


void unpadding(const uint8_t *in, uint8_t *out)
{
    strncpy((char *)out, (char *)in, strlen((char *)in)-in[strlen((char *)in)-1] );
    
}

void sm4_encrypt(const uint8_t *in, uint8_t *out, const sm4_ctx *ctx)
{
    uint8_t* padded=NULL;
    uint8_t tmp[SM4_BLOCK_SIZE*2];
    if (strlen((char *)in) % SM4_BLOCK_SIZE != 0)
        padded = (uint8_t*) malloc( strlen((char *)in+16));
        padding(in, padded);
    for (int i=0; i< strlen((char *)padded-1); i+=SM4_BLOCK_SIZE)
    {
        sm4_encrypt_single_block(in+i, tmp, ctx);
        strncat((char *)(out+i), (char *)tmp, SM4_BLOCK_SIZE);
    }
    
    free(padded);
    return;
}

void sm4_decrypt(const uint8_t *in, uint8_t *out, const sm4_ctx *ctx)
{
    uint8_t* padded;
    uint8_t tmp[SM4_BLOCK_SIZE*2];
    padded = (uint8_t*) malloc( strlen((char *)in+16));
    for (int i=0; i< strlen((char *)in); i+=SM4_BLOCK_SIZE)
    {
        sm4_decrypt_single_block(in+i, tmp, ctx);
        strncat((char *)(padded+i), (char *)tmp, SM4_BLOCK_SIZE);
    }
    
    unpadding(padded, out);
    free(padded);
    return;
}
