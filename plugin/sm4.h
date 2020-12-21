#ifndef _sm4_H_
#define _sm4_H_
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define u8 unsigned char
#define u32 unsigned long

void four_uCh2uLong(u8 *in, u32 *out);
void uLong2four_uCh(u32 in, u8 *out);
unsigned long move(u32 data, int length);
unsigned long func_key(u32 input);
unsigned long func_data(u32 input);
void print_hex(u8 *data, int len);
void encode_fun(int len, u8 *key, u8 *input, u8 *output);
void decode_fun(int len, u8 *key, u8 *input, u8 *output);


#endif
