/*
 * PESC - Pseudorandom Encryption with Shuffling and Coding
 * Copyright (C) 2016 Mateusz Muszyński
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * Compile: gcc -O3 std=c99 -o pesc pesc.c
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#ifdef RAND_MAX
	#undef RAND_MAX
#endif

#define RAND_MAX 65534

uint32_t seed = 0xF1F2F3F4;

// Park-Miller 31bit pseudorandom number generator
// http://www.firstpr.com.au/dsp/rand31/p1192-park.pdf
uint32_t random()
{
	if(seed == 0) seed = 0F1F2F3F4;
	uint32_t v = 16807 * (seed % 127773) - 2836 * (seed / 127773);
	if (v < 0) v += 2147483647;
	return ((seed = v) % ((uint32_t)RAND_MAX + 1));
}

// Convert 8 hex chars from string to uint32
uint32_t HexToUInt32(char* str, int start)
{
	uint32_t v = 0;
	for (size_t i = 0; i < 8; i++)
	{
		char tmp = str[start + i];
		#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			if      (tmp >= 'A' && tmp <= 'F') v += (tmp - 'A' + 0xA) << ((7 - i) * 4);
			else if (tmp >= 'a' && tmp <= 'f') v += (tmp - 'a' + 0xA) << ((7 - i) * 4);
			else if (tmp >= '0' && tmp <= '9') v += (tmp - '0')       << ((7 - i) * 4);
		#else
			if      (tmp >= 'A' && tmp <= 'F') v += (tmp - 'A' + 0xA) << (i * 4);
			else if (tmp >= 'a' && tmp <= 'f') v += (tmp - 'a' + 0xA) << (i * 4);
			else if (tmp >= '0' && tmp <= '9') v += (tmp - '0')       << (i * 4);
		#endif
		else
		{
			fputs("Unsupported character in key\n", stderr);
			exit(EXIT_FAILURE);
		}
	}
	return v;
}

// Generate exchange table for (De)Shuffling
size_t* GenExchangeTable(size_t len)
{
	size_t* exTable = malloc((len - 1) * sizeof(size_t));
	for (size_t i = len - 1; i > 0; i--)
		exTable[len - 1 - i] = random() % (i + 1);
	return exTable;
}

// Fisher–Yates shuffle
void Shuffle(char* data, size_t len)
{
	size_t* exTable = GenExchangeTable(len);
	for (size_t i = len - 1; i > 0; i--)
	{
		size_t n = exTable[len - 1 - i];
		char tmp = data[i];
		data[i]  = data[n];
		data[n]  = tmp;
	}
	free(exTable);
}

void DeShuffle(char* data, size_t len)
{
	size_t* exTable = GenExchangeTable(len);
	for (size_t i = 1; i < len; i++)
	{
		size_t n = exTable[len - i - 1];
		char tmp = data[i];
		data[i]  = data[n];
		data[n]  = tmp;
	}
	free(exTable);
}

// Simple text coding with PRNG
void Code(char* data, size_t len)
{
	for (size_t i = 0; i < len; i++)
		data[i] += (char)(random()%255);
}

void DeCode(char* data, size_t len)
{
	for (size_t i = 0; i < len; i++)
		data[i] -= (char)(random()%255);
}

// Encrypt text
void Encrypt(char* data, size_t len, uint32_t* keys, size_t kn)
{
	for (size_t i = 0; i < kn; i++)
	{
		seed = keys[i];
		Shuffle(data, len);
		seed = keys[kn - 1 - i];
		Code(data, len);
	}
}

void Decrypt(char* data, size_t len, uint32_t* keys, size_t kn)
{
	for (size_t i = kn; i--;)
	{
		seed = keys[kn - 1 - i];
		DeCode(data, len);
		seed = keys[i];
		DeShuffle(data, len);
	}
}

#ifdef TEST
int main(int argc, char* argv[])
{
	char* org = "Hello from Encryption Hell!";
	char* enc = strdup(org);

	uint32_t* keys = malloc(4 * sizeof(uint32_t));
	keys[0] = 0xFF123456;
	keys[1] = 0x12345678;
	keys[2] = 0xABCDEFED;
	keys[3] = 0x09876543;

	Encrypt(enc, strlen(enc), keys, 4);
	Decrypt(enc, strlen(enc), keys, 4);
	
	free(keys);
	
	if(strcmp(org, enc) == 0)
	{
		free(enc);
		return EXIT_SUCCESS;
	}
	free(enc);
	return EXIT_FAILURE;
}

#else

int main(int argc, char* argv[])
{
	int d = 0; // Decrypt flag
	if (argc == 3 && strcmp(argv[1], "-d")==0) d = 1;
	if ((argc != 2 && d == 0) || strlen(argv[1 + d])%8 != 0)
	{
		fputs("Usage: pesc [-d] key\n", stderr);
		fputs("Program read stdin until EOF and encypt/decrypt data into stdout.\n\n", stderr);
		fputs("    -d  : decrypt\n", stderr);
		fputs("    key : 32/64/128/256/... bit key in hex e.g. 1F2A3E74\n", stderr);
		return EXIT_FAILURE;
	}

	// split key into few 32bit subkeys
	size_t    kn   = strlen(argv[1 + d]) / 8;
	uint32_t* keys = malloc(kn * sizeof(uint32_t));
	for (size_t i = 0; i < kn; i++)
		keys[i] = HexToUInt32(argv[1 + d], i * 8);

	// read stdin into data buffer
	char*   data      = malloc(1000 * sizeof(char));
	size_t  allocSize = 1000;
	size_t  len       = 0;
	uint32_t c;
	while((c = getc(stdin)) != EOF)
	{
		data[len++] = (char)c;
		if(allocSize == len+1)
		{
			allocSize *= 2;
			data = realloc(data, allocSize * sizeof(char));
		}
	}

	// perform crypting job
	if(d) Decrypt(data, len, keys, kn);
	else  Encrypt(data, len, keys, kn);

	//print result to stdout
	for(size_t i = 0; i < len; i++)
		putchar(data[i]);

	//clear before exit
	free(keys);
	free(data);
	
	return EXIT_SUCCESS;
}
#endif
