// SPDX-License-Identifier: GPL-2.0
// Author: Harry Chong
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#define SYS_BITMERGE 442 // syscall number

void bitmerge(long high_bits, long low_bits)
{
	printf("---------\n");
	printf("Running: SYS_BITMERGE\n");
	printf("High Bits: %lx\n", high_bits);
	printf("Low Bits: %lx\n", low_bits);

	long long ret = syscall(SYS_BITMERGE, low_bits, high_bits);

	if (ret < 0)
		printf("Error: MSB is set. Invalid value was passed\n");
	else
		printf("Success! Merged Value: %llx\n", ret);
}

int main(void)
{
	// usage: bitmerge(high_bits, low_bits)
	printf("VALID TEST CASES (MSB not set):\n");
	bitmerge(0x00000000, 0x00000000);
	bitmerge(0x0FFFFFFF, 0xFFFFFFFF);
	bitmerge(0x0F0F0F0F, 0x0F0F0F0F);

	printf("\n-----------------------------------\n\n");

	printf("INVALID TEST CASES (MSB set):\n");
	bitmerge(0xF0000000, 0x00000000);
	bitmerge(0xFFFFFFFF, 0xFFFFFFFF);
	bitmerge(0xF0F0F0F0, 0xF0F0F0F0);
}
