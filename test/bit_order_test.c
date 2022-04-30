/*
 * BigBro @ 2022
 */

#include <unistd.h>
#include <stdio.h>

struct bit_order_st {
	unsigned char a: 2,
				b: 3,
				c: 3;
};

int main(int argc, char *argv[])
{
	unsigned char ch = 0x71;
	struct bit_order_st *p = (struct bit_order_st *)&ch;

	printf("8 bits: 0x%02x\n", ch);
	printf("2 bits - a: %u\n", p->a);
	printf("3 bits - b: %u\n", p->b);
	printf("3 bits - c: %u\n", p->c);

	return 0;
}
