/***************************
 * Recursive output for string
 * 	Copyright: https://github.com/hiyouthinker @2018
 *
****************************/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static int recursion(char *s)
{
	if (!*s)
		return 0;
	printf("%c", *s);
	recursion(s+1);
	return 0;
}

static int recursion_reverse(char *s)
{
	if (!*s)
		return 0;
	recursion_reverse(s+1);
	printf("%c", *s);
	return 0;
}

int main(int argc, char *argv[])
{
	char str[1024];

	memset(str, 0, sizeof(str));
	printf("Please input:\n");
	scanf("%s", str);

	recursion(str);
	printf("\n");
	recursion_reverse(str);
	printf("\n");
	return 0;
}
