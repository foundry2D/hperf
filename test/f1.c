#include <stdio.h>

static int static_loop()
{
	long a = 0;
	for (long i = 0; i < 30000000; i++) {
		a += i / 7;
	}

	return a;
}

int loop0();

int loop1()
{
	return static_loop();
}

int main()
{
	int r = 0;

	for (int t = 0; t < 10; t++) {
		int a = loop0();
		printf("\ta = %d\n", a);
		int b = loop1();
		printf("\tb = %d\n", b);

		r += a * b;
	}

	printf("r = %d\n", r);
	return 0;
}

