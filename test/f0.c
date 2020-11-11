static int static_loop()
{
	long a = 4;
	for (long i = 0; i < 30000000; i++) {
		a += i * 7;
	}

	return a;
}

int loop0()
{
	return static_loop();
}

