gcc -Wall -Wextra -c -o f0.o f0.c -ggdb
gcc -Wall -Wextra -c -o f1.o f1.c -ggdb
gcc -static -o test f0.o f1.o
