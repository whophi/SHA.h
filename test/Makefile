tests: test test_no_simd

test: test.c
	gcc -O0 -march=native -Wall -ggdb -o test.exe test.c

test_no_simd: test.c
	gcc -O0 -DSHA_NO_SIMD -march=native -Wall -ggdb -o test_no_simd.exe test.c

flags:
	gcc -march=native -dM -E empty.c