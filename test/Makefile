PYTHON=python
CC=gcc

tests_run: tests
	$(PYTHON) ./tests.py

tests: test test_no_simd

test: test.c
	$(CC) -O0 -march=native -Wall -Wextra -ggdb -o test.exe test.c

test_no_simd: test.c
	$(CC) -O0 -DSHA_NO_SIMD -march=native -Wall -Wextra -ggdb -o test_no_simd.exe test.c

flags:
	$(CC) -march=native -dM -E empty.c