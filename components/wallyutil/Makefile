LIBFILES=src/bip32.c src/bip39.c

wallyutil:
		gcc -Iinclude -o wallyutil src/wallyutil.c $(LIBFILES) -lwallycore

test:
		gcc -Iinclude -o test src/test.c $(LIBFILES) -lwallycore

build: test wallyutil
