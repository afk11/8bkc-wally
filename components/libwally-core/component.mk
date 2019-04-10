COMPONENT_OWNBUILDTARGET := true
COMPONENT_OWNCLEANTARGET := true
COMPONENT_ADD_INCLUDEDIRS += src/secp256k1/include

build:
	cd $(COMPONENT_PATH) && \
        ./tools/autogen.sh && export CFLAGS="-Wno-maybe-uninitialized -fno-stack-protector ${CFLAGS}" && \
        ./configure --enable-elements --enable-tests=no --enable-static=no --enable-shared=no --with-asm=no --enable-lto=no --disable-swig-java --disable-js-wrappers --disable-swig-python --disable-dependency-tracking --host=xtensa-esp32-elf --enable-ecmult-static-precomputation && \
        $(MAKE) -o configure && \
        $(AR) cru $(COMPONENT_BUILD_DIR)/$(COMPONENT_LIBRARY) src/secp256k1/src/libsecp256k1_la-secp256k1.o src/*.o src/ccan/ccan/crypto/sha256/libwallycore_la-sha256.o src/ccan/ccan/crypto/sha512/libwallycore_la-sha512.o src/ccan/ccan/crypto/ripemd160/libwallycore_la-ripemd160.o src/ccan/ccan/str/hex/libwallycore_la-hex.o src/libwallycore_la-hex.o

clean:
	find ${COMPONENT_BUILD_DIR} -name "*.a" -type f -delete ; find . -name "*.o" -type f -delete > /dev/null 2>&1 ; \
        cd $(COMPONENT_PATH) ; \
        ./tools/cleanup.sh > /dev/null 2>&1

