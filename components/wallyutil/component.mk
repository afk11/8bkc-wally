COMPONENT_OBJS := src/bip39.o src/bip32.o
COMPONENT_SRCDIRS := src
COMPONENT_OWNCLEANTARGET := true
COMPONENT_ADD_INCLUDEDIRS += include

clean:
	find ${COMPONENT_BUILD_DIR} -name "*.a" -type f -delete ; find . -name "*.o" -type f -delete > /dev/null 2>&1 ; \
        cd $(COMPONENT_PATH) ; \
        ./tools/cleanup.sh > /dev/null 2>&1

