

ARGON2_EXPORTED_FUNCTIONS = '[ \
		"_argon2_hash", \
		"_argon2_verify", \
		"_free", \
		"_malloc" \
	]'

EXPORTED_RUNTIME_METHODS = '[ \
		"stringToUTF8", \
		"UTF8ToString" \
	]'

CPPFLAGS = -I$(INCLUDE_DIR)
CFLAGS = -O3
LDFLAGS = -O3

INCLUDE_DIR = ../phc-winner-argon2/include
SOURCE_DIR = ../phc-winner-argon2/src
SOURCE_FILES = $(SOURCE_DIR)/argon2.c $(SOURCE_DIR)/core.c $(SOURCE_DIR)/ref.c $(SOURCE_DIR)/thread.c $(SOURCE_DIR)/encoding.c $(SOURCE_DIR)/blake2/blake2b.c
TARGET_DIR = ./tmp
TARGET_LLVM = $(TARGET_DIR)/argon2.lo
TARGET_JS = src/argon2wasm.js
WASM_POST_JS = src/argon2wasm.post.js
WASM_FLAGS = -s WASM=1 -s ALLOW_MEMORY_GROWTH=1 -s WASM_ASYNC_COMPILATION=0 -s MODULARIZE=1




${TARGET_JS}:
	mkdir -p $(TARGET_DIR)
	emcc ${CPPFLAGS} ${CFLAGS} -r ${SOURCE_FILES} -o ${TARGET_LLVM}
	emcc ${LDFLAGS} $(TARGET_LLVM) -o $@ ${WASM_FLAGS} \
		-s EXPORTED_FUNCTIONS=${ARGON2_EXPORTED_FUNCTIONS} \
		-s EXPORTED_RUNTIME_METHODS=${EXPORTED_RUNTIME_METHODS} \
		--post-js ${WASM_POST_JS}
clean:
	rm -rf ${TARGET_DIR}
	rm -f ${TARGET_JS}
