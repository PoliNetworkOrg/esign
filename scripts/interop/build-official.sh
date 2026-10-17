#!/usr/bin/env bash
# Builds the official CIE middleware's PKCS#11 module (italia/cie-middleware-linux) from source, without Eclipse:
# first the signing SDK with its CMake file, then every C++ file of cie-pkcs11 except the bundled Crypto++ headers,
# linked with the flags of the project's .cproject. Usage: build-official.sh <source dir> <output .so>
#
# Everything is compiled without optimization, like the Eclipse "Debug" configuration the official README builds:
# the code relies on undefined behaviour that optimizing compilers turn into crashes (for example
# CSession::GetNewSessionID has no return statement). No source file is modified.
set -euo pipefail
src=$1
out=$2
cd "$src"

# The SDK's CSP/ATR.cpp includes ../LOGGER/Logger.h, which only cie-pkcs11 has: the extra include directory makes
# that path resolve. Newer GCC no longer includes <cstdint> transitively.
flags="-O0 -g -w -fpermissive -include cstdint -I$PWD/cie-pkcs11/PKCS11"
cmake -S cie_sign_sdk -B cie_sign_sdk/build -DCMAKE_CXX_FLAGS="$flags" -DCMAKE_C_FLAGS="-O0 -w" >/dev/null
cmake --build cie_sign_sdk/build -j"$(nproc)" >/dev/null
cmake --install cie_sign_sdk/build >/dev/null

mkdir -p obj
mapfile -t files < <(find cie-pkcs11 -name '*.cpp' -not -path '*/Cryptopp/*' | sort)
printf '%s\n' "${files[@]}" | xargs -P"$(nproc)" -I{} sh -c '
  o=obj/$(echo "{}" | tr / _ | sed "s/\.cpp$/.o/")
  g++ -std=gnu++14 -fPIC -O0 -g -w -fpermissive -include cstdint -include cstring -D__STDC_LIB_EXT1__ \
    -Icie_sign_sdk/Dependencies/openssl/include -I/usr/include/PCSC -Icie-pkcs11 -Icie-pkcs11/LOGGER -Icie-pkcs11/Util -Icie-pkcs11/PKCS11 -Icie-pkcs11/Sign \
    -c "{}" -o "$o"'

deps=cie_sign_sdk/Dependencies
g++ -shared -o "$out" obj/*.o \
  -Wl,--allow-multiple-definition -Wl,--undefined=EVP_idea_cbc -Wl,--undefined=TLS_client_method \
  -Wl,--undefined=curl_global_init -Wl,--undefined=png_get_valid -Wl,--undefined=FcInitLoadConfigAndFonts \
  -Lcie-pkcs11 -Lcie-pkcs11/Sign -L$deps/zlib -L$deps/openssl -L$deps/libiconv -L$deps/libpng -L$deps/bzip2 \
  -L$deps/fontconfig -L$deps/freetype -L$deps/libcurl -L$deps/libxml2 -L$deps/podofo \
  -Wl,--start-group -lcie_sign_sdk -lpodofo -lcryptopp -lcurl -lssl -lcrypto -lfontconfig -lfreetype -lpng16 \
  -lxml2 -liconv -lcharset -lz -lbz2 -Wl,--end-group -lpcsclite -lpthread -ldl
echo "built $out"
