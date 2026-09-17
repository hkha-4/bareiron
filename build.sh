#!/usr/bin/env bash

if [ ! -f "include/registries.h" ]; then
  echo "Error: 'include/registries.h' is missing."
  echo "Please follow the 'Compilation' section of the README to generate it."
  exit 1
fi

case "$OSTYPE" in
  msys*|cygwin*|win32*) exe=".exe" ;;
  *) exe="" ;;
esac
windows_linker=""
unameOut="$(uname -s)"
case "$unameOut" in
  MINGW64_NT*) windows_linker="-static -lws2_32 -pthread" ;;
esac
compiler="gcc"
for arg in "$@"; do
  case $arg in
    --9x)
      if [[ "$unameOut" == MINGW64_NT* ]]; then
        compiler="/opt/bin/i686-w64-mingw32-gcc"
        windows_linker="$windows_linker -Wl,--subsystem,console:4"
      else
        echo "Error: Compiling for Windows 9x is only supported when running under the MinGW64 shell."
        exit 1
      fi
      ;;
  esac
done

rm -f "bareiron$exe"
$compiler src/*.c -O2 -Iinclude -o "bareiron$exe" $windows_linker \
  -Wl,--wrap=cs_loginStart -Wl,--wrap=handlePacket
"./bareiron$exe"
