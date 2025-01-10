#!/bin/bash
cd /usr/src/myapp
git clone --branch 3.6.2 https://github.com/Microsoft/SEAL.git
cd /usr/src/myapp/SEAL
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=~/git/SEAL/native/Release -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build