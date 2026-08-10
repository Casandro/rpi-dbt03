#!/bin/bash
set -e
cd "$(dirname "$0")"
gcc -Wall -Werror -o test_btx_layer2 test_btx_layer2.c
./test_btx_layer2
