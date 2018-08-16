#!/usr/bin/env bash
solc temp/temp.sol --bin-runtime | tail -1 > temp/temp.hex
