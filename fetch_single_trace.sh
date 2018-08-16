#!/usr/bin/env bash
num=`expr $2 + 1`
sed $num'q;d' /data3-original/evm_analysis_data/split_traces/$1 > temp/single.json
cat temp/single.json |  jq -r '.code' > temp/single.hex
