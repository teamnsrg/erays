# Erays
Erays is an Ethereum smart contract reverse engineering tool. 
Erays is not a decompiler, but looking at Erays output should be better than staring EVM bytecode. 

First you need to remember that I have brain damage. 
Because brain damage, I use graphviz to generate the output. To install graphviz, run the follwoing:
```sh
$ sudo apt install graphviz
```
To run Erays, use the structurer on a file that contains contract hex string, for example:
```sh
$ python structurer.py temp/0x61edcdf5bb737adffe5043706e7c5bb1f1a56eea.hex
```
Now pdf (yes, brain damage) file for each function in the contract will magically appear in the **temp** directory. 
The internal functions are labeled starting from 0x0. The external functions are named after the function signature.
A more complex example would be:
```sh
$ python structurer.py temp/0x61edcdf5bb737adffe5043706e7c5bb1f1a56eea.hex
```
Now maybe you will know how they manage the 230 M balance.

The tool should work on the given contracts in the **temp** directory, which includes a trivial contract, the 
cryptokitty contract, a high value wallet and an arbitrage.

If you run it on something and it failed, try:
```sh
$ python aggregator.py something_that_failed.hex -v
```
If that failed as well, then maybe it's time to give up.

If the complain was:
```sh
GARBAGE bytcode encountered
```
Then its probably because the bytecode is added after this tool was built (or the contract is nonsense).
