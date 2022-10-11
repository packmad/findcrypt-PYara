# findcrypt-PYara

While analyzing a program, quite often we want to know if it uses any crypto algorithm. 
The idea behind this project is pretty simple: 
since almost all crypto algorithms use specific APIs, magic constants, strings, alphabets, etc. we will just look for 
these byte patterns in the file. 

*findcrypt* is a well known plugin available also for
  + [Ghidra](https://github.com/TorgoTorgo/ghidra-findcrypt)
  + [Ida PRO](https://github.com/polymorf/findcrypt-yara)

However, for performance and dependencies reasons it can also be implemented with 
[Yara](https://virustotal.github.io/yara/) rules.
This python script that wraps [this](https://github.com/Yara-Rules/rules/blob/master/crypto/crypto_signatures.yar) 
ruleset which can help us in finding crypto stuff in programs.


### Dependencies
```shell
pip3 install -r requirements.txt
```