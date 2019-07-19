This archive contains Pascal/Delphi sources for the SkipJack cipher.

SkipJack is a compact 64-bit block cipher with 80-bit keys. It was
designed by the NSA as an unbalanced Feistel network with 32 rounds; in
1998 it was declassified and a specification was published by NIST (the
specification was clarified in 2002).

There is code for a DLL and the following modes of operation are
supported: CBC, CFB64, CTR, ECB, OFB. All modes allow plain and cipher
text lengths that need not be multiples of the block length (for ECB and
CBC cipher text stealing is used for the short block). CTR mode can use
4 built-in incrementing functions or a user supplied one, and provides
seek functions for random access reads.

All modes support a function that resets the chaining variables without
re-initializing the round keys.

Last changes (Nov. 2017)
- Adjustments for FPC/ARM and Delphi Tokyo
