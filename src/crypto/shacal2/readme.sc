This archive contains Pascal/Delphi sources for the SHACAL-2 cipher.

The 256-bit block cipher SHACAL-2 is based on the compression function
of SHA256. It supports keys sizes from 128 to 512 bits. SHACAL-2 is
designed by Helena Handschuh and David Naccache and is the only
recommended 256-bit block cipher of the NESSIE portfolio.

There is code for a DLL and the following modes of operation are
supported: CBC, CFB, CTR, ECB, OFB. All modes allow plain and cipher
text lengths that need not be multiples of the block length (for ECB and
CBC cipher text stealing is used for the short block). CTR mode can use
4 built-in incrementing functions or a user supplied one, and provides
functions for random access reads.

All modes support a reset function that re-initializes the chaining
variables without the (time consuming) recalculation of the round keys.

Last changes (Nov. 2017)
- Adjustments for FPC/ARM and Delphi Tokyo
