unit ANU_Base;

(*************************************************************************

 DESCRIPTION   :  Anubis (tweaked) basic routines

 REQUIREMENTS  :  TP5-7, D1-D7/D9-D12/D17-D18/D25S, FPC, VP, WDOSX

 EXTERNAL DATA :  ---

 MEMORY USAGE  :  6.5 KB static data

 DISPLAY MODE  :  ---

 REFERENCES    :  [1] http://www.larc.usp.br/~pbarreto/AnubisPage.html
                  [2] Tweaked version of Anubis, all zips from [1]
                      Docs: anubis-tweak.zip
                      C source: anubis-tweak-c.zip
                      Test vectors: anubis-tweak-test-vectors.zip
                  [3] The original definition of Anubis as submitted to NESSIE
                      http://www.larc.usp.br/~pbarreto/anubis.zip

 REMARKS       :  With BASM16 the tables T0 .. T5) and the used context should
                  be dword aligned to get optimal speed. If ANU_A4 is defined
                  a dummy 16 bit integer is placed before T0, use the function
                  ANU_T0Ofs to get the ofs(T0) mod 15.

                  Since only one round key array is used, it is essential that
                  the correct key setup is done for encryption and decryption.
                  The block modes units check for correct setup and return
                  error codes. The procedures ANU_Encrypt and ANU_Decrypt
                  normally do no such checks! If the symbol debug is defined,
                  RTE 210 is generated if the check fails. So be careful if
                  you call these routines directly.


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.01     02.08.08  W.Ehrhardt  Initial BP7 ANU_Init/RKEnc
 0.02     02.08.08  we          core routine, D4+ compatible
 0.03     02.08.08  we          ANU_Init/RKDec, TP5-6 compatible
 0.04     03.08.08  we          Decrypt byte in context
 0.05     03.08.08  we          ANU_Init2, ANU_Init_Enc, ANU_Init_Dec
 0.06     05.08.08  we          Names analog to AES: ANU_Init_Encr, ANU_Init_Decr
 0.07     09.08.08  we          Crypt BIT16 with byte vectors: speed factor 7
 0.08     09.08.08  we          Init2/BIT16 with byte vector typecasts
 0.09     09.08.08  we          Init2/BIT16 kv: byte vector absolute kappa
 0.10     09.08.08  we          Byte size sbox SB for inverse key setup
 0.11     09.08.08  we          Unroll init/final RB loops in crypt
 0.12     11.08.08  we          Crypt with BASM16 (speed doubled for Pentium 4)
 0.13     11.08.08  we          ANU_T0Ofs for BASM16, cyrpt is 60 faster if ofs(T0)=0
 0.14     11.08.08  we          If ANU_A4 is defined a dummy integer is placed before T0
 0.15     12.08.08  we          BASM16: force inter/state in crypt to be dword
                                aligned when called from ANU_Encrypt/Decrypt
 0.16     14.08.08  we          Debug: Generate RTE 210 if wrong key setup detected
 0.17     14.08.08  we          Avoid FPC2.2.2 warning in ANU_T0Ofs: cardinal typecast $ifdef HAS_XTYPES
 0.18     16.08.08  we          Removed ANU_Reset
 0.19     24.11.08  we          Uses BTypes
 0.20     09.12.08  we          Updated URLs
 0.21     01.08.10  we          ANU_Err_CTR_SeekOffset, ANU_Err_Invalid_16Bit_Length
 0.23     22.07.12  we          64-bit compatibility
 0.24     25.12.12  we          {$J+} if needed
 0.25     19.11.17  we          RB for CPUARM
 **************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2008-2017 Wolfgang Ehrhardt

 This software is provided 'as-is', without any express or implied warranty.
 In no event will the authors be held liable for any damages arising from
 the use of this software.

 Permission is granted to anyone to use this software for any purpose,
 including commercial applications, and to alter it and redistribute it
 freely, subject to the following restrictions:

 1. The origin of this software must not be misrepresented; you must not
    claim that you wrote the original software. If you use this software in
    a product, an acknowledgment in the product documentation would be
    appreciated but is not required.

 2. Altered source versions must be plainly marked as such, and must not be
    misrepresented as being the original software.

 3. This notice may not be removed or altered from any source distribution.
----------------------------------------------------------------------------*)

{$i std.inc}


interface


const
  ANU_Err_Invalid_Key_Size       = -1;  {Key size in bits not 128, 192, or 256}
  ANU_Err_Invalid_Mode           = -2;  {Encr/Decr with Init for Decr/Encr}
  ANU_Err_Invalid_Length         = -3;  {No full block for cipher stealing}
  ANU_Err_Data_After_Short_Block = -4;  {Short block must be last}
  ANU_Err_MultipleIncProcs       = -5;  {More than one IncProc Setting}
  ANU_Err_NIL_Pointer            = -6;  {nil pointer to block with nonzero length}
  ANU_Err_EAX_Inv_Text_Length    = -7;  {More than 64K text length in EAX all-in-one for 16 Bit}
  ANU_Err_EAX_Inv_TAG_Length     = -8;  {EAX all-in-one tag length not 0..16}
  ANU_Err_EAX_Verify_Tag         = -9;  {EAX all-in-one tag does not compare}

  ANU_Err_CTR_SeekOffset         = -15; {Negative offset in ANU_CTR_Seek}
  ANU_Err_Invalid_16Bit_Length   = -20; {Pointer + Offset > $FFFF for 16 bit code}

type
  TANURndKey = packed array[0..18,0..3] of longint;  {Round key schedule}
  TANUBlock  = packed array[0..15]  of byte;         {128 bit block}
  PANUBlock  = ^TANUBlock;

type
  TANUIncProc = procedure(var CTR: TANUBlock);  {user supplied IncCTR proc}
                   {$ifdef DLL} stdcall; {$endif}
type
  TANUContext = packed record
                 IV      : TANUBlock;   {IV or CTR              }
                 buf     : TANUBlock;   {Work buffer            }
                 bLen    : word;        {Bytes used in buf      }
                 Rounds  : word;        {Number of rounds       }
                 KeyBits : word;        {Number of bits in key  }
                 Decrypt : byte;        {<>0 if decrypting key  }
                 Flag    : byte;        {Bit 1: Short block     }
                 IncProc : TANUIncProc; {Increment proc CTR-Mode}
                 RK      : TANURndKey;  {Encr/Decr round keys   }
               end;

const
  ANUBLKSIZE  = sizeof(TANUBlock);     {Anubis block size in bytes}

{$ifdef CONST}
function  ANU_Init2(const Key; KeyBits: word; var ctx: TANUContext; decr: byte): integer;
  {-Anubis context/round key initialization, Inverse key if decr<>0}
  {$ifdef DLL} stdcall; {$endif}

function  ANU_Init_Encr(const Key; KeyBits: word; var ctx: TANUContext): integer;
  {-Anubis context/round key initialization for encrytion}
  {$ifdef DLL} stdcall; {$endif}

function  ANU_Init_Decr(const Key; KeyBits: word; var ctx: TANUContext): integer;
  {-Anubis context/round key initialization for decr<ptionn}
  {$ifdef DLL} stdcall; {$endif}

procedure ANU_Encrypt(var ctx: TANUContext; const BI: TANUBlock; var BO: TANUBlock);
  {-encrypt one block (in ECB mode)}
  {$ifdef DLL} stdcall; {$endif}

procedure ANU_Decrypt(var ctx: TANUContext; const BI: TANUBlock; var BO: TANUBlock);
  {-decrypt one block (in ECB mode)}
  {$ifdef DLL} stdcall; {$endif}

procedure ANU_XorBlock(const B1, B2: TANUBlock; var B3: TANUBlock);
  {-xor two blocks, result in third}
  {$ifdef DLL} stdcall; {$endif}
{$else}
function  ANU_Init2(var Key; KeyBits: word; var ctx: TANUContext; decr: byte): integer;
  {-Anubis context/round key initialization, Inverse key if decr<>0}

function  ANU_Init_Encr(var Key; KeyBits: word; var ctx: TANUContext): integer;
  {-Anubis context/round key initialization for encrytion}

function  ANU_Init_Decr(var Key; KeyBits: word; var ctx: TANUContext): integer;
  {-Anubis context/round key initialization for decr<ptionn}

procedure ANU_Encrypt(var ctx: TANUContext; var BI: TANUBlock; var BO: TANUBlock);
  {-encrypt one block (in ECB mode)}

procedure ANU_Decrypt(var ctx: TANUContext; var BI: TANUBlock; var BO: TANUBlock);
  {-decrypt one block (in ECB mode)}

procedure ANU_XorBlock(var B1, B2: TANUBlock; var B3: TANUBlock);
  {-xor two blocks, result in third}
{$endif}

procedure ANU_SetFastInit(value: boolean);
  {-set FastInit variable}
  {$ifdef DLL} stdcall; {$endif}

function  ANU_GetFastInit: boolean;
  {-Returns FastInit variable}
  {$ifdef DLL} stdcall; {$endif}

function  ANU_T0Ofs: byte;
  {-Return offset of Table T0 mod 15, used to optimize BASM16 32 bit access}


implementation

uses
  BTypes;

type
  TXSBox = packed array[0..255] of longint; {Extended S-box}
  TWA4   = packed array[0..3] of longint;   {Block as array of longint}

{$ifdef StrictLong}
  {$warnings off}
  {$R-} {avoid D9+ errors!}
{$endif}

const
  {$ifdef BIT16}
    {$ifdef ANU_A4}
      dummy: integer = 0;     {dummy integer to dword align T0 and T1..T5}
    {$endif}
  {$endif}
  T0: TXSBox =
        ($ba69d2bb, $54a84de5, $2f5ebce2, $74e8cd25, $53a651f7, $d3bb6bd0, $d2b96fd6, $4d9a29b3,
         $50a05dfd, $ac458acf, $8d070e09, $bf63c6a5, $70e0dd3d, $52a455f1, $9a29527b, $4c982db5,
         $eac98f46, $d5b773c4, $97336655, $d1bf63dc, $3366ccaa, $51a259fb, $5bb671c7, $a651a2f3,
         $dea15ffe, $48903dad, $a84d9ad7, $992f5e71, $dbab4be0, $3264c8ac, $b773e695, $fce5d732,
         $e3dbab70, $9e214263, $913f7e41, $9b2b567d, $e2d9af76, $bb6bd6bd, $4182199b, $6edca579,
         $a557aef9, $cb8b0b80, $6bd6b167, $95376e59, $a15fbee1, $f3fbeb10, $b17ffe81, $0204080c,
         $cc851792, $c49537a2, $1d3a744e, $14285078, $c39b2bb0, $63c69157, $daa94fe6, $5dba69d3,
         $5fbe61df, $dca557f2, $7dfae913, $cd871394, $7ffee11f, $5ab475c1, $6cd8ad75, $5cb86dd5,
         $f7f3fb08, $264c98d4, $ffe3db38, $edc79354, $e8cd874a, $9d274e69, $6fdea17f, $8e010203,
         $19326456, $a05dbae7, $f0fde71a, $890f1e11, $0f1e3c22, $070e1c12, $af4386c5, $fbebcb20,
         $08102030, $152a547e, $0d1a342e, $04081018, $01020406, $64c88d45, $dfa35bf8, $76ecc529,
         $79f2f90b, $dda753f4, $3d7af48e, $162c5874, $3f7efc82, $376edcb2, $6ddaa973, $3870e090,
         $b96fdeb1, $73e6d137, $e9cf834c, $356ad4be, $55aa49e3, $71e2d93b, $7bf6f107, $8c050a0f,
         $72e4d531, $880d1a17, $f6f1ff0e, $2a54a8fc, $3e7cf884, $5ebc65d9, $274e9cd2, $468c0589,
         $0c183028, $65ca8943, $68d0bd6d, $61c2995b, $03060c0a, $c19f23bc, $57ae41ef, $d6b17fce,
         $d9af43ec, $58b07dcd, $d8ad47ea, $66cc8549, $d7b37bc8, $3a74e89c, $c88d078a, $3c78f088,
         $fae9cf26, $96316253, $a753a6f5, $982d5a77, $ecc59752, $b86ddab7, $c7933ba8, $ae4182c3,
         $69d2b96b, $4b9631a7, $ab4b96dd, $a94f9ed1, $67ce814f, $0a14283c, $478e018f, $f2f9ef16,
         $b577ee99, $224488cc, $e5d7b364, $eec19f5e, $be61c2a3, $2b56acfa, $811f3e21, $1224486c,
         $831b362d, $1b366c5a, $0e1c3824, $23468cca, $f5f7f304, $458a0983, $214284c6, $ce811f9e,
         $499239ab, $2c58b0e8, $f9efc32c, $e6d1bf6e, $b671e293, $2850a0f0, $172e5c72, $8219322b,
         $1a34685c, $8b0b161d, $fee1df3e, $8a09121b, $09122436, $c98f038c, $87132635, $4e9c25b9,
         $e1dfa37c, $2e5cb8e4, $e4d5b762, $e0dda77a, $ebcb8b40, $903d7a47, $a455aaff, $1e3c7844,
         $85172e39, $60c09d5d, $00000000, $254a94de, $f4f5f702, $f1ffe31c, $94356a5f, $0b162c3a,
         $e7d3bb68, $75eac923, $efc39b58, $3468d0b8, $3162c4a6, $d4b577c2, $d0bd67da, $86112233,
         $7efce519, $ad478ec9, $fde7d334, $2952a4f6, $3060c0a0, $3b76ec9a, $9f234665, $f8edc72a,
         $c6913fae, $13264c6a, $060c1814, $050a141e, $c59733a4, $11224466, $77eec12f, $7cf8ed15,
         $7af4f501, $78f0fd0d, $366cd8b4, $1c387048, $3972e496, $59b279cb, $18306050, $56ac45e9,
         $b37bf68d, $b07dfa87, $244890d8, $204080c0, $b279f28b, $9239724b, $a35bb6ed, $c09d27ba,
         $44880d85, $62c49551, $10204060, $b475ea9f, $84152a3f, $43861197, $933b764d, $c2992fb6,
         $4a9435a1, $bd67cea9, $8f030605, $2d5ab4ee, $bc65caaf, $9c254a6f, $6ad4b561, $40801d9d,
         $cf831b98, $a259b2eb, $801d3a27, $4f9e21bf, $1f3e7c42, $ca890f86, $aa4992db, $42841591);

  T1: TXSBox =
        ($69babbd2, $a854e54d, $5e2fe2bc, $e87425cd, $a653f751, $bbd3d06b, $b9d2d66f, $9a4db329,
         $a050fd5d, $45accf8a, $078d090e, $63bfa5c6, $e0703ddd, $a452f155, $299a7b52, $984cb52d,
         $c9ea468f, $b7d5c473, $33975566, $bfd1dc63, $6633aacc, $a251fb59, $b65bc771, $51a6f3a2,
         $a1defe5f, $9048ad3d, $4da8d79a, $2f99715e, $abdbe04b, $6432acc8, $73b795e6, $e5fc32d7,
         $dbe370ab, $219e6342, $3f91417e, $2b9b7d56, $d9e276af, $6bbbbdd6, $82419b19, $dc6e79a5,
         $57a5f9ae, $8bcb800b, $d66b67b1, $3795596e, $5fa1e1be, $fbf310eb, $7fb181fe, $04020c08,
         $85cc9217, $95c4a237, $3a1d4e74, $28147850, $9bc3b02b, $c6635791, $a9dae64f, $ba5dd369,
         $be5fdf61, $a5dcf257, $fa7d13e9, $87cd9413, $fe7f1fe1, $b45ac175, $d86c75ad, $b85cd56d,
         $f3f708fb, $4c26d498, $e3ff38db, $c7ed5493, $cde84a87, $279d694e, $de6f7fa1, $018e0302,
         $32195664, $5da0e7ba, $fdf01ae7, $0f89111e, $1e0f223c, $0e07121c, $43afc586, $ebfb20cb,
         $10083020, $2a157e54, $1a0d2e34, $08041810, $02010604, $c864458d, $a3dff85b, $ec7629c5,
         $f2790bf9, $a7ddf453, $7a3d8ef4, $2c167458, $7e3f82fc, $6e37b2dc, $da6d73a9, $703890e0,
         $6fb9b1de, $e67337d1, $cfe94c83, $6a35bed4, $aa55e349, $e2713bd9, $f67b07f1, $058c0f0a,
         $e47231d5, $0d88171a, $f1f60eff, $542afca8, $7c3e84f8, $bc5ed965, $4e27d29c, $8c468905,
         $180c2830, $ca654389, $d0686dbd, $c2615b99, $06030a0c, $9fc1bc23, $ae57ef41, $b1d6ce7f,
         $afd9ec43, $b058cd7d, $add8ea47, $cc664985, $b3d7c87b, $743a9ce8, $8dc88a07, $783c88f0,
         $e9fa26cf, $31965362, $53a7f5a6, $2d98775a, $c5ec5297, $6db8b7da, $93c7a83b, $41aec382,
         $d2696bb9, $964ba731, $4babdd96, $4fa9d19e, $ce674f81, $140a3c28, $8e478f01, $f9f216ef,
         $77b599ee, $4422cc88, $d7e564b3, $c1ee5e9f, $61bea3c2, $562bfaac, $1f81213e, $24126c48,
         $1b832d36, $361b5a6c, $1c0e2438, $4623ca8c, $f7f504f3, $8a458309, $4221c684, $81ce9e1f,
         $9249ab39, $582ce8b0, $eff92cc3, $d1e66ebf, $71b693e2, $5028f0a0, $2e17725c, $19822b32,
         $341a5c68, $0b8b1d16, $e1fe3edf, $098a1b12, $12093624, $8fc98c03, $13873526, $9c4eb925,
         $dfe17ca3, $5c2ee4b8, $d5e462b7, $dde07aa7, $cbeb408b, $3d90477a, $55a4ffaa, $3c1e4478,
         $1785392e, $c0605d9d, $00000000, $4a25de94, $f5f402f7, $fff11ce3, $35945f6a, $160b3a2c,
         $d3e768bb, $ea7523c9, $c3ef589b, $6834b8d0, $6231a6c4, $b5d4c277, $bdd0da67, $11863322,
         $fc7e19e5, $47adc98e, $e7fd34d3, $5229f6a4, $6030a0c0, $763b9aec, $239f6546, $edf82ac7,
         $91c6ae3f, $26136a4c, $0c061418, $0a051e14, $97c5a433, $22116644, $ee772fc1, $f87c15ed,
         $f47a01f5, $f0780dfd, $6c36b4d8, $381c4870, $723996e4, $b259cb79, $30185060, $ac56e945,
         $7bb38df6, $7db087fa, $4824d890, $4020c080, $79b28bf2, $39924b72, $5ba3edb6, $9dc0ba27,
         $8844850d, $c4625195, $20106040, $75b49fea, $15843f2a, $86439711, $3b934d76, $99c2b62f,
         $944aa135, $67bda9ce, $038f0506, $5a2deeb4, $65bcafca, $259c6f4a, $d46a61b5, $80409d1d,
         $83cf981b, $59a2ebb2, $1d80273a, $9e4fbf21, $3e1f427c, $89ca860f, $49aadb92, $84429115);

  T2: TXSBox =
        ($d2bbba69, $4de554a8, $bce22f5e, $cd2574e8, $51f753a6, $6bd0d3bb, $6fd6d2b9, $29b34d9a,
         $5dfd50a0, $8acfac45, $0e098d07, $c6a5bf63, $dd3d70e0, $55f152a4, $527b9a29, $2db54c98,
         $8f46eac9, $73c4d5b7, $66559733, $63dcd1bf, $ccaa3366, $59fb51a2, $71c75bb6, $a2f3a651,
         $5ffedea1, $3dad4890, $9ad7a84d, $5e71992f, $4be0dbab, $c8ac3264, $e695b773, $d732fce5,
         $ab70e3db, $42639e21, $7e41913f, $567d9b2b, $af76e2d9, $d6bdbb6b, $199b4182, $a5796edc,
         $aef9a557, $0b80cb8b, $b1676bd6, $6e599537, $bee1a15f, $eb10f3fb, $fe81b17f, $080c0204,
         $1792cc85, $37a2c495, $744e1d3a, $50781428, $2bb0c39b, $915763c6, $4fe6daa9, $69d35dba,
         $61df5fbe, $57f2dca5, $e9137dfa, $1394cd87, $e11f7ffe, $75c15ab4, $ad756cd8, $6dd55cb8,
         $fb08f7f3, $98d4264c, $db38ffe3, $9354edc7, $874ae8cd, $4e699d27, $a17f6fde, $02038e01,
         $64561932, $bae7a05d, $e71af0fd, $1e11890f, $3c220f1e, $1c12070e, $86c5af43, $cb20fbeb,
         $20300810, $547e152a, $342e0d1a, $10180408, $04060102, $8d4564c8, $5bf8dfa3, $c52976ec,
         $f90b79f2, $53f4dda7, $f48e3d7a, $5874162c, $fc823f7e, $dcb2376e, $a9736dda, $e0903870,
         $deb1b96f, $d13773e6, $834ce9cf, $d4be356a, $49e355aa, $d93b71e2, $f1077bf6, $0a0f8c05,
         $d53172e4, $1a17880d, $ff0ef6f1, $a8fc2a54, $f8843e7c, $65d95ebc, $9cd2274e, $0589468c,
         $30280c18, $894365ca, $bd6d68d0, $995b61c2, $0c0a0306, $23bcc19f, $41ef57ae, $7fced6b1,
         $43ecd9af, $7dcd58b0, $47ead8ad, $854966cc, $7bc8d7b3, $e89c3a74, $078ac88d, $f0883c78,
         $cf26fae9, $62539631, $a6f5a753, $5a77982d, $9752ecc5, $dab7b86d, $3ba8c793, $82c3ae41,
         $b96b69d2, $31a74b96, $96ddab4b, $9ed1a94f, $814f67ce, $283c0a14, $018f478e, $ef16f2f9,
         $ee99b577, $88cc2244, $b364e5d7, $9f5eeec1, $c2a3be61, $acfa2b56, $3e21811f, $486c1224,
         $362d831b, $6c5a1b36, $38240e1c, $8cca2346, $f304f5f7, $0983458a, $84c62142, $1f9ece81,
         $39ab4992, $b0e82c58, $c32cf9ef, $bf6ee6d1, $e293b671, $a0f02850, $5c72172e, $322b8219,
         $685c1a34, $161d8b0b, $df3efee1, $121b8a09, $24360912, $038cc98f, $26358713, $25b94e9c,
         $a37ce1df, $b8e42e5c, $b762e4d5, $a77ae0dd, $8b40ebcb, $7a47903d, $aaffa455, $78441e3c,
         $2e398517, $9d5d60c0, $00000000, $94de254a, $f702f4f5, $e31cf1ff, $6a5f9435, $2c3a0b16,
         $bb68e7d3, $c92375ea, $9b58efc3, $d0b83468, $c4a63162, $77c2d4b5, $67dad0bd, $22338611,
         $e5197efc, $8ec9ad47, $d334fde7, $a4f62952, $c0a03060, $ec9a3b76, $46659f23, $c72af8ed,
         $3faec691, $4c6a1326, $1814060c, $141e050a, $33a4c597, $44661122, $c12f77ee, $ed157cf8,
         $f5017af4, $fd0d78f0, $d8b4366c, $70481c38, $e4963972, $79cb59b2, $60501830, $45e956ac,
         $f68db37b, $fa87b07d, $90d82448, $80c02040, $f28bb279, $724b9239, $b6eda35b, $27bac09d,
         $0d854488, $955162c4, $40601020, $ea9fb475, $2a3f8415, $11974386, $764d933b, $2fb6c299,
         $35a14a94, $cea9bd67, $06058f03, $b4ee2d5a, $caafbc65, $4a6f9c25, $b5616ad4, $1d9d4080,
         $1b98cf83, $b2eba259, $3a27801d, $21bf4f9e, $7c421f3e, $0f86ca89, $92dbaa49, $15914284);

  T3: TXSBox =
        ($bbd269ba, $e54da854, $e2bc5e2f, $25cde874, $f751a653, $d06bbbd3, $d66fb9d2, $b3299a4d,
         $fd5da050, $cf8a45ac, $090e078d, $a5c663bf, $3ddde070, $f155a452, $7b52299a, $b52d984c,
         $468fc9ea, $c473b7d5, $55663397, $dc63bfd1, $aacc6633, $fb59a251, $c771b65b, $f3a251a6,
         $fe5fa1de, $ad3d9048, $d79a4da8, $715e2f99, $e04babdb, $acc86432, $95e673b7, $32d7e5fc,
         $70abdbe3, $6342219e, $417e3f91, $7d562b9b, $76afd9e2, $bdd66bbb, $9b198241, $79a5dc6e,
         $f9ae57a5, $800b8bcb, $67b1d66b, $596e3795, $e1be5fa1, $10ebfbf3, $81fe7fb1, $0c080402,
         $921785cc, $a23795c4, $4e743a1d, $78502814, $b02b9bc3, $5791c663, $e64fa9da, $d369ba5d,
         $df61be5f, $f257a5dc, $13e9fa7d, $941387cd, $1fe1fe7f, $c175b45a, $75add86c, $d56db85c,
         $08fbf3f7, $d4984c26, $38dbe3ff, $5493c7ed, $4a87cde8, $694e279d, $7fa1de6f, $0302018e,
         $56643219, $e7ba5da0, $1ae7fdf0, $111e0f89, $223c1e0f, $121c0e07, $c58643af, $20cbebfb,
         $30201008, $7e542a15, $2e341a0d, $18100804, $06040201, $458dc864, $f85ba3df, $29c5ec76,
         $0bf9f279, $f453a7dd, $8ef47a3d, $74582c16, $82fc7e3f, $b2dc6e37, $73a9da6d, $90e07038,
         $b1de6fb9, $37d1e673, $4c83cfe9, $bed46a35, $e349aa55, $3bd9e271, $07f1f67b, $0f0a058c,
         $31d5e472, $171a0d88, $0efff1f6, $fca8542a, $84f87c3e, $d965bc5e, $d29c4e27, $89058c46,
         $2830180c, $4389ca65, $6dbdd068, $5b99c261, $0a0c0603, $bc239fc1, $ef41ae57, $ce7fb1d6,
         $ec43afd9, $cd7db058, $ea47add8, $4985cc66, $c87bb3d7, $9ce8743a, $8a078dc8, $88f0783c,
         $26cfe9fa, $53623196, $f5a653a7, $775a2d98, $5297c5ec, $b7da6db8, $a83b93c7, $c38241ae,
         $6bb9d269, $a731964b, $dd964bab, $d19e4fa9, $4f81ce67, $3c28140a, $8f018e47, $16eff9f2,
         $99ee77b5, $cc884422, $64b3d7e5, $5e9fc1ee, $a3c261be, $faac562b, $213e1f81, $6c482412,
         $2d361b83, $5a6c361b, $24381c0e, $ca8c4623, $04f3f7f5, $83098a45, $c6844221, $9e1f81ce,
         $ab399249, $e8b0582c, $2cc3eff9, $6ebfd1e6, $93e271b6, $f0a05028, $725c2e17, $2b321982,
         $5c68341a, $1d160b8b, $3edfe1fe, $1b12098a, $36241209, $8c038fc9, $35261387, $b9259c4e,
         $7ca3dfe1, $e4b85c2e, $62b7d5e4, $7aa7dde0, $408bcbeb, $477a3d90, $ffaa55a4, $44783c1e,
         $392e1785, $5d9dc060, $00000000, $de944a25, $02f7f5f4, $1ce3fff1, $5f6a3594, $3a2c160b,
         $68bbd3e7, $23c9ea75, $589bc3ef, $b8d06834, $a6c46231, $c277b5d4, $da67bdd0, $33221186,
         $19e5fc7e, $c98e47ad, $34d3e7fd, $f6a45229, $a0c06030, $9aec763b, $6546239f, $2ac7edf8,
         $ae3f91c6, $6a4c2613, $14180c06, $1e140a05, $a43397c5, $66442211, $2fc1ee77, $15edf87c,
         $01f5f47a, $0dfdf078, $b4d86c36, $4870381c, $96e47239, $cb79b259, $50603018, $e945ac56,
         $8df67bb3, $87fa7db0, $d8904824, $c0804020, $8bf279b2, $4b723992, $edb65ba3, $ba279dc0,
         $850d8844, $5195c462, $60402010, $9fea75b4, $3f2a1584, $97118643, $4d763b93, $b62f99c2,
         $a135944a, $a9ce67bd, $0506038f, $eeb45a2d, $afca65bc, $6f4a259c, $61b5d46a, $9d1d8040,
         $981b83cf, $ebb259a2, $273a1d80, $bf219e4f, $427c3e1f, $860f89ca, $db9249aa, $91158442);

  T4: TXSBox =
        ($babababa, $54545454, $2f2f2f2f, $74747474, $53535353, $d3d3d3d3, $d2d2d2d2, $4d4d4d4d,
         $50505050, $acacacac, $8d8d8d8d, $bfbfbfbf, $70707070, $52525252, $9a9a9a9a, $4c4c4c4c,
         $eaeaeaea, $d5d5d5d5, $97979797, $d1d1d1d1, $33333333, $51515151, $5b5b5b5b, $a6a6a6a6,
         $dededede, $48484848, $a8a8a8a8, $99999999, $dbdbdbdb, $32323232, $b7b7b7b7, $fcfcfcfc,
         $e3e3e3e3, $9e9e9e9e, $91919191, $9b9b9b9b, $e2e2e2e2, $bbbbbbbb, $41414141, $6e6e6e6e,
         $a5a5a5a5, $cbcbcbcb, $6b6b6b6b, $95959595, $a1a1a1a1, $f3f3f3f3, $b1b1b1b1, $02020202,
         $cccccccc, $c4c4c4c4, $1d1d1d1d, $14141414, $c3c3c3c3, $63636363, $dadadada, $5d5d5d5d,
         $5f5f5f5f, $dcdcdcdc, $7d7d7d7d, $cdcdcdcd, $7f7f7f7f, $5a5a5a5a, $6c6c6c6c, $5c5c5c5c,
         $f7f7f7f7, $26262626, $ffffffff, $edededed, $e8e8e8e8, $9d9d9d9d, $6f6f6f6f, $8e8e8e8e,
         $19191919, $a0a0a0a0, $f0f0f0f0, $89898989, $0f0f0f0f, $07070707, $afafafaf, $fbfbfbfb,
         $08080808, $15151515, $0d0d0d0d, $04040404, $01010101, $64646464, $dfdfdfdf, $76767676,
         $79797979, $dddddddd, $3d3d3d3d, $16161616, $3f3f3f3f, $37373737, $6d6d6d6d, $38383838,
         $b9b9b9b9, $73737373, $e9e9e9e9, $35353535, $55555555, $71717171, $7b7b7b7b, $8c8c8c8c,
         $72727272, $88888888, $f6f6f6f6, $2a2a2a2a, $3e3e3e3e, $5e5e5e5e, $27272727, $46464646,
         $0c0c0c0c, $65656565, $68686868, $61616161, $03030303, $c1c1c1c1, $57575757, $d6d6d6d6,
         $d9d9d9d9, $58585858, $d8d8d8d8, $66666666, $d7d7d7d7, $3a3a3a3a, $c8c8c8c8, $3c3c3c3c,
         $fafafafa, $96969696, $a7a7a7a7, $98989898, $ecececec, $b8b8b8b8, $c7c7c7c7, $aeaeaeae,
         $69696969, $4b4b4b4b, $abababab, $a9a9a9a9, $67676767, $0a0a0a0a, $47474747, $f2f2f2f2,
         $b5b5b5b5, $22222222, $e5e5e5e5, $eeeeeeee, $bebebebe, $2b2b2b2b, $81818181, $12121212,
         $83838383, $1b1b1b1b, $0e0e0e0e, $23232323, $f5f5f5f5, $45454545, $21212121, $cececece,
         $49494949, $2c2c2c2c, $f9f9f9f9, $e6e6e6e6, $b6b6b6b6, $28282828, $17171717, $82828282,
         $1a1a1a1a, $8b8b8b8b, $fefefefe, $8a8a8a8a, $09090909, $c9c9c9c9, $87878787, $4e4e4e4e,
         $e1e1e1e1, $2e2e2e2e, $e4e4e4e4, $e0e0e0e0, $ebebebeb, $90909090, $a4a4a4a4, $1e1e1e1e,
         $85858585, $60606060, $00000000, $25252525, $f4f4f4f4, $f1f1f1f1, $94949494, $0b0b0b0b,
         $e7e7e7e7, $75757575, $efefefef, $34343434, $31313131, $d4d4d4d4, $d0d0d0d0, $86868686,
         $7e7e7e7e, $adadadad, $fdfdfdfd, $29292929, $30303030, $3b3b3b3b, $9f9f9f9f, $f8f8f8f8,
         $c6c6c6c6, $13131313, $06060606, $05050505, $c5c5c5c5, $11111111, $77777777, $7c7c7c7c,
         $7a7a7a7a, $78787878, $36363636, $1c1c1c1c, $39393939, $59595959, $18181818, $56565656,
         $b3b3b3b3, $b0b0b0b0, $24242424, $20202020, $b2b2b2b2, $92929292, $a3a3a3a3, $c0c0c0c0,
         $44444444, $62626262, $10101010, $b4b4b4b4, $84848484, $43434343, $93939393, $c2c2c2c2,
         $4a4a4a4a, $bdbdbdbd, $8f8f8f8f, $2d2d2d2d, $bcbcbcbc, $9c9c9c9c, $6a6a6a6a, $40404040,
         $cfcfcfcf, $a2a2a2a2, $80808080, $4f4f4f4f, $1f1f1f1f, $cacacaca, $aaaaaaaa, $42424242);

  T5: TXSBox =
        ($00000000, $01020608, $02040c10, $03060a18, $04081820, $050a1e28, $060c1430, $070e1238,
         $08103040, $09123648, $0a143c50, $0b163a58, $0c182860, $0d1a2e68, $0e1c2470, $0f1e2278,
         $10206080, $11226688, $12246c90, $13266a98, $142878a0, $152a7ea8, $162c74b0, $172e72b8,
         $183050c0, $193256c8, $1a345cd0, $1b365ad8, $1c3848e0, $1d3a4ee8, $1e3c44f0, $1f3e42f8,
         $2040c01d, $2142c615, $2244cc0d, $2346ca05, $2448d83d, $254ade35, $264cd42d, $274ed225,
         $2850f05d, $2952f655, $2a54fc4d, $2b56fa45, $2c58e87d, $2d5aee75, $2e5ce46d, $2f5ee265,
         $3060a09d, $3162a695, $3264ac8d, $3366aa85, $3468b8bd, $356abeb5, $366cb4ad, $376eb2a5,
         $387090dd, $397296d5, $3a749ccd, $3b769ac5, $3c7888fd, $3d7a8ef5, $3e7c84ed, $3f7e82e5,
         $40809d3a, $41829b32, $4284912a, $43869722, $4488851a, $458a8312, $468c890a, $478e8f02,
         $4890ad7a, $4992ab72, $4a94a16a, $4b96a762, $4c98b55a, $4d9ab352, $4e9cb94a, $4f9ebf42,
         $50a0fdba, $51a2fbb2, $52a4f1aa, $53a6f7a2, $54a8e59a, $55aae392, $56ace98a, $57aeef82,
         $58b0cdfa, $59b2cbf2, $5ab4c1ea, $5bb6c7e2, $5cb8d5da, $5dbad3d2, $5ebcd9ca, $5fbedfc2,
         $60c05d27, $61c25b2f, $62c45137, $63c6573f, $64c84507, $65ca430f, $66cc4917, $67ce4f1f,
         $68d06d67, $69d26b6f, $6ad46177, $6bd6677f, $6cd87547, $6dda734f, $6edc7957, $6fde7f5f,
         $70e03da7, $71e23baf, $72e431b7, $73e637bf, $74e82587, $75ea238f, $76ec2997, $77ee2f9f,
         $78f00de7, $79f20bef, $7af401f7, $7bf607ff, $7cf815c7, $7dfa13cf, $7efc19d7, $7ffe1fdf,
         $801d2774, $811f217c, $82192b64, $831b2d6c, $84153f54, $8517395c, $86113344, $8713354c,
         $880d1734, $890f113c, $8a091b24, $8b0b1d2c, $8c050f14, $8d07091c, $8e010304, $8f03050c,
         $903d47f4, $913f41fc, $92394be4, $933b4dec, $94355fd4, $953759dc, $963153c4, $973355cc,
         $982d77b4, $992f71bc, $9a297ba4, $9b2b7dac, $9c256f94, $9d27699c, $9e216384, $9f23658c,
         $a05de769, $a15fe161, $a259eb79, $a35bed71, $a455ff49, $a557f941, $a651f359, $a753f551,
         $a84dd729, $a94fd121, $aa49db39, $ab4bdd31, $ac45cf09, $ad47c901, $ae41c319, $af43c511,
         $b07d87e9, $b17f81e1, $b2798bf9, $b37b8df1, $b4759fc9, $b57799c1, $b67193d9, $b77395d1,
         $b86db7a9, $b96fb1a1, $ba69bbb9, $bb6bbdb1, $bc65af89, $bd67a981, $be61a399, $bf63a591,
         $c09dba4e, $c19fbc46, $c299b65e, $c39bb056, $c495a26e, $c597a466, $c691ae7e, $c793a876,
         $c88d8a0e, $c98f8c06, $ca89861e, $cb8b8016, $cc85922e, $cd879426, $ce819e3e, $cf839836,
         $d0bddace, $d1bfdcc6, $d2b9d6de, $d3bbd0d6, $d4b5c2ee, $d5b7c4e6, $d6b1cefe, $d7b3c8f6,
         $d8adea8e, $d9afec86, $daa9e69e, $dbabe096, $dca5f2ae, $dda7f4a6, $dea1febe, $dfa3f8b6,
         $e0dd7a53, $e1df7c5b, $e2d97643, $e3db704b, $e4d56273, $e5d7647b, $e6d16e63, $e7d3686b,
         $e8cd4a13, $e9cf4c1b, $eac94603, $ebcb400b, $ecc55233, $edc7543b, $eec15e23, $efc3582b,
         $f0fd1ad3, $f1ff1cdb, $f2f916c3, $f3fb10cb, $f4f502f3, $f5f704fb, $f6f10ee3, $f7f308eb,
         $f8ed2a93, $f9ef2c9b, $fae92683, $fbeb208b, $fce532b3, $fde734bb, $fee13ea3, $ffe338ab);

  SB: array[byte] of byte =
        ($ba,$54,$2f,$74,$53,$d3,$d2,$4d,$50,$ac,$8d,$bf,$70,$52,$9a,$4c,
         $ea,$d5,$97,$d1,$33,$51,$5b,$a6,$de,$48,$a8,$99,$db,$32,$b7,$fc,
         $e3,$9e,$91,$9b,$e2,$bb,$41,$6e,$a5,$cb,$6b,$95,$a1,$f3,$b1,$02,
         $cc,$c4,$1d,$14,$c3,$63,$da,$5d,$5f,$dc,$7d,$cd,$7f,$5a,$6c,$5c,
         $f7,$26,$ff,$ed,$e8,$9d,$6f,$8e,$19,$a0,$f0,$89,$0f,$07,$af,$fb,
         $08,$15,$0d,$04,$01,$64,$df,$76,$79,$dd,$3d,$16,$3f,$37,$6d,$38,
         $b9,$73,$e9,$35,$55,$71,$7b,$8c,$72,$88,$f6,$2a,$3e,$5e,$27,$46,
         $0c,$65,$68,$61,$03,$c1,$57,$d6,$d9,$58,$d8,$66,$d7,$3a,$c8,$3c,
         $fa,$96,$a7,$98,$ec,$b8,$c7,$ae,$69,$4b,$ab,$a9,$67,$0a,$47,$f2,
         $b5,$22,$e5,$ee,$be,$2b,$81,$12,$83,$1b,$0e,$23,$f5,$45,$21,$ce,
         $49,$2c,$f9,$e6,$b6,$28,$17,$82,$1a,$8b,$fe,$8a,$09,$c9,$87,$4e,
         $e1,$2e,$e4,$e0,$eb,$90,$a4,$1e,$85,$60,$00,$25,$f4,$f1,$94,$0b,
         $e7,$75,$ef,$34,$31,$d4,$d0,$86,$7e,$ad,$fd,$29,$30,$3b,$9f,$f8,
         $c6,$13,$06,$05,$c5,$11,$77,$7c,$7a,$78,$36,$1c,$39,$59,$18,$56,
         $b3,$b0,$24,$20,$b2,$92,$a3,$c0,$44,$62,$10,$b4,$84,$43,$93,$c2,
         $4a,$bd,$8f,$2d,$bc,$9c,$6a,$40,$cf,$a2,$80,$4f,$1f,$ca,$aa,$42);


  RC: array[0..18] of longint =
        ($ba542f74, $53d3d24d, $50ac8dbf, $70529a4c, $ead597d1,
         $33515ba6, $de48a899, $db32b7fc, $e39e919b, $e2bb416e,
         $a5cb6b95, $a1f3b102, $ccc41d14, $c363da5d, $5fdc7dcd,
         $7f5a6c5c, $f726ffed, $e89d6f8e, $19a0f089);

const
  X000000ff = longint($000000ff);  {Avoid D4+ warnings}
  X0000ff00 = longint($0000ff00);
  X00ff0000 = longint($00ff0000);
  Xff000000 = longint($ff000000);

{$ifdef StrictLong}
  {$warnings on}
  {$ifdef RangeChecks_on}
    {$R+}
  {$endif}
{$endif}

{$ifdef D4Plus}
var
{$else}
{$ifdef J_OPT} {$J+} {$endif}
const
{$endif}
  FastInit : boolean = true;    {Clear only necessary context data at init}
                                {IV and buf remain uninitialized}


{$ifndef BIT16}
{------- 32/64-bit code --------}
{$ifdef BIT64}
{---------------------------------------------------------------------------}
function RB(A: longint): longint;  {$ifdef HAS_INLINE} inline; {$endif}
  {-reverse byte order in longint}
begin
  RB := ((A and $FF) shl 24) or ((A and $FF00) shl 8) or ((A and $FF0000) shr 8) or ((A and longint($FF000000)) shr 24);
end;
{$else}
 {$ifdef CPUARM}
   {---------------------------------------------------------------------------}
   function RB(A: longint): longint;  {$ifdef HAS_INLINE} inline; {$endif}
     {-reverse byte order in longint}
   begin
     RB := ((A and $FF) shl 24) or ((A and $FF00) shl 8) or ((A and $FF0000) shr 8) or ((A and longint($FF000000)) shr 24);
   end;
 {$else}
  {---------------------------------------------------------------------------}
  function RB(A: longint): longint; assembler;  {&frame-}
    {-reverse byte order in longint}
  asm
    {$ifdef LoadArgs}
      mov eax,[A]
    {$endif}
      xchg al,ah
      rol  eax,16
      xchg al,ah
  end;
 {$endif}

{$endif}

{$else}
{---------------------------------------------------------------------------}
function RB(A: longint): longint;
  {-reverse byte order in longint}
inline(
  $58/              {pop    ax   }
  $5A/              {pop    dx   }
  $86/$C6/          {xchg   dh,al}
  $86/$E2);         {xchg   dl,ah}
{$endif}


{$ifdef BASM16}
{---------------------------------------------------------------------------}
procedure ANU_XorBlock({$ifdef CONST} const {$else} var {$endif} B1, B2: TANUBlock; var B3: TANUBlock);
  {-xor two blocks, result in third}
begin
  asm
             mov   di,ds
             lds   si,[B1]
    db $66;  mov   ax,[si]
    db $66;  mov   bx,[si+4]
    db $66;  mov   cx,[si+8]
    db $66;  mov   dx,[si+12]
             lds   si,[B2]
    db $66;  xor   ax,[si]
    db $66;  xor   bx,[si+4]
    db $66;  xor   cx,[si+8]
    db $66;  xor   dx,[si+12]
             lds   si,[B3]
    db $66;  mov   [si],ax
    db $66;  mov   [si+4],bx
    db $66;  mov   [si+8],cx
    db $66;  mov   [si+12],dx
             mov   ds,di
  end;
end;

{$else}

{---------------------------------------------------------------------------}
procedure ANU_XorBlock({$ifdef CONST} const {$else} var {$endif} B1, B2: TANUBlock; var B3: TANUBlock);
  {-xor two blocks, result in third}
var
  a1: TWA4 absolute B1;
  a2: TWA4 absolute B2;
  a3: TWA4 absolute B3;
begin
  a3[0] := a1[0] xor a2[0];
  a3[1] := a1[1] xor a2[1];
  a3[2] := a1[2] xor a2[2];
  a3[3] := a1[3] xor a2[3];
end;

{$endif BASM16}


{---------------------------------------------------------------------------}
procedure ANU_SetFastInit(value: boolean);
  {-set FastInit variable}
begin
  FastInit := value;
end;


{---------------------------------------------------------------------------}
function  ANU_GetFastInit: boolean;
  {-Returns FastInit variable}
begin
  ANU_GetFastInit := FastInit;
end;


{$ifndef BIT16}
{---------------------------------------------------------------------------}
function ANU_Init2(const Key; KeyBits: word; var ctx: TANUContext; decr: byte): integer;
  {-Anubis context/round key initialization, decrypt if decr<>0}
var
  kappa,inter: array[0..9] of longint;
  i,j,N,N1,r: integer;
  K0,K1,K2,K3: longint;
  RKEnc: TANURndKey;
begin
  if (KeyBits and $1F <> 0) or (KeyBits<128) or (KeyBits>320) then begin
    ANU_Init2 := ANU_Err_Invalid_Key_Size;
    exit;
  end;

  ANU_Init2 := 0;
  if FastInit then with ctx do begin
    {Clear only the necessary context data at init. IV and buf}
    {remain uninitialized, other fields are initialized below.}
    bLen :=0;
    Flag :=0;
    IncProc := nil;
  end
  else fillchar(ctx, sizeof(ctx), 0);

  N  := KeyBits shr 5;
  N1 := pred(N);
  ctx.Rounds  := 8 + N;
  ctx.Keybits := KeyBits;
  ctx.Decrypt := decr;

  {map cipher key to initial key state}
  for i:=0 to N1 do kappa[i] := RB(TXSBox(Key)[i]);

  {generate Rounds + 1 round keys}
  for r:=0 to ctx.Rounds do begin
    K0 := T4[kappa[N1] shr 24];
    K1 := T4[kappa[N1] shr 16 and $ff];
    K2 := T4[kappa[N1] shr  8 and $ff];
    K3 := T4[kappa[N1]        and $ff];
    for i:=N-2 downto 0 do begin
      K0 := T4[kappa[i] shr 24] xor
           (T5[K0 shr 24        ] and Xff000000) xor
           (T5[K0 shr 16 and $ff] and X00ff0000) xor
           (T5[K0 shr  8 and $ff] and X0000ff00) xor
           (T5[K0        and $ff] and X000000ff);
      K1 := T4[kappa[i] shr 16 and $ff] xor
           (T5[K1 shr 24        ] and Xff000000) xor
           (T5[K1 shr 16 and $ff] and X00ff0000) xor
           (T5[K1 shr  8 and $ff] and X0000ff00) xor
           (T5[K1        and $ff] and X000000ff);
      K2 := T4[kappa[i] shr  8 and $ff] xor
           (T5[K2 shr 24        ] and Xff000000) xor
           (T5[K2 shr 16 and $ff] and X00ff0000) xor
           (T5[K2 shr  8 and $ff] and X0000ff00) xor
           (T5[K2        and $ff] and X000000ff);
      K3 := T4[kappa[i]       and $ff] xor
           (T5[K3 shr 24        ] and Xff000000) xor
           (T5[K3 shr 16 and $ff] and X00ff0000) xor
           (T5[K3 shr  8 and $ff] and X0000ff00) xor
           (T5[K3        and $ff] and X000000ff);
    end; {for i}
    ctx.RK[r][0] := K0;
    ctx.RK[r][1] := K1;
    ctx.RK[r][2] := K2;
    ctx.RK[r][3] := K3;
    if r<ctx.Rounds then begin
      for i:=0 to N1 do begin
        j := i;
        inter[i] := T0[kappa[j] shr 24];                      if j=0 then j:=N1 else dec(j);
        inter[i] := inter[i] xor T1[kappa[j] shr 16 and $ff]; if j=0 then j:=N1 else dec(j);
        inter[i] := inter[i] xor T2[kappa[j] shr  8 and $ff]; if j=0 then j:=N1 else dec(j);
        inter[i] := inter[i] xor T3[kappa[j] and $ff];
      end;
      kappa[0] := inter[0] xor RC[r];
      for i:=1 to pred(N) do kappa[i] := inter[i];
    end;
  end;
  {generate inverse key schedule}
  if decr<>0 then with ctx do begin
    RKEnc := RK;
    j := Rounds;
    for i:=0 to 3 do begin
      RK[0][i] := RKEnc[j][i];
      RK[j][i] := RKEnc[0][i];
    end;
    for r:=1 to pred(j) do begin
      for i:=0 to 3 do begin
        K0 := RKEnc[j-r][i];
        RK[r][i] := T0[SB[K0 shr 24        ]] xor
                    T1[SB[K0 shr 16 and $ff]] xor
                    T2[SB[K0 shr  8 and $ff]] xor
                    T3[SB[K0        and $ff]];
      end;
    end;
  end;
end;


{---------------------------------------------------------------------------}
procedure crypt(const BI: TANUBlock; var BO: TANUBlock; const roundKey: TANURndKey; RR: integer);
  {-core crypting routine, enc/dec differ only for roundKey}
var
  r: integer;
  state, inter: TWA4;
begin
  {map plaintext block to cipher state and add initial round key}
  state[0] := RB(TWA4(BI)[0]) xor roundKey[0][0];
  state[1] := RB(TWA4(BI)[1]) xor roundKey[0][1];
  state[2] := RB(TWA4(BI)[2]) xor roundKey[0][2];
  state[3] := RB(TWA4(BI)[3]) xor roundKey[0][3];
  {RR-1 full rounds}
  for r:=1 to RR-1 do begin
    inter[0] := T0[state[0] shr 24        ] xor
                T1[state[1] shr 24        ] xor
                T2[state[2] shr 24        ] xor
                T3[state[3] shr 24        ] xor roundKey[r][0];
    inter[1] := T0[state[0] shr 16 and $ff] xor
                T1[state[1] shr 16 and $ff] xor
                T2[state[2] shr 16 and $ff] xor
                T3[state[3] shr 16 and $ff] xor roundKey[r][1];
    inter[2] := T0[state[0] shr  8 and $ff] xor
                T1[state[1] shr  8 and $ff] xor
                T2[state[2] shr  8 and $ff] xor
                T3[state[3] shr  8 and $ff] xor roundKey[r][2];
    inter[3] := T0[state[0]        and $ff] xor
                T1[state[1]        and $ff] xor
                T2[state[2]        and $ff] xor
                T3[state[3]        and $ff] xor roundKey[r][3];
    state[0] := inter[0];
    state[1] := inter[1];
    state[2] := inter[2];
    state[3] := inter[3];
  end;
  {last round}
  inter[0] := (T0[state[0] shr 24        ] and Xff000000) xor
              (T1[state[1] shr 24        ] and X00ff0000) xor
              (T2[state[2] shr 24        ] and X0000ff00) xor
              (T3[state[3] shr 24        ] and X000000ff) xor roundKey[RR][0];
  inter[1] := (T0[state[0] shr 16 and $ff] and Xff000000) xor
              (T1[state[1] shr 16 and $ff] and X00ff0000) xor
              (T2[state[2] shr 16 and $ff] and X0000ff00) xor
              (T3[state[3] shr 16 and $ff] and X000000ff) xor roundKey[RR][1];
  inter[2] := (T0[state[0] shr  8 and $ff] and Xff000000) xor
              (T1[state[1] shr  8 and $ff] and X00ff0000) xor
              (T2[state[2] shr  8 and $ff] and X0000ff00) xor
              (T3[state[3] shr  8 and $ff] and X000000ff) xor roundKey[RR][2];
  inter[3] := (T0[state[0]        and $ff] and Xff000000) xor
              (T1[state[1]        and $ff] and X00ff0000) xor
              (T2[state[2]        and $ff] and X0000ff00) xor
              (T3[state[3]        and $ff] and X000000ff) xor roundKey[RR][3];
  {map cipher state to ciphertext block}
  TWA4(BO)[0] := RB(inter[0]);
  TWA4(BO)[1] := RB(inter[1]);
  TWA4(BO)[2] := RB(inter[2]);
  TWA4(BO)[3] := RB(inter[3]);
end;


{$else}


{---------------------------------------------------------------------------}
function ANU_Init2({$ifdef CONST} const {$else} var {$endif} Key; KeyBits: word; var ctx: TANUContext; decr: byte): integer;
  {-Anubis context/round key initialization, decrypt if decr<>0}
type
  TBA4 = array[0..3] of byte;
var
  i,j,N,N1,N14,r: integer;
  K0,K1,K2,K3: longint;
  RKEnc: TANURndKey;
  kappa,inter: array[0..9] of longint;
  kv: array[0..39] of byte absolute kappa;
begin
  if (KeyBits and $1F <> 0) or (KeyBits<128) or (KeyBits>320) then begin
    ANU_Init2 := ANU_Err_Invalid_Key_Size;
    exit;
  end;

  ANU_Init2 := 0;
  if FastInit then with ctx do begin
    {Clear only the necessary context data at init. IV and buf}
    {remain uninitialized, other fields are initialized below.}
    bLen :=0;
    Flag :=0;
    {$ifdef CONST}
      IncProc := nil;
    {$else}
      {TP5-6 do not like IncProc := nil;}
      fillchar(IncProc, sizeof(IncProc), 0);
    {$endif}
  end
  else fillchar(ctx, sizeof(ctx), 0);

  N   := KeyBits shr 5;
  N1  := pred(N);
  N14 := 4*N1;
  ctx.Rounds  := 8 + N;
  ctx.Keybits := KeyBits;
  ctx.Decrypt := decr;

  {map cipher key to initial key state}
  for i:=0 to N1 do kappa[i] := RB(TXSBox(Key)[i]);

  {generate Rounds + 1 round keys}
  for r:=0 to ctx.Rounds do begin
    j  := N14;
    K0 := T4[kv[j+3]];
    K1 := T4[kv[j+2]];
    K2 := T4[kv[j+1]];
    K3 := T4[kv[j  ]];
    for i:=N-2 downto 0 do begin
      dec(j,4);
      K0 := T4[kv[j+3]] xor
           (T5[TBA4(K0)[3]] and Xff000000) xor
           (T5[TBA4(K0)[2]] and X00ff0000) xor
           (T5[TBA4(K0)[1]] and X0000ff00) xor
           (T5[TBA4(K0)[0]] and X000000ff);
      K1 := T4[kv[j+2]] xor
           (T5[TBA4(K1)[3]] and Xff000000) xor
           (T5[TBA4(K1)[2]] and X00ff0000) xor
           (T5[TBA4(K1)[1]] and X0000ff00) xor
           (T5[TBA4(K1)[0]] and X000000ff);
      K2 := T4[kv[j+1]] xor
           (T5[TBA4(K2)[3]] and Xff000000) xor
           (T5[TBA4(K2)[2]] and X00ff0000) xor
           (T5[TBA4(K2)[1]] and X0000ff00) xor
           (T5[TBA4(K2)[0]] and X000000ff);
      K3 := T4[kv[j  ]] xor
           (T5[TBA4(K3)[3]] and Xff000000) xor
           (T5[TBA4(K3)[2]] and X00ff0000) xor
           (T5[TBA4(K3)[1]] and X0000ff00) xor
           (T5[TBA4(K3)[0]] and X000000ff);
    end; {for i}
    ctx.RK[r][0] := K0;
    ctx.RK[r][1] := K1;
    ctx.RK[r][2] := K2;
    ctx.RK[r][3] := K3;
    if r<ctx.Rounds then begin
      for i:=0 to N1 do begin
        j := 4*i;
        inter[i] := T0[kv[j+3]];              if j=0 then j:=N14 else dec(j,4);
        inter[i] := inter[i] xor T1[kv[j+2]]; if j=0 then j:=N14 else dec(j,4);
        inter[i] := inter[i] xor T2[kv[j+1]]; if j=0 then j:=N14 else dec(j,4);
        inter[i] := inter[i] xor T3[kv[j  ]];
      end;
      kappa[0] := inter[0] xor RC[r];
      for i:=1 to N1 do kappa[i] := inter[i];
    end;
  end;
  {generate inverse key schedule}
  if decr<>0 then with ctx do begin
    RKEnc := RK;
    j := Rounds;
    for i:=0 to 3 do begin
      RK[0][i] := RKEnc[j][i];
      RK[j][i] := RKEnc[0][i];
    end;
    for r:=1 to pred(j) do begin
      for i:=0 to 3 do begin
        K0 := RKEnc[j-r][i];
        RK[r][i] := T0[SB[TBA4(K0)[3]]] xor T1[SB[TBA4(K0)[2]]] xor T2[SB[TBA4(K0)[1]]] xor T3[SB[TBA4(K0)[0]]];
      end;
    end;
  end;
end;


{---------------------------------------------------------------------------}
{$ifdef BASM16}
{$ifdef CONST}
procedure crypt(const BI: TANUBlock; var BO: TANUBlock; const roundKey: TANURndKey; RR: integer);
  {-core crypting routine, enc/dec differ only for roundKey}
{$else}
procedure crypt(var BI: TANUBlock; var BO: TANUBlock; var roundKey: TANURndKey; RR: integer);
  {-core crypting routine, enc/dec differ only for roundKey}
{$endif}
var
  state, inter: TWA4;
  sv: TANUBlock absolute state;
  iv: TANUBlock absolute inter;
const
  X000000ff: longint = $000000ff;
  X0000ff00: longint = $0000ff00;
  X00ff0000: longint = $00ff0000;
  Xff000000: longint = $ff000000;
begin
  asm
  {map plaintext block to cipher state and add initial round key}
            push ds
            lds  si,[bi]
            les  di,[roundkey]
    {state[0] := RB(TWA4(BI)[0]) xor roundKey[0][0]}
    db $66; mov  ax,[si]
            xchg al,ah
    db $66; rol  ax,16
            xchg al,ah
    db $66; xor  ax,es:[di]
    db $66; mov  word ptr state[0], ax

    {state[1] := RB(TWA4(BI)[1]) xor roundKey[0][1]}
    db $66; mov  ax,[si+4]
            xchg al,ah
    db $66; rol  ax,16
            xchg al,ah
    db $66; xor  ax,es:[di+4]
    db $66; mov  word ptr state[4], ax

    {state[2] := RB(TWA4(BI)[2]) xor roundKey[0][2]}
    db $66; mov  ax,[si+8]
            xchg al,ah
    db $66; rol  ax,16
            xchg al,ah
    db $66; xor  ax,es:[di+8]
    db $66; mov  word ptr state[8], ax

    {state[3] := RB(TWA4(BI)[3]) xor roundKey[0][3]}
    db $66; mov  ax,[si+12]
            xchg al,ah
    db $66; rol  ax,16
            xchg al,ah
    db $66; xor  ax,es:[di+12]
    db $66; mov  word ptr state[12], ax

            add  di,16
            pop  ds

            {load cx with RR-1, skip if RR<2}
            mov  cx,[RR]
            sub  cx,1
            jle  @@2

    { *Note* in the following round loop            }
    { op  eax, mem[4*bx] is calculated as           }
    { lea esi, [ebx + 2*ebx]                        }
    { op  eax, mem[ebx+esi]                         }
    { lea esi,[ebx+2*ebx] = db $66,$67,$8D,$34,$5B; }

    db $66; sub  bx,bx      {clear ebx}

  {RR-1 full rounds}

  @@1:
    {inter[0] := T0[sv[ 3]] xor T1[sv[ 7]] xor T2[sv[11]] xor T3[sv[15]] xor roundKey[r][0]}
            mov  bl,byte ptr sv[3]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T0[bx+si]

            mov  bl,byte ptr sv[7]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T1[bx+si]

            mov  bl,byte ptr sv[11]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T2[bx+si]

            mov  bl,byte ptr sv[15]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T3[bx+si]
    db $66; xor  ax,es:[di]
    db $66; mov  word ptr inter[0],ax

    {inter[1] := T0[sv[ 2]] xor T1[sv[ 6]] xor T2[sv[10]] xor T3[sv[14]] xor roundKey[r][1]}
            mov  bl,byte ptr sv[2]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T0[bx+si]

            mov  bl,byte ptr sv[6]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T1[bx+si]

            mov  bl,byte ptr sv[10]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T2[bx+si]

            mov  bl,byte ptr sv[14]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T3[bx+si]

    db $66; xor  ax,es:[di+4]
    db $66; mov  word ptr inter[4],ax

    {inter[2] := T0[sv[ 1]] xor T1[sv[ 5]] xor T2[sv[ 9]] xor T3[sv[13]] xor roundKey[r][2]}
            mov  bl,byte ptr sv[1]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T0[bx+si]

            mov  bl,byte ptr sv[5]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T1[bx+si]

            mov  bl,byte ptr sv[9]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T2[bx+si]

            mov  bl,byte ptr sv[13]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T3[bx+si]

    db $66; xor  ax,es:[di+8]
    db $66; mov  word ptr inter[8],ax

    {inter[3] := T0[sv[ 0]] xor T1[sv[ 4]] xor T2[sv[ 8]] xor T3[sv[12]] xor roundKey[r][3]}
            mov  bl,byte ptr sv[0]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T0[bx+si]

            mov  bl,byte ptr sv[4]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T1[bx+si]

            mov  bl,byte ptr sv[8]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T2[bx+si]

            mov  bl,byte ptr sv[12]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T3[bx+si]

    db $66; xor  ax,es:[di+12]
    db $66; mov  word ptr inter[12],ax

    {state[0] := inter[0]}
    {state[1] := inter[1]}
    {state[2] := inter[2]}
    {state[3] := inter[3]}
    db $66; mov  ax,word ptr inter[0]
    db $66; mov  word ptr state[0],ax
    db $66; mov  ax,word ptr inter[4]
    db $66; mov  word ptr state[4],ax
    db $66; mov  ax,word ptr inter[8]
    db $66; mov  word ptr state[8],ax
    db $66; mov  ax,word ptr inter[12]
    db $66; mov  word ptr state[12],ax

            add  di,16
            dec  cx
            jnz  @@1
  @@2:

    {inter[0] := (T0[sv[ 3]] and Xff000000) xor
                 (T1[sv[ 7]] and X00ff0000) xor
                 (T2[sv[11]] and X0000ff00) xor
                 (T3[sv[15]] and X000000ff) xor roundKey[RR][0];}
    db $66; mov  cx,es:[di]
            mov  bl,byte ptr sv[3]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T0[bx+si]
    db $66; and  ax,word ptr Xff000000
    db $66; xor  cx,ax

            mov  bl,byte ptr sv[7]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T1[bx+si]
    db $66; and  ax,word ptr X00ff0000
    db $66; xor  cx,ax

            mov  bl,byte ptr sv[11]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T2[bx+si]
    db $66; and  ax,word ptr X0000ff00
    db $66; xor  cx,ax

            mov  bl,byte ptr sv[15]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T3[bx+si]
    db $66; and  ax,word ptr X000000ff
    db $66; xor  ax,cx
    db $66; mov  word ptr inter[0],ax

    {inter[1] := (T0[sv[ 2]] and Xff000000) xor
                 (T1[sv[ 6]] and X00ff0000) xor
                 (T2[sv[10]] and X0000ff00) xor
                 (T3[sv[14]] and X000000ff) xor roundKey[RR][1];}
    db $66; mov  cx,es:[di+4]
            mov  bl,byte ptr sv[2]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T0[bx+si]
    db $66; and  ax,word ptr Xff000000
    db $66; xor  cx,ax

            mov  bl,byte ptr sv[6]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T1[bx+si]
    db $66; and  ax,word ptr X00ff0000
    db $66; xor  cx,ax

            mov  bl,byte ptr sv[10]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T2[bx+si]
    db $66; and  ax,word ptr X0000ff00
    db $66; xor  cx,ax

            mov  bl,byte ptr sv[14]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T3[bx+si]
    db $66; and  ax,word ptr X000000ff
    db $66; xor  ax,cx
    db $66; mov  word ptr inter[4],ax

    {inter[2] := (T0[sv[ 1]] and Xff000000) xor
                 (T1[sv[ 5]] and X00ff0000) xor
                 (T2[sv[ 9]] and X0000ff00) xor
                 (T3[sv[13]] and X000000ff) xor roundKey[RR][2];}
    db $66; mov  cx,es:[di+8]
            mov  bl,byte ptr sv[1]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T0[bx+si]
    db $66; and  ax,word ptr Xff000000
    db $66; xor  cx,ax

            mov  bl,byte ptr sv[5]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T1[bx+si]
    db $66; and  ax,word ptr X00ff0000
    db $66; xor  cx,ax

            mov  bl,byte ptr sv[9]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T2[bx+si]
    db $66; and  ax,word ptr X0000ff00
    db $66; xor  cx,ax

            mov  bl,byte ptr sv[13]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T3[bx+si]
    db $66; and  ax,word ptr X000000ff
    db $66; xor  ax,cx
    db $66; mov  word ptr inter[8],ax

    {inter[3] := (T0[sv[ 0]] and Xff000000) xor
                 (T1[sv[ 4]] and X00ff0000) xor
                 (T2[sv[ 8]] and X0000ff00) xor
                 (T3[sv[12]] and X000000ff) xor roundKey[RR][3];}
    db $66; mov  cx,es:[di+12]
            mov  bl,byte ptr sv[0]
    db $66,$67,$8D,$34,$5B;
    db $66; mov  ax,word ptr T0[bx+si]
    db $66; and  ax,word ptr Xff000000
    db $66; xor  cx,ax

            mov  bl,byte ptr sv[4]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T1[bx+si]
    db $66; and  ax,word ptr X00ff0000
    db $66; xor  cx,ax

            mov  bl,byte ptr sv[8]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T2[bx+si]
    db $66; and  ax,word ptr X0000ff00
    db $66; xor  cx,ax

            mov  bl,byte ptr sv[12]
    db $66,$67,$8D,$34,$5B;
    db $66; xor  ax,word ptr T3[bx+si]
    db $66; and  ax,word ptr X000000ff
    db $66; xor  ax,cx
    db $66; mov  word ptr inter[12],ax

    {map cipher state to ciphertext block}
            les  di,[BO]
    {TWA4(BO)[0] := RB(inter[0])}
    db $66; mov  ax,word ptr inter[0]
            xchg al,ah
    db $66; rol  ax,16
            xchg al,ah
    db $66; mov  es:[di],ax

    {TWA4(BO)[1] := RB(inter[1])}
    db $66; mov  ax,word ptr inter[4]
            xchg al,ah
    db $66; rol  ax,16
            xchg al,ah
    db $66; mov  es:[di+4],ax

    {TWA4(BO)[2] := RB(inter[2])}
    db $66; mov  ax,word ptr inter[8]
            xchg al,ah
    db $66; rol  ax,16
            xchg al,ah
    db $66; mov  es:[di+8],ax

    {TWA4(BO)[3] := RB(inter[3])}
    db $66; mov  ax,word ptr inter[12]
            xchg al,ah
    db $66; rol  ax,16
            xchg al,ah
    db $66; mov  es:[di+12],ax

  end;
end;
{$else}
{---------------------------------------------------------------------------}
{$ifdef CONST}
procedure crypt(const BI: TANUBlock; var BO: TANUBlock; const roundKey: TANURndKey; RR: integer);
  {-core crypting routine, enc/dec differ only for roundKey}
{$else}
procedure crypt(var BI: TANUBlock; var BO: TANUBlock; var roundKey: TANURndKey; RR: integer);
  {-core crypting routine, enc/dec differ only for roundKey}
{$endif}
var
  r: integer;
  state, inter: TWA4;
  sv: TANUBlock absolute state;
  iv: TANUBlock absolute inter;
begin
  {map plaintext block to cipher state and add initial round key}
  state[0] := RB(TWA4(BI)[0]) xor roundKey[0][0];
  state[1] := RB(TWA4(BI)[1]) xor roundKey[0][1];
  state[2] := RB(TWA4(BI)[2]) xor roundKey[0][2];
  state[3] := RB(TWA4(BI)[3]) xor roundKey[0][3];
  {RR-1 full rounds}
  for r:=1 to RR-1 do begin
    inter[0] := T0[sv[ 3]] xor T1[sv[ 7]] xor T2[sv[11]] xor T3[sv[15]] xor roundKey[r][0];
    inter[1] := T0[sv[ 2]] xor T1[sv[ 6]] xor T2[sv[10]] xor T3[sv[14]] xor roundKey[r][1];
    inter[2] := T0[sv[ 1]] xor T1[sv[ 5]] xor T2[sv[ 9]] xor T3[sv[13]] xor roundKey[r][2];
    inter[3] := T0[sv[ 0]] xor T1[sv[ 4]] xor T2[sv[ 8]] xor T3[sv[12]] xor roundKey[r][3];
    state[0] := inter[0];
    state[1] := inter[1];
    state[2] := inter[2];
    state[3] := inter[3];
  end;
  {last round}
  inter[0] := (T0[sv[ 3]] and Xff000000) xor
              (T1[sv[ 7]] and X00ff0000) xor
              (T2[sv[11]] and X0000ff00) xor
              (T3[sv[15]] and X000000ff) xor roundKey[RR][0];
  inter[1] := (T0[sv[ 2]] and Xff000000) xor
              (T1[sv[ 6]] and X00ff0000) xor
              (T2[sv[10]] and X0000ff00) xor
              (T3[sv[14]] and X000000ff) xor roundKey[RR][1];
  inter[2] := (T0[sv[ 1]] and Xff000000) xor
              (T1[sv[ 5]] and X00ff0000) xor
              (T2[sv[ 9]] and X0000ff00) xor
              (T3[sv[13]] and X000000ff) xor roundKey[RR][2];
  inter[3] := (T0[sv[ 0]] and Xff000000) xor
              (T1[sv[ 4]] and X00ff0000) xor
              (T2[sv[ 8]] and X0000ff00) xor
              (T3[sv[12]] and X000000ff) xor roundKey[RR][3];
  {map cipher state to ciphertext block}
  TWA4(BO)[0] := RB(inter[0]);
  TWA4(BO)[1] := RB(inter[1]);
  TWA4(BO)[2] := RB(inter[2]);
  TWA4(BO)[3] := RB(inter[3]);
end;
{$endif}

{$endif}


{---------------------------------------------------------------------------}
function ANU_Init_Encr({$ifdef CONST} const {$else} var {$endif} Key; KeyBits: word; var ctx: TANUContext): integer;
  {-Anubis context/round key initialization}
begin
  ANU_Init_Encr := ANU_Init2(Key, KeyBits, ctx, 0);
end;


{---------------------------------------------------------------------------}
function ANU_Init_Decr({$ifdef CONST} const {$else} var {$endif} Key; KeyBits: word; var ctx: TANUContext): integer;
  {-Anubis context/round key initialization}
begin
  ANU_Init_Decr := ANU_Init2(Key, KeyBits, ctx, 1);
end;


{---------------------------------------------------------------------------}
procedure ANU_Encrypt(var ctx: TANUContext; {$ifdef CONST} const {$else} var {$endif}  BI: TANUBlock; var BO: TANUBlock);
  {-encrypt one block (in ECB mode)}
begin
  {$ifndef DLL}
    {$ifdef debug}
      {Check correct key setup}
      if ctx.Decrypt<>0 then RunError(210);
    {$endif}
  {$endif}
  {$ifdef BASM16}
    {Make x in inter/state dword aligned for optimized 32 bit access}
    if (sptr and 3)=0 then asm push ax end;
  {$endif}
  crypt(BI,BO,ctx.RK,ctx.rounds);
end;


{---------------------------------------------------------------------------}
procedure ANU_Decrypt(var ctx: TANUContext; {$ifdef CONST} const {$else} var {$endif}  BI: TANUBlock; var BO: TANUBlock);
  {-decrypt one block (in ECB mode)}
begin
  {$ifndef DLL}
    {$ifdef debug}
      {Check correct key setup}
      if ctx.Decrypt=0 then RunError(210);
    {$endif}
  {$endif}
  {$ifdef BASM16}
    {Make x in inter/state dword aligned for optimized 32 bit access}
    if (sptr and 3)=0 then asm push ax end;
  {$endif}
  crypt(BI,BO,ctx.RK,ctx.rounds);
end;


{---------------------------------------------------------------------------}
function ANU_T0Ofs: byte;
  {-Return offset of Table T0 mod 15, used to optimize BASM16 32 bit access}
begin
  ANU_T0Ofs := __P2I(@T0) and 15;
end;

end.
