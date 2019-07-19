unit sosemanu;

{Sosemanuk stream cipher routines}

interface

{$i STD.INC}

{$define CHECK_KEY_BITS}  {undef to allow key sizes from 0 to 256 bits}
                          {otherwise 128 to 256 bits are used.}

{.$define DebugAlign}      {Debug output for BASM16 alignment}

(*************************************************************************

 DESCRIPTION     :  Sosemanuk stream cipher routines

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10, FPC, VP, WDOSX

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  2 KB static Alpha tables

 DISPLAY MODE    :  ---

 REMARKS         :  Some BASM16 hints: High speed 16 bit code needs careful
                    tuning (note that BP7 real mode code is faster than FPC
                    32 bit with -O3 optimization)! The most important measure
                    is to dword align the local variables in MakeStreamBlock.
                    This must be done before MakeStreamBlock is called (with
                    code that tests and conditionally adjust the stack pointer).
                    Good but less important (about 1 cycle per byte) is the
                    dword access and alignment of the mul/divAlpha-Tables, via
                    $define Alpha32 and the DummyAlignBasm word.

 REFERENCES      :  [1] Phase 3 version for ECRYPT Stream Cipher Project
                        http://www.ecrypt.eu.org/stream/sosemanukp3.html
                        http://www.ecrypt.eu.org/stream/p3ciphers/sosemanuk/sosemanuk_p3source.zip
                        http://www.ecrypt.eu.org/stream/p3ciphers/sosemanuk/sosemanuk_p3.pdf
                    [2] http://www.cl.cam.ac.uk/~rja14/serpent.html

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.01     10.04.09  W.Ehrhardt  Initial version: Key setup from fast java implementation
 0.02     10.04.09  we          IV setup from fast java implementation
 0.03     10.04.09  we          Stream generator from fast java implementation
 0.04     11.04.09  we          BIT16: Recycling of Serpent Key/IV setup
 0.05     11.04.09  we          Replace RotateLeft by shl/shr
 0.06     11.04.09  we          Common context definition
 0.07     11.04.09  we          Working 32 bit selftest
 0.08     11.04.09  we          MakeStreamBlock with nblk parameter
 0.09     11.04.09  we          mulAlpha/divAlpha tables
 0.10     11.04.09  we          sose_keystream_blocks, sose_keystream_bytes
 0.11     11.04.09  we          sose_encrypt_bytes
 0.12     11.04.09  we          extendend selftest
 0.13     11.04.09  we          Changed sose_encrypt_bytes to avoid D3/D3 Internal error: URW882
 0.14     11.04.09  we          Working 16 bit part (with 32 bit MakeStreamBlock)
 0.15     12.04.09  we          SM16INC/MakeStreamBlock: r2 := RotL(tt * $54655307,7)
 0.16     12.04.09  we          SM16INC/MakeStreamBlock: mul/divAlpha index via byte
 0.17     12.04.09  we          SM16INC/MakeStreamBlock: BASM for RotL(tt * $54655307,7)
 0.18     12.04.09  we          SM16INC/MakeStreamBlock: SHL8/SHR8 inline
 0.19     12.04.09  we          Cond. define CHECK_KEY_BITS
 0.20     13.04.09  we          Improved sose_encrypt_bytes/sose_keystream_bytes
 0.21     13.04.09  we          Special FPC code in sose_encrypt_bytes
 0.22     14.04.09  we          SM16INC/MakeStreamBlock: separate code for BASM16
 0.23     14.04.09  we          SM16INC/MakeStreamBlock: more BASM code
 0.24     14.04.09  we          SM16INC/MakeStreamBlock: conditional define Alpha32
 0.25     14.04.09  we          BASM16: Add code to dword align local variables of MakeStreamBlock
 0.26     15.04.09  we          Second pass in selftest with length <> blocksize
 0.27     15.04.09  we          Separate BIT16 inc files, sose_ivsetup with BASM16
 0.28     24.04.09  we          BASM16 keysetup
 0.29     24.04.09  we          Faster lkey setup in sose_keysetup; BASM16: dword align K0
 **************************************************************************)



(*-------------------------------------------------------------------------
 (C) Copyright 2009 Wolfgang Ehrhardt

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


(*************************************************************************
 Encryption/decryption of arbitrary length messages.

 For efficiency reasons, the API provides two types of encrypt/decrypt
 functions. The sose_encrypt_bytes function encrypts byte strings of
 arbitrary length, while the sose_encrypt_blocks function only accepts
 lengths which are multiples of sose_blocklength.

 The user is allowed to make multiple calls to sose_encrypt_blocks to
 incrementally encrypt a long message, but he is NOT allowed to make
 additional encryption calls once he has called sose_encrypt_bytes
 (unless he starts a new message of course). For example, this sequence
 of calls is acceptable:

   sose_keysetup();

   sose_ivsetup();
   sose_encrypt_blocks();
   sose_encrypt_blocks();
   sose_encrypt_bytes();

   sose_ivsetup();
   sose_encrypt_blocks();
   sose_encrypt_blocks();

   sose_ivsetup();
   sose_encrypt_bytes();

   The following sequence is not:

   sose_keysetup();
   sose_ivsetup();
   sose_encrypt_blocks();
   sose_encrypt_bytes();
   sose_encrypt_blocks();
**************************************************************************)


uses
  BTypes;

const
  sose_blocklength = 80;                  {Block length in bytes}

type
  TSMBlock   = packed array[0..79] of byte;
  TSMBlockW  = packed array[0..19] of longint;
  TPSMBlock  = ^TSMBlock;
  TPSMBlockW = ^TSMBlockW;

  {Structure containing the context of Sosemanuk}
  sose_ctx   = packed record
                  lfsr   : array[0..9]  of longint;  {Internal state LFSR}
                  fsmr   : array[1..2]  of longint;  {Finite state machine}
                  RndKey : array[0..99] of longint;  {Round keys from key setup}
                end;


function  sose_keysetup(var ctx: sose_ctx; key: pointer; keybits: word): integer;
  {-Key setup, keybits div 8 (max. 32) bytes of key^ are used, if CHECK_KEY_BITS}
  { is defined (default), keybits must be at least 128. It is the user's }
  { responsibility to supply a pointer to at least keybits accessible bits.}

procedure sose_ivsetup(var ctx: sose_ctx; IV: pointer);
  {-IV setup, 128 bits of IV^ are used. It is the user's responsibility to }
  { supply least 128 accessible IV bits. After having called sose_keysetup,}
  { the user is allowed to call sose_ivsetup different times in order to   }
  { encrypt/decrypt different messages with the same key but different IV's}

procedure sose_encrypt_bytes(var ctx: sose_ctx; ptp, ctp: pointer; msglen: longint);
  {-Bytewise encryption, msglen: message length in bytes}

procedure sose_encrypt_blocks(var ctx: sose_ctx; ptp, ctp: pointer; blocks: word);
  {-Blockwise encrypt plainttext to ciphertext, blocks: length in 80 byte blocks}

procedure sose_encrypt_packet(var ctx: sose_ctx; IV, ptp, ctp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to  supply least 128 accessible IV bits.}

procedure sose_decrypt_bytes(var ctx: sose_ctx; ctp, ptp: pointer; msglen: longint);
  {-Bytewise decryption, msglen: message length in bytes}

procedure sose_decrypt_blocks(var ctx: sose_ctx; ctp, ptp: pointer; blocks: word);
  {-Blockwise decryption, blocks: length in 80 byte blocks}

procedure sose_decrypt_packet(var ctx: sose_ctx; IV, ctp, ptp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to  supply least 128 accessible IV bits.}

procedure sose_keystream_bytes(var ctx: sose_ctx; keystream: pointer; kslen: longint);
  {-Generate keystream, kslen: keystream length in bytes}

procedure sose_keystream_blocks(var ctx: sose_ctx; keystream: pointer; blocks: word);
  {-Generate keystream, blocks: keystream length in 80 byte blocks}

function  sose_selftest: boolean;
  {-Simple self-test of Sosemanuk}



implementation

type
  TWA4 = packed array[0..3] of longint;
  PWA4 = ^TWA4;

{.$undef BASM16}

(*
The sig const is used for the translation of conditional Java/C expressions
like ((r1 & 0x01) != 0 ? s8 : 0)) into (sig[r1 and 1] and s8).
BASM does not need this const, because the translation is done as follows
   mov ax,[r1]
   shr ax,1
   sbb eax,eax
   and eax,[s8]
*)

{$ifndef BASM16}
const
  sig: array[0..1] of longint = (0, -1);
{$endif}

{$ifdef StrictLong}
  {$warnings off}
  {$R-} {avoid D9+ errors!}
{$endif}


const
  {$ifdef BASM16}
  {$define Alpha32}  {define Alpha32 to use dword access in  MakeStreamBlock}
  DummyAlignBasm: word = 0;  {Use this const to dowrd align the mul/divAlpha-Tables}
  {$endif}
  mulAlpha: array[0..255] of longint = (
    $00000000, $e19fcf13, $6b973726, $8a08f835, $d6876e4c, $3718a15f, $bd10596a, $5c8f9679,
    $05a7dc98, $e438138b, $6e30ebbe, $8faf24ad, $d320b2d4, $32bf7dc7, $b8b785f2, $59284ae1,
    $0ae71199, $eb78de8a, $617026bf, $80efe9ac, $dc607fd5, $3dffb0c6, $b7f748f3, $566887e0,
    $0f40cd01, $eedf0212, $64d7fa27, $85483534, $d9c7a34d, $38586c5e, $b250946b, $53cf5b78,
    $1467229b, $f5f8ed88, $7ff015bd, $9e6fdaae, $c2e04cd7, $237f83c4, $a9777bf1, $48e8b4e2,
    $11c0fe03, $f05f3110, $7a57c925, $9bc80636, $c747904f, $26d85f5c, $acd0a769, $4d4f687a,
    $1e803302, $ff1ffc11, $75170424, $9488cb37, $c8075d4e, $2998925d, $a3906a68, $420fa57b,
    $1b27ef9a, $fab82089, $70b0d8bc, $912f17af, $cda081d6, $2c3f4ec5, $a637b6f0, $47a879e3,
    $28ce449f, $c9518b8c, $435973b9, $a2c6bcaa, $fe492ad3, $1fd6e5c0, $95de1df5, $7441d2e6,
    $2d699807, $ccf65714, $46feaf21, $a7616032, $fbeef64b, $1a713958, $9079c16d, $71e60e7e,
    $22295506, $c3b69a15, $49be6220, $a821ad33, $f4ae3b4a, $1531f459, $9f390c6c, $7ea6c37f,
    $278e899e, $c611468d, $4c19beb8, $ad8671ab, $f109e7d2, $109628c1, $9a9ed0f4, $7b011fe7,
    $3ca96604, $dd36a917, $573e5122, $b6a19e31, $ea2e0848, $0bb1c75b, $81b93f6e, $6026f07d,
    $390eba9c, $d891758f, $52998dba, $b30642a9, $ef89d4d0, $0e161bc3, $841ee3f6, $65812ce5,
    $364e779d, $d7d1b88e, $5dd940bb, $bc468fa8, $e0c919d1, $0156d6c2, $8b5e2ef7, $6ac1e1e4,
    $33e9ab05, $d2766416, $587e9c23, $b9e15330, $e56ec549, $04f10a5a, $8ef9f26f, $6f663d7c,
    $50358897, $b1aa4784, $3ba2bfb1, $da3d70a2, $86b2e6db, $672d29c8, $ed25d1fd, $0cba1eee,
    $5592540f, $b40d9b1c, $3e056329, $df9aac3a, $83153a43, $628af550, $e8820d65, $091dc276,
    $5ad2990e, $bb4d561d, $3145ae28, $d0da613b, $8c55f742, $6dca3851, $e7c2c064, $065d0f77,
    $5f754596, $beea8a85, $34e272b0, $d57dbda3, $89f22bda, $686de4c9, $e2651cfc, $03fad3ef,
    $4452aa0c, $a5cd651f, $2fc59d2a, $ce5a5239, $92d5c440, $734a0b53, $f942f366, $18dd3c75,
    $41f57694, $a06ab987, $2a6241b2, $cbfd8ea1, $977218d8, $76edd7cb, $fce52ffe, $1d7ae0ed,
    $4eb5bb95, $af2a7486, $25228cb3, $c4bd43a0, $9832d5d9, $79ad1aca, $f3a5e2ff, $123a2dec,
    $4b12670d, $aa8da81e, $2085502b, $c11a9f38, $9d950941, $7c0ac652, $f6023e67, $179df174,
    $78fbcc08, $9964031b, $136cfb2e, $f2f3343d, $ae7ca244, $4fe36d57, $c5eb9562, $24745a71,
    $7d5c1090, $9cc3df83, $16cb27b6, $f754e8a5, $abdb7edc, $4a44b1cf, $c04c49fa, $21d386e9,
    $721cdd91, $93831282, $198beab7, $f81425a4, $a49bb3dd, $45047cce, $cf0c84fb, $2e934be8,
    $77bb0109, $9624ce1a, $1c2c362f, $fdb3f93c, $a13c6f45, $40a3a056, $caab5863, $2b349770,
    $6c9cee93, $8d032180, $070bd9b5, $e69416a6, $ba1b80df, $5b844fcc, $d18cb7f9, $301378ea,
    $693b320b, $88a4fd18, $02ac052d, $e333ca3e, $bfbc5c47, $5e239354, $d42b6b61, $35b4a472,
    $667bff0a, $87e43019, $0decc82c, $ec73073f, $b0fc9146, $51635e55, $db6ba660, $3af46973,
    $63dc2392, $8243ec81, $084b14b4, $e9d4dba7, $b55b4dde, $54c482cd, $decc7af8, $3f53b5eb);

  divAlpha: array[0..255] of longint = (
    $00000000, $180f40cd, $301e8033, $2811c0fe, $603ca966, $7833e9ab, $50222955, $482d6998,
    $c078fbcc, $d877bb01, $f0667bff, $e8693b32, $a04452aa, $b84b1267, $905ad299, $88559254,
    $29f05f31, $31ff1ffc, $19eedf02, $01e19fcf, $49ccf657, $51c3b69a, $79d27664, $61dd36a9,
    $e988a4fd, $f187e430, $d99624ce, $c1996403, $89b40d9b, $91bb4d56, $b9aa8da8, $a1a5cd65,
    $5249be62, $4a46feaf, $62573e51, $7a587e9c, $32751704, $2a7a57c9, $026b9737, $1a64d7fa,
    $923145ae, $8a3e0563, $a22fc59d, $ba208550, $f20decc8, $ea02ac05, $c2136cfb, $da1c2c36,
    $7bb9e153, $63b6a19e, $4ba76160, $53a821ad, $1b854835, $038a08f8, $2b9bc806, $339488cb,
    $bbc11a9f, $a3ce5a52, $8bdf9aac, $93d0da61, $dbfdb3f9, $c3f2f334, $ebe333ca, $f3ec7307,
    $a492d5c4, $bc9d9509, $948c55f7, $8c83153a, $c4ae7ca2, $dca13c6f, $f4b0fc91, $ecbfbc5c,
    $64ea2e08, $7ce56ec5, $54f4ae3b, $4cfbeef6, $04d6876e, $1cd9c7a3, $34c8075d, $2cc74790,
    $8d628af5, $956dca38, $bd7c0ac6, $a5734a0b, $ed5e2393, $f551635e, $dd40a3a0, $c54fe36d,
    $4d1a7139, $551531f4, $7d04f10a, $650bb1c7, $2d26d85f, $35299892, $1d38586c, $053718a1,
    $f6db6ba6, $eed42b6b, $c6c5eb95, $decaab58, $96e7c2c0, $8ee8820d, $a6f942f3, $bef6023e,
    $36a3906a, $2eacd0a7, $06bd1059, $1eb25094, $569f390c, $4e9079c1, $6681b93f, $7e8ef9f2,
    $df2b3497, $c724745a, $ef35b4a4, $f73af469, $bf179df1, $a718dd3c, $8f091dc2, $97065d0f,
    $1f53cf5b, $075c8f96, $2f4d4f68, $37420fa5, $7f6f663d, $676026f0, $4f71e60e, $577ea6c3,
    $e18d0321, $f98243ec, $d1938312, $c99cc3df, $81b1aa47, $99beea8a, $b1af2a74, $a9a06ab9,
    $21f5f8ed, $39fab820, $11eb78de, $09e43813, $41c9518b, $59c61146, $71d7d1b8, $69d89175,
    $c87d5c10, $d0721cdd, $f863dc23, $e06c9cee, $a841f576, $b04eb5bb, $985f7545, $80503588,
    $0805a7dc, $100ae711, $381b27ef, $20146722, $68390eba, $70364e77, $58278e89, $4028ce44,
    $b3c4bd43, $abcbfd8e, $83da3d70, $9bd57dbd, $d3f81425, $cbf754e8, $e3e69416, $fbe9d4db,
    $73bc468f, $6bb30642, $43a2c6bc, $5bad8671, $1380efe9, $0b8faf24, $239e6fda, $3b912f17,
    $9a34e272, $823ba2bf, $aa2a6241, $b225228c, $fa084b14, $e2070bd9, $ca16cb27, $d2198bea,
    $5a4c19be, $42435973, $6a52998d, $725dd940, $3a70b0d8, $227ff015, $0a6e30eb, $12617026,
    $451fd6e5, $5d109628, $750156d6, $6d0e161b, $25237f83, $3d2c3f4e, $153dffb0, $0d32bf7d,
    $85672d29, $9d686de4, $b579ad1a, $ad76edd7, $e55b844f, $fd54c482, $d545047c, $cd4a44b1,
    $6cef89d4, $74e0c919, $5cf109e7, $44fe492a, $0cd320b2, $14dc607f, $3ccda081, $24c2e04c,
    $ac977218, $b49832d5, $9c89f22b, $8486b2e6, $ccabdb7e, $d4a49bb3, $fcb55b4d, $e4ba1b80,
    $17566887, $0f59284a, $2748e8b4, $3f47a879, $776ac1e1, $6f65812c, $477441d2, $5f7b011f,
    $d72e934b, $cf21d386, $e7301378, $ff3f53b5, $b7123a2d, $af1d7ae0, $870cba1e, $9f03fad3,
    $3ea637b6, $26a9777b, $0eb8b785, $16b7f748, $5e9a9ed0, $4695de1d, $6e841ee3, $768b5e2e,
    $fedecc7a, $e6d18cb7, $cec04c49, $d6cf0c84, $9ee2651c, $86ed25d1, $aefce52f, $b6f3a5e2);

{$ifdef StrictLong}
  {$warnings on}
  {$ifdef RangeChecks_on}
    {$R+}
  {$endif}
{$endif}


{$ifdef BIT16}
  {$F-}
  {$ifdef BASM16}
    {$i sm16inca.pas}
  {$else}
    {$i sm16incp.pas}
  {$endif}
{$else}
  {$i sm32inc.pas}
{$endif}


{---------------------------------------------------------------------------}
procedure sose_encrypt_bytes(var ctx: sose_ctx; ptp, ctp: pointer; msglen: longint);
  {-Bytewise encryption, msglen: message length in bytes}
var
  i: integer;
  tmp: TSMBlock;
  im: integer;
begin
  {$ifdef BASM16}
    {dword align local variables in MakeStreamBlock}
    if sptr and 3 = 0 then asm push ax; end;
  {$endif}
  while msglen>0 do begin
    MakeStreamBlock(ctx, TPSMBlockW(@tmp), 1);
    if msglen<=sose_blocklength then im := integer(msglen)
    else im := sose_blocklength;
    {$ifdef BASM16}
      {Note that the 32 bit access may be unaligned and the latency  }
      {will be increased, but AFAIK even then the code will be faster}
      {than a pure 8 bit access version. In the unlikely event that  }
      {the unaligned 32 bit access is too slow, remove the lines of  }
      {code from  'shr cx,2'  ... 'jz @@4'.}
      asm
                   push ds
                   lds  si,[ptp]
                   les  di,[ctp]
                   lea  bx,[tmp]
                   mov  cx,[im]
                   shr  cx,2
                   jz   @@2
      @@1: db $66; mov  ax,ss:[bx]
           db $66; xor  ax,[si]
           db $66; mov  es:[di],ax
                   add  si,4
                   add  di,4
                   add  bx,4
                   dec  cx
                   jnz  @@1
              @@2: mov  cx,[im]
                   and  cx,3
                   jz   @@4
              @@3: mov  al,ss:[bx]
                   xor  al,[si]
                   mov  es:[di],al
                   inc  si
                   inc  di
                   inc  bx
                   dec  cx
                   jnz  @@3
              @@4: mov  word ptr [ptp],si
                   mov  word ptr [ctp],di
                   pop  ds
      end;
    {$else}
      {$ifdef FPC}
        for i:=0 to pred(im) do begin
          pByte(ctp)^ := byte(ptp^) xor tmp[i];
          inc(Ptr2Inc(ptp));
          inc(Ptr2Inc(ctp));
        end;
      {$else}
        for i:=0 to pred(im) do TPSMBlock(ctp)^[i] := TPSMBlock(ptp)^[i] xor tmp[i];
        inc(Ptr2Inc(ptp),im);
        inc(Ptr2Inc(ctp),im);
      {$endif}
    {$endif}
    dec(msglen,sose_blocklength);
  end;
end;


{---------------------------------------------------------------------------}
procedure sose_keystream_bytes(var ctx: sose_ctx; keystream: pointer; kslen: longint);
  {-Generate keystream, kslen: keystream length in bytes}
var
  tmp: TSMBlock;
  i: word;
begin
  {$ifdef BASM16}
    {dword align local variables in MakeStreamBlock}
    if sptr and 3 = 0 then asm push ax; end;
  {$endif}
  i := 800*sose_blocklength;
  while kslen>=i do begin
    MakeStreamBlock(ctx, keystream, 800);
    inc(Ptr2Inc(keystream), i);
    dec(kslen,i);
  end;
  i := kslen div sose_blocklength;
  if i>0 then begin
    MakeStreamBlock(ctx, keystream, i);
    inc(Ptr2Inc(keystream),i*sose_blocklength);
    dec(kslen,i*sose_blocklength);
  end;
  if kslen>0 then begin
    {here 0 < kslen < sose_blocklength}
    MakeStreamBlock(ctx, TPSMBlockW(@tmp), 1);
    move(tmp,keystream^,integer(kslen));
  end;
end;


{---------------------------------------------------------------------------}
procedure sose_decrypt_bytes(var ctx: sose_ctx; ctp, ptp: pointer; msglen: longint);
  {-Bytewise decryption, msglen: message length in bytes}
begin
  sose_encrypt_bytes(ctx, ctp, ptp, msglen);
end;


{---------------------------------------------------------------------------}
procedure sose_encrypt_blocks(var ctx: sose_ctx; ptp, ctp: pointer; blocks: word);
  {-Blockwise encryption, blocks: length in 80 byte blocks}
begin
  sose_encrypt_bytes(ctx, ptp, ctp, longint(Blocks)*sose_blocklength);
end;


{---------------------------------------------------------------------------}
procedure sose_decrypt_blocks(var ctx: sose_ctx; ctp, ptp: pointer; blocks: word);
  {-Blockwise decryption, blocks: length in 80 byte blocks}
begin
  sose_encrypt_bytes(ctx, ctp, ptp, longint(Blocks)*sose_blocklength);
end;


{---------------------------------------------------------------------------}
procedure sose_encrypt_packet(var ctx: sose_ctx; IV, ptp, ctp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to  supply least 128 accessible IV bits.}
begin
  sose_ivsetup(ctx, iv);
  sose_encrypt_bytes(ctx, ptp, ctp, msglen);
end;


{---------------------------------------------------------------------------}
procedure sose_decrypt_packet(var ctx: sose_ctx; IV, ctp, ptp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to  supply least 128 accessible IV bits.}
begin
  sose_ivsetup(ctx, iv);
  sose_encrypt_bytes(ctx, ctp, ptp, msglen);
end;


{---------------------------------------------------------------------------}
procedure sose_keystream_blocks(var ctx: sose_ctx; keystream: pointer; blocks: word);
  {-Generate keystream, blocks: keystream length in 80 byte blocks}
begin
  {$ifdef BASM16}
    {dword align local variables in MakeStreamBlock}
    if sptr and 3 = 0 then asm push ax; end;
  {$endif}
  makeStreamBlock(ctx, keystream, Blocks);
end;


{---------------------------------------------------------------------------}
function sose_selftest: boolean;
  {-Simple self-test of Sosemanuk, detailed test vector 2 of eSTREAM submission}
const
  key: array[0.. 15] of byte = ($00,$11,$22,$33,$44,$55,$66,$77,$88,$99,$AA,$BB,$CC,$DD,$EE,$FF);
   IV: array[0.. 15] of byte = ($88,$99,$AA,$BB,$CC,$DD,$EE,$FF,$00,$11,$22,$33,$44,$55,$66,$77);
   ks: array[0..159] of byte = ($FA,$61,$DB,$EB,$71,$17,$81,$31,$A7,$7C,$71,$4B,$D2,$EA,$BF,$4E,
                                $13,$94,$20,$7A,$25,$69,$8A,$A1,$30,$8F,$2F,$06,$3A,$0F,$76,$06,
                                $04,$CF,$67,$56,$9B,$A5,$9A,$3D,$FA,$D7,$F0,$01,$45,$C7,$8D,$29,
                                $C5,$FF,$E5,$F9,$64,$95,$04,$86,$42,$44,$51,$95,$2C,$84,$03,$9D,
                                $23,$4D,$9C,$37,$EE,$CB,$BC,$A1,$EB,$FB,$0D,$D1,$6E,$A1,$19,$4A,
                                $6A,$FC,$1A,$46,$0E,$33,$E3,$3F,$E8,$D5,$5C,$48,$97,$70,$79,$C6,
                                $87,$81,$0D,$74,$FE,$DD,$EE,$1B,$39,$86,$21,$8F,$B1,$E1,$C1,$76,
                                $5E,$4D,$F6,$4D,$7F,$69,$11,$C1,$9A,$27,$0C,$59,$C7,$4B,$24,$46,
                                $17,$17,$F8,$6C,$E3,$B1,$18,$08,$FA,$CD,$4F,$2E,$71,$41,$68,$DA,
                                $44,$CF,$63,$60,$D5,$4D,$DA,$22,$41,$BC,$B7,$94,$01,$A4,$ED,$CC);
var
  ctx: sose_ctx;
  tmp: array[0..159] of byte;
  i,j,len:   integer;
begin
  sose_selftest := false;
  for j:=0 to 1 do begin
    len := sizeof(tmp);
    if j=1 then dec(len,27);
    {if j=1 then check the routines with msglen not a multiple of}
    {the blocksize, and that remaining bytes of tmp are untouched.}
    if sose_keysetup(ctx, @key, sizeof(key)*8) <> 0 then exit;
    fillchar(tmp, sizeof(tmp), 0);
    sose_ivsetup(ctx, @IV);
    sose_keystream_bytes(ctx, @tmp, len);
    for i:=0 to pred(len) do begin
      if tmp[i]<>ks[i] then exit;
    end;
    for i:=len to pred(sizeof(tmp)) do begin
      if tmp[i]<>0 then exit;
    end;
    fillchar(tmp, sizeof(tmp), 0);
    sose_ivsetup(ctx, @IV);
    sose_encrypt_bytes(ctx, @tmp, @tmp, len);
    for i:=0 to pred(len) do begin
      if tmp[i]<>ks[i] then exit;
    end;
    for i:=len to pred(sizeof(tmp)) do begin
      if tmp[i]<>0 then exit;
    end;
    fillchar(tmp, sizeof(tmp), 0);
    sose_encrypt_packet(ctx, @IV, @tmp, @tmp, len);
    for i:=0 to pred(len) do begin
      if tmp[i]<>ks[i] then exit;
    end;
    for i:=len to pred(sizeof(tmp)) do begin
      if tmp[i]<>0 then exit;
    end;
  end;
  sose_selftest := true;
end;

{$ifdef BASM16}
{$ifdef DebugAlign}
begin
  writeln('ofs(MulAlpha) and 3 = ', ofs(MulAlpha) and 3);
{$endif}
{$endif}

end.
