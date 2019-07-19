unit salsa20;

{Salsa20 stream cipher routines}


interface

{$i STD.INC}

{$ifdef BIT32}
  {.$define ChaChaBasm32}  {Use EddyHawk's BASM version of chacha_wordtobyte}
{$endif}


(*************************************************************************

 DESCRIPTION     :  Salsa20 stream cipher routines

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12/D17-D18, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  [1] Original version for ECRYPT Stream Cipher Project
                        http://www.ecrypt.eu.org/stream/ciphers/salsa20/salsa20.zip
                        http://www.ecrypt.eu.org/stream/ciphers/salsa20/salsa20source.zip
                    [2] salsa20,12,8-ref.c version 20060209, D.J. Bernstein, public domain
                        http://cr.yp.to/streamciphers/submissions.tar.gz
                    [3] Snuffle 2005: the Salsa20 encryption function:
                        http://cr.yp.to/snuffle.html
                    [4] D.J. Bernstein:  Extending the Salsa20 nonce, available via
                        http://cr.yp.to/papers.html#xsalsa, version used is
                        http://cr.yp.to/snuffle/xsalsa-20081128.pdf
                    [5] D.J. Bernstein: Cryptography in NaCl, available via
                        http://nacl.cr.yp.to/valid.html, version used is
                        http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
                    [6] D.J. Bernstein: ChaCha, a variant of Salsa20
                        http://cr.yp.to/chacha/chacha-20080128.pdf

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     22.02.06  W.Ehrhardt  Initial BP7 version, ABC layout, ref code
 0.11     23.02.06  we          improved wordtobyte, all compilers
 0.12     23.02.06  we          quarterround function with BASM
 0.13     26.02.06  we          8/12 rounds versions
 0.14     26.02.06  we          BIT32/BASM16 with BASM
 0.15     26.02.06  we          separate code for salsa_keystream_bytes
 0.16     26.02.06  we          salsa_keystream_bytes writes to keystream if possible
 0.17     26.02.06  we          optimized salsa_keysetup, salsa_keysetup256
 0.18     01.03.06  we          BASM16: salsa20_wordtobyte completely with basm
 0.19     04.03.06  we          BASM16: Make x in salsa20_wordtobyte dword aligned
 0.20     04.03.06  we          BASM16: removed dopush variable
 0.21     23.04.06  we          xkeysetup with keybits and rounds
 0.22     10.11.06  we          Corrected typo about IV size
 0.23     28.07.08  we          Default 12 rounds for 128 bit keys, 20 for 256
 0.24     23.11.08  we          Uses BTypes
 0.25     08.04.09  we          salsa20_wordtobyte with finaladd parameter
 0.26     09.04.09  we          XSalsa20 functions
 0.27     09.04.09  we          Clear context in XSalsa20 packet functions
 0.28     12.04.09  we          BASM16: encryption speed more than doubled
 0.29     13.04.09  we          Increased encryption speed for other compilers
 0.30     13.04.09  we          Special case FPC
 0.31     14.04.09  we          BASM16: encryption speed increased with 32 bit access
 0.32     15.04.09  we          Second pass in xsalsa_selftest with length <> blocksize

 0.33     12.03.10  EddyHawk    EddyHawk contributed functions: chacha20_wordtobyte,
                                chacha_ivsetup, chacha_ks, chacha_keystream_bytes
 0.34     12.03.10  we          ChaCha: Remove BASM16 push from chacha_keystream_bytes
 0.35     12.03.10  we          ChaCha: Allow even number of ChaCha rounds > 0
 0.36     12.03.10  we          ChaCha: 128 bit keys implemented
 0.37     12.03.10  we          ChaCha: Encrypt/Decrypt/Packets/Blocks
 0.38     13.03.10  we          new name: chacha_wordtobyte
 0.39     13.03.10  we          chacha_selftest, ChaCha URL

 0.40     02.05.12  EddyHawk    EddyHawk contributed BASM32 chacha_wordtobyte
 0.41     17.06.12  we          Added PurePascal 64-bit compatible salsa20_wordtobyte

 0.42     08.09.13  Martok      Martok contributed improved PurePascal chacha_wordtobyte
 0.43     29.09.13  we          BIT16: improved chacha_wordtobyte and chacha_encrypt_bytes

 0.44     26.08.15  we          Faster (reordered) PurePascal salsa20_wordtobyte

**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2006-2015 Wolfgang Ehrhardt

 Portions of ChaCha code (C) Copyright 2010/2012 EddyHawk
 Portions of ChaCha code (C) Copyright 2013      Martok

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
 Encryption/decryption of arbitrary length messages with Salsa20

 For efficiency reasons, the API provides two types of encrypt/decrypt
 functions. The salsa_encrypt_bytes function encrypts byte strings of
 arbitrary length, while the salsa_encrypt_blocks function only accepts
 lengths which are multiples of salsa_blocklength.

 The user is allowed to make multiple calls to salsa_encrypt_blocks to
 incrementally encrypt a long message, but he is NOT allowed to make
 additional encryption calls once he has called salsa_encrypt_bytes
 (unless he starts a new message of course). For example, this sequence
 of calls is acceptable:

   salsa_keysetup();

   salsa_ivsetup();
   salsa_encrypt_blocks();
   salsa_encrypt_blocks();
   salsa_encrypt_bytes();

   salsa_ivsetup();
   salsa_encrypt_blocks();
   salsa_encrypt_blocks();

   salsa_ivsetup();
   salsa_encrypt_bytes();

   The following sequence is not:

   salsa_keysetup();
   salsa_ivsetup();
   salsa_encrypt_blocks();
   salsa_encrypt_bytes();
   salsa_encrypt_blocks();



 XSalsa20 note:
 -------------
 Since the 192 bit nonce/IV is used (together with the primary 266 bit key)
 to derive the secondary working key, there are no separate key/IV setup
 functions and packet processing can be done without a user supplied context.


 ChaCha note:
 -----------
 ChaCha is a variant of Salsa with improved diffusion per round (and
 conjectured increased resistance to cryptanalysis). My implementation
 allows 128/256 bit keys and any even number of rounds > 0.
 **************************************************************************)


uses
  BTypes;

const
  salsa_blocklength = 64;                  {Block length in bytes}

type
  TSalsaBlk = array[0..15] of longint;

  {Structure containing the context of salsa20}
  salsa_ctx   = packed record
                  input : TSalsaBlk;       {internal state}
                  rounds: word;            {number of rounds}
                  kbits : word;            {number of key bits}
                end;


procedure salsa_keysetup(var ctx: salsa_ctx; key: pointer);
  {-Key setup, 128 bits of key^ are used, default rounds=12. It is the user's}
  { responsibility  to supply a pointer to at least 128 accessible key bits!}

procedure salsa_keysetup256(var ctx: salsa_ctx; key: pointer);
  {-Key setup, 256 bits of key^ are used, default rounds=20 It is the user's}
  { responsibility to supply a pointer to at least 256 accessible key bits!}

procedure salsa_xkeysetup(var ctx: salsa_ctx; key: pointer; keybits, rounds: word);
  {-Key setup, 128 bits of key^ are used if keybits<>256.. It is the user's }
  { responsibility to supply a pointer to at least 128 (resp 256) accessible}
  { key bits. If rounds not in [8,12,20], then rounds=20 will be used.}

procedure salsa_ivsetup(var ctx: salsa_ctx; IV: pointer);
  {-IV setup, 64 bits of IV^ are used. It is the user's responsibility to  }
  { supply least 64 accessible IV bits. After having called salsa_keysetup,}
  { the user is allowed to call salsa_ivsetup different times in order to  }
  { encrypt/decrypt different messages with the same key but different IV's}

procedure salsa_encrypt_bytes(var ctx: salsa_ctx; ptp, ctp: pointer; msglen: longint);
  {-Bytewise encryption, msglen: message length in bytes}

procedure salsa_encrypt_blocks(var ctx: salsa_ctx; ptp, ctp: pointer; blocks: word);
  {-Blockwise encrypt plainttext to ciphertext, blocks: length in 64 byte blocks}

procedure salsa_encrypt_packet(var ctx: salsa_ctx; IV, ptp, ctp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to supply least 64 accessible IV bits.}

procedure salsa_decrypt_bytes(var ctx: salsa_ctx; ctp, ptp: pointer; msglen: longint);
  {-Bytewise decryption, msglen: message length in bytes}

procedure salsa_decrypt_blocks(var ctx: salsa_ctx; ctp, ptp: pointer; blocks: word);
  {-Blockwise decryption, blocks: length in 64 byte blocks}

procedure salsa_decrypt_packet(var ctx: salsa_ctx; IV, ctp, ptp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to supply least 64 accessible IV bits.}

procedure salsa_keystream_bytes(var ctx: salsa_ctx; keystream: pointer; kslen: longint);
  {-Generate keystream, kslen: keystream length in bytes}

procedure salsa_keystream_blocks(var ctx: salsa_ctx; keystream: pointer; blocks: word);
  {-Generate keystream, blocks: keystream length in 64 byte blocks}

function  salsa_selftest: boolean;
  {-Simple self-test of Salsa20, tests 128/256 key bits and 8/12/20 rounds}


{---------------------------------------------------------------------------}
{----------------------  XSalsa20 functions  -------------------------------}
{---------------------------------------------------------------------------}

procedure xsalsa_setup(var ctx: salsa_ctx; key, IV: pointer);
  {-Key/IV setup, 256 bits of key^ and 192 bits of IV^ are used. It is the}
  { user's responsibility that the required bits are accessible! Rounds=20}

procedure xsalsa_encrypt_bytes(var ctx: salsa_ctx; ptp, ctp: pointer; msglen: longint);
  {-Bytewise encryption, msglen: message length in bytes}

procedure xsalsa_decrypt_bytes(var ctx: salsa_ctx; ctp, ptp: pointer; msglen: longint);
  {-Bytewise decryption, msglen: message length in bytes}

procedure xsalsa_encrypt_packet(key, IV, ptp, ctp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to supply least 192 accessible IV bits.}

procedure xsalsa_decrypt_packet(key, IV, ctp, ptp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to supply least 192 accessible IV bits.}

function  xsalsa_selftest: boolean;
  {-Simple self-test of XSalsa20}


{---------------------------------------------------------------------------}
{------------------------  ChaCha functions  -------------------------------}
{---------------------------------------------------------------------------}

{$ifdef ChaChaBasm32}
 {$ifndef BIT32}
  {$undef ChaChaBasm32}
 {$endif}
{$endif}

{$ifdef ChaChaBasm32}
const
  ChaChaBasm32 = true;
{$else}
const
  ChaChaBasm32 = false;
{$endif}

procedure chacha_xkeysetup(var ctx: salsa_ctx; key: pointer; keybits, rounds: word);
  {-Key setup, 128 bits of key^ are used if keybits<>256.. It is the user's }
  { responsibility to supply a pointer to at least 128 (resp 256) accessible}
  { key bits. Rounds should be even > 0 (will be forced)}

procedure chacha_keysetup(var ctx: salsa_ctx; key: pointer);
  {-Key setup, 128 bits of key^ are used, default rounds=12. It is the user's}
  { responsibility  to supply a pointer to at least 128 accessible key bits!}

procedure chacha_keysetup256(var ctx: salsa_ctx; key: pointer);
  {-Key setup, 256 bits of key^ are used, default rounds=20. It is the user's}
  { responsibility to supply a pointer to at least 256 accessible key bits!}

procedure chacha_ivsetup(var ctx: salsa_ctx; IV: pointer);
  {-IV setup, 64 bits of IV^ are used. It is the user's responsibility to  }
  { supply least 64 accessible IV bits. After having called salsa_keysetup,}
  { the user is allowed to call salsa_ivsetup different times in order to  }
  { encrypt/decrypt different messages with the same key but different IV's}

procedure chacha_encrypt_bytes(var ctx: salsa_ctx; ptp, ctp: pointer; msglen: longint);
  {-Bytewise encryption, msglen: message length in bytes}

procedure chacha_decrypt_bytes(var ctx: salsa_ctx; ctp, ptp: pointer; msglen: longint);
  {-Bytewise decryption, msglen: message length in bytes}

procedure chacha_encrypt_blocks(var ctx: salsa_ctx; ptp, ctp: pointer; blocks: word);
  {-Blockwise encryption, blocks: length in 64 byte blocks}

procedure chacha_decrypt_blocks(var ctx: salsa_ctx; ctp, ptp: pointer; blocks: word);
  {-Blockwise decryption, blocks: length in 64 byte blocks}

procedure chacha_encrypt_packet(var ctx: salsa_ctx; IV, ptp, ctp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to supply least 64 accessible IV bits.}

procedure chacha_decrypt_packet(var ctx: salsa_ctx; IV, ctp, ptp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to supply least 64 accessible IV bits.}

procedure chacha_keystream_bytes(var ctx: salsa_ctx; keystream: pointer; kslen: longint);
  {-Generate keystream, kslen: keystream length in bytes}

procedure chacha_keystream_blocks(var ctx: salsa_ctx; keystream: pointer; blocks: word);
  {-Generate keystream, blocks: keystream length in 64 byte blocks}

function  chacha_selftest: boolean;
  {-Simple self-test of ChaCha, tests 128/256 key bits and 8/12/20 rounds}


implementation


{$ifdef BIT16}
  {$F-}

  {$ifdef BASM16}
    (** TP6-7/D1 **)
    {---------------------------------------------------------------------------}
    function RotL(X: longint; c: word): longint;
    inline(
      $59/              {pop    cx     }
      $66/$58/          {pop    eax    }
      $66/$D3/$C0/      {rol    eax,cl }
      $66/$8B/$D0/      {mov    edx,eax}
      $66/$C1/$EA/$10); {shr    edx,16 }

  {$else}
    {** T5/5.5 **}
    {---------------------------------------------------------------------------}
    function RotL(X: longint; c: word): longint;
      {-Rotate left}
    inline(
      $59/           {  pop    cx    }
      $58/           {  pop    ax    }
      $5A/           {  pop    dx    }

      $83/$F9/$10/   {  cmp    cx,16 }
      $72/$06/       {  jb     S     }
      $92/           {  xchg   dx,ax }
      $83/$E9/$10/   {  sub    cx,16 }
      $74/$09/       {  je     X     }

      $2B/$DB/       {S:sub    bx,bx }
      $D1/$D0/       {L:rcl    ax,1  }
      $D1/$D2/       {  rcl    dx,1  }
      $13/$C3/       {  adc    ax,bx }
      $49/           {  dec    cx    }
      $75/$F7);      {  jne    L     }
                     {X:             }
  {$endif}
{$endif}

{Helper types}
type
  T4L  = array[0..3] of longint;
  P4L  = ^T4L;
  T8L  = array[0..7] of longint;
  P8L  = ^T8L;
  T32B = array[0..31] of byte;
  T64B = array[0..63] of byte;
  P64B = ^T64B;


const
  tau  : packed array[0..15] of char8 = 'expand 16-byte k';
  sigma: packed array[0..15] of char8 = 'expand 32-byte k';


{---------------------------------------------------------------------------}
procedure salsa_keysetup(var ctx: salsa_ctx; key: pointer);
  {-Key setup, 128 bits of key^ are used, default rounds=12. It is the user's}
  { responsibility to supply a pointer to at least 128 accessible key bits!}
begin
  with ctx do begin
    input[1]  := P8L(key)^[0];
    input[2]  := P8L(key)^[1];
    input[3]  := P8L(key)^[2];
    input[4]  := P8L(key)^[3];
    input[11] := input[1];
    input[12] := input[2];
    input[13] := input[3];
    input[14] := input[4];
    input[0]  := T4L(tau)[0];
    input[5]  := T4L(tau)[1];
    input[10] := T4L(tau)[2];
    input[15] := T4L(tau)[3];
    rounds    := 12;
    kbits     := 128;
  end;
end;


{---------------------------------------------------------------------------}
procedure salsa_keysetup256(var ctx: salsa_ctx; key: pointer);
  {-Key setup, 256 bits of key^ are used, default rounds=20 It is the user's}
  { responsibility to supply a pointer to at least 256 accessible key bits!}
begin
  with ctx do begin
    input[1]  := P8L(key)^[0];
    input[2]  := P8L(key)^[1];
    input[3]  := P8L(key)^[2];
    input[4]  := P8L(key)^[3];
    input[11] := P8L(key)^[4];
    input[12] := P8L(key)^[5];
    input[13] := P8L(key)^[6];
    input[14] := P8L(key)^[7];
    input[0]  := T4L(sigma)[0];
    input[5]  := T4L(sigma)[1];
    input[10] := T4L(sigma)[2];
    input[15] := T4L(sigma)[3];
    rounds    := 20;
    kbits     := 256;
  end;
end;


{---------------------------------------------------------------------------}
procedure salsa_xkeysetup(var ctx: salsa_ctx; key: pointer; keybits, rounds: word);
  {-Key setup, 128 bits of key^ are used if keybits<>256.. It is the user's }
  { responsibility to supply a pointer to at least 128 (resp 256) accessible}
  { key bits. If rounds not in [8,12,20], then rounds=20 will be used.}
begin
  if keybits=256 then salsa_keysetup256(ctx,key)
  else salsa_keysetup(ctx,key);
  if (rounds<>8) and (rounds<>12) then rounds := 20;
  ctx.rounds := rounds;
end;


{---------------------------------------------------------------------------}
procedure salsa_ivsetup(var ctx: salsa_ctx; IV: pointer);
  {-IV setup, 64 bits of IV^ are used. It is the user's responsibility to  }
  { supply least 64 accessible IV bits. After having called salsa_keysetup,}
  { the user is allowed to call salsa_ivsetup different times in order to  }
  { encrypt/decrypt different messages with the same key but different IV's}
begin
  with ctx do begin
    input[6] := P4L(IV)^[0];
    input[7] := P4L(IV)^[1];
    input[8] := 0;
    input[9] := 0;
  end;
end;


{$ifdef BIT64}
  {$define PurePascal}
{$endif}


{$ifdef PurePascal}
{---------------------------------------------------------------------------}
procedure salsa20_wordtobyte(var output: T64B; const input: TSalsaBlk; rounds: word; finaladd: boolean);
  {-This is the Salsa20 "hash" function}
var
  i: integer;
  y: longint;
  x: TSalsaBlk;
begin
  x := input;
{$ifdef OldOrder}
  for i:=1 to (rounds shr 1) do begin
    y := x[ 0] + x[12]; x[ 4] := x[ 4] xor ((y shl 07) or (y shr (32-07)));
    y := x[ 4] + x[ 0]; x[ 8] := x[ 8] xor ((y shl 09) or (y shr (32-09)));
    y := x[ 8] + x[ 4]; x[12] := x[12] xor ((y shl 13) or (y shr (32-13)));
    y := x[12] + x[ 8]; x[ 0] := x[ 0] xor ((y shl 18) or (y shr (32-18)));

    y := x[ 5] + x[ 1]; x[ 9] := x[ 9] xor ((y shl 07) or (y shr (32-07)));
    y := x[ 9] + x[ 5]; x[13] := x[13] xor ((y shl 09) or (y shr (32-09)));
    y := x[13] + x[ 9]; x[ 1] := x[ 1] xor ((y shl 13) or (y shr (32-13)));
    y := x[ 1] + x[13]; x[ 5] := x[ 5] xor ((y shl 18) or (y shr (32-18)));

    y := x[10] + x[ 6]; x[14] := x[14] xor ((y shl 07) or (y shr (32-07)));
    y := x[14] + x[10]; x[ 2] := x[ 2] xor ((y shl 09) or (y shr (32-09)));
    y := x[ 2] + x[14]; x[ 6] := x[ 6] xor ((y shl 13) or (y shr (32-13)));
    y := x[ 6] + x[ 2]; x[10] := x[10] xor ((y shl 18) or (y shr (32-18)));

    y := x[15] + x[11]; x[ 3] := x[ 3] xor ((y shl 07) or (y shr (32-07)));
    y := x[ 3] + x[15]; x[ 7] := x[ 7] xor ((y shl 09) or (y shr (32-09)));
    y := x[ 7] + x[ 3]; x[11] := x[11] xor ((y shl 13) or (y shr (32-13)));
    y := x[11] + x[ 7]; x[15] := x[15] xor ((y shl 18) or (y shr (32-18)));

    y := x[ 0] + x[ 3]; x[ 1] := x[ 1] xor ((y shl 07) or (y shr (32-07)));
    y := x[ 1] + x[ 0]; x[ 2] := x[ 2] xor ((y shl 09) or (y shr (32-09)));
    y := x[ 2] + x[ 1]; x[ 3] := x[ 3] xor ((y shl 13) or (y shr (32-13)));
    y := x[ 3] + x[ 2]; x[ 0] := x[ 0] xor ((y shl 18) or (y shr (32-18)));

    y := x[ 5] + x[ 4]; x[ 6] := x[ 6] xor ((y shl 07) or (y shr (32-07)));
    y := x[ 6] + x[ 5]; x[ 7] := x[ 7] xor ((y shl 09) or (y shr (32-09)));
    y := x[ 7] + x[ 6]; x[ 4] := x[ 4] xor ((y shl 13) or (y shr (32-13)));
    y := x[ 4] + x[ 7]; x[ 5] := x[ 5] xor ((y shl 18) or (y shr (32-18)));

    y := x[10] + x[ 9]; x[11] := x[11] xor ((y shl 07) or (y shr (32-07)));
    y := x[11] + x[10]; x[ 8] := x[ 8] xor ((y shl 09) or (y shr (32-09)));
    y := x[ 8] + x[11]; x[ 9] := x[ 9] xor ((y shl 13) or (y shr (32-13)));
    y := x[ 9] + x[ 8]; x[10] := x[10] xor ((y shl 18) or (y shr (32-18)));

    y := x[15] + x[14]; x[12] := x[12] xor ((y shl 07) or (y shr (32-07)));
    y := x[12] + x[15]; x[13] := x[13] xor ((y shl 09) or (y shr (32-09)));
    y := x[13] + x[12]; x[14] := x[14] xor ((y shl 13) or (y shr (32-13)));
    y := x[14] + x[13]; x[15] := x[15] xor ((y shl 18) or (y shr (32-18)));
  end;
{$else}
  for i:=1 to (rounds shr 1) do begin
    y := x[ 0] + x[12]; x[ 4] := x[ 4] xor ((y shl 07) or (y shr (32-07)));
    y := x[ 5] + x[ 1]; x[ 9] := x[ 9] xor ((y shl 07) or (y shr (32-07)));
    y := x[10] + x[ 6]; x[14] := x[14] xor ((y shl 07) or (y shr (32-07)));
    y := x[15] + x[11]; x[ 3] := x[ 3] xor ((y shl 07) or (y shr (32-07)));

    y := x[ 4] + x[ 0]; x[ 8] := x[ 8] xor ((y shl 09) or (y shr (32-09)));
    y := x[ 9] + x[ 5]; x[13] := x[13] xor ((y shl 09) or (y shr (32-09)));
    y := x[14] + x[10]; x[ 2] := x[ 2] xor ((y shl 09) or (y shr (32-09)));
    y := x[ 3] + x[15]; x[ 7] := x[ 7] xor ((y shl 09) or (y shr (32-09)));

    y := x[ 8] + x[ 4]; x[12] := x[12] xor ((y shl 13) or (y shr (32-13)));
    y := x[13] + x[ 9]; x[ 1] := x[ 1] xor ((y shl 13) or (y shr (32-13)));
    y := x[ 2] + x[14]; x[ 6] := x[ 6] xor ((y shl 13) or (y shr (32-13)));
    y := x[ 7] + x[ 3]; x[11] := x[11] xor ((y shl 13) or (y shr (32-13)));

    y := x[12] + x[ 8]; x[ 0] := x[ 0] xor ((y shl 18) or (y shr (32-18)));
    y := x[ 1] + x[13]; x[ 5] := x[ 5] xor ((y shl 18) or (y shr (32-18)));
    y := x[ 6] + x[ 2]; x[10] := x[10] xor ((y shl 18) or (y shr (32-18)));
    y := x[11] + x[ 7]; x[15] := x[15] xor ((y shl 18) or (y shr (32-18)));

    y := x[ 0] + x[ 3]; x[ 1] := x[ 1] xor ((y shl 07) or (y shr (32-07)));
    y := x[ 5] + x[ 4]; x[ 6] := x[ 6] xor ((y shl 07) or (y shr (32-07)));
    y := x[10] + x[ 9]; x[11] := x[11] xor ((y shl 07) or (y shr (32-07)));
    y := x[15] + x[14]; x[12] := x[12] xor ((y shl 07) or (y shr (32-07)));

    y := x[ 1] + x[ 0]; x[ 2] := x[ 2] xor ((y shl 09) or (y shr (32-09)));
    y := x[ 6] + x[ 5]; x[ 7] := x[ 7] xor ((y shl 09) or (y shr (32-09)));
    y := x[11] + x[10]; x[ 8] := x[ 8] xor ((y shl 09) or (y shr (32-09)));
    y := x[12] + x[15]; x[13] := x[13] xor ((y shl 09) or (y shr (32-09)));

    y := x[ 2] + x[ 1]; x[ 3] := x[ 3] xor ((y shl 13) or (y shr (32-13)));
    y := x[ 7] + x[ 6]; x[ 4] := x[ 4] xor ((y shl 13) or (y shr (32-13)));
    y := x[ 8] + x[11]; x[ 9] := x[ 9] xor ((y shl 13) or (y shr (32-13)));
    y := x[13] + x[12]; x[14] := x[14] xor ((y shl 13) or (y shr (32-13)));

    y := x[ 3] + x[ 2]; x[ 0] := x[ 0] xor ((y shl 18) or (y shr (32-18)));
    y := x[ 4] + x[ 7]; x[ 5] := x[ 5] xor ((y shl 18) or (y shr (32-18)));
    y := x[ 9] + x[ 8]; x[10] := x[10] xor ((y shl 18) or (y shr (32-18)));
    y := x[14] + x[13]; x[15] := x[15] xor ((y shl 18) or (y shr (32-18)));
  end;
{$endif}
  if finaladd then begin
    for i:=0 to 15 do TSalsaBlk(output)[i] := x[i] + input[i]
  end
  else TSalsaBlk(output) := x;
end;

{$else}

{$ifdef BIT32}

{---------------------------------------------------------------------------}
procedure salsa20_wordtobyte(var output: T64B; const input: TSalsaBlk; rounds: word; finaladd: boolean);
  {-This is the Salsa20 "hash" function}
var
  i: integer;
  x: TSalsaBlk;
begin
  x := input;
  asm
    push  ebx
    push  esi
    push  edi
    movzx edi,[rounds]
    shr   edi,1

     {round4(x[ 4], x[ 8], x[12], x[ 0]);}
  @@1: mov  eax,dword ptr x[ 4*4]
       mov  ebx,dword ptr x[ 8*4]
       mov  ecx,dword ptr x[12*4]
       mov  edx,dword ptr x[ 0*4]
       mov  esi,edx
       add  esi,ecx
       rol  esi,7
       xor  eax,esi
       mov  esi,eax
       add  esi,edx
       rol  esi,9
       xor  ebx,esi
       mov  esi,ebx
       add  esi,eax
       rol  esi,13
       xor  ecx,esi
       mov  esi,ecx
       add  esi,ebx
       rol  esi,18
       xor  edx,esi
       mov  dword ptr x[ 4*4],eax
       mov  dword ptr x[ 8*4],ebx
       mov  dword ptr x[12*4],ecx
       mov  dword ptr x[ 0*4],edx
     {round4(x[ 9], x[13], x[ 1], x[ 5]);}
       mov  eax,dword ptr x[ 9*4]
       mov  ebx,dword ptr x[13*4]
       mov  ecx,dword ptr x[ 1*4]
       mov  edx,dword ptr x[ 5*4]
       mov  esi,edx
       add  esi,ecx
       rol  esi,7
       xor  eax,esi
       mov  esi,eax
       add  esi,edx
       rol  esi,9
       xor  ebx,esi
       mov  esi,ebx
       add  esi,eax
       rol  esi,13
       xor  ecx,esi
       mov  esi,ecx
       add  esi,ebx
       rol  esi,18
       xor  edx,esi
       mov  dword ptr x[ 9*4],eax
       mov  dword ptr x[13*4],ebx
       mov  dword ptr x[ 1*4],ecx
       mov  dword ptr x[ 5*4],edx
     {round4(x[14], x[ 2], x[ 6], x[10]);}
       mov  eax,dword ptr x[14*4]
       mov  ebx,dword ptr x[ 2*4]
       mov  ecx,dword ptr x[ 6*4]
       mov  edx,dword ptr x[10*4]
       mov  esi,edx
       add  esi,ecx
       rol  esi,7
       xor  eax,esi
       mov  esi,eax
       add  esi,edx
       rol  esi,9
       xor  ebx,esi
       mov  esi,ebx
       add  esi,eax
       rol  esi,13
       xor  ecx,esi
       mov  esi,ecx
       add  esi,ebx
       rol  esi,18
       xor  edx,esi
       mov  dword ptr x[14*4],eax
       mov  dword ptr x[ 2*4],ebx
       mov  dword ptr x[ 6*4],ecx
       mov  dword ptr x[10*4],edx
     {round4(x[ 3], x[ 7], x[11], x[15]);}
       mov  eax,dword ptr x[ 3*4]
       mov  ebx,dword ptr x[ 7*4]
       mov  ecx,dword ptr x[11*4]
       mov  edx,dword ptr x[15*4]
       mov  esi,edx
       add  esi,ecx
       rol  esi,7
       xor  eax,esi
       mov  esi,eax
       add  esi,edx
       rol  esi,9
       xor  ebx,esi
       mov  esi,ebx
       add  esi,eax
       rol  esi,13
       xor  ecx,esi
       mov  esi,ecx
       add  esi,ebx
       rol  esi,18
       xor  edx,esi
       mov  dword ptr x[ 3*4],eax
       mov  dword ptr x[ 7*4],ebx
       mov  dword ptr x[11*4],ecx
       mov  dword ptr x[15*4],edx
     {round4(x[ 1], x[ 2], x[ 3], x[ 0]);}
       mov  eax,dword ptr x[ 1*4]
       mov  ebx,dword ptr x[ 2*4]
       mov  ecx,dword ptr x[ 3*4]
       mov  edx,dword ptr x[ 0*4]
       mov  esi,edx
       add  esi,ecx
       rol  esi,7
       xor  eax,esi
       mov  esi,eax
       add  esi,edx
       rol  esi,9
       xor  ebx,esi
       mov  esi,ebx
       add  esi,eax
       rol  esi,13
       xor  ecx,esi
       mov  esi,ecx
       add  esi,ebx
       rol  esi,18
       xor  edx,esi
       mov  dword ptr x[ 1*4],eax
       mov  dword ptr x[ 2*4],ebx
       mov  dword ptr x[ 3*4],ecx
       mov  dword ptr x[ 0*4],edx
     {round4(x[ 6], x[ 7], x[ 4], x[ 5]);}
       mov  eax,dword ptr x[ 6*4]
       mov  ebx,dword ptr x[ 7*4]
       mov  ecx,dword ptr x[ 4*4]
       mov  edx,dword ptr x[ 5*4]
       mov  esi,edx
       add  esi,ecx
       rol  esi,7
       xor  eax,esi
       mov  esi,eax
       add  esi,edx
       rol  esi,9
       xor  ebx,esi
       mov  esi,ebx
       add  esi,eax
       rol  esi,13
       xor  ecx,esi
       mov  esi,ecx
       add  esi,ebx
       rol  esi,18
       xor  edx,esi
       mov  dword ptr x[ 6*4],eax
       mov  dword ptr x[ 7*4],ebx
       mov  dword ptr x[ 4*4],ecx
       mov  dword ptr x[ 5*4],edx
     {round4(x[11], x[ 8], x[ 9], x[10]);}
       mov  eax,dword ptr x[11*4]
       mov  ebx,dword ptr x[ 8*4]
       mov  ecx,dword ptr x[ 9*4]
       mov  edx,dword ptr x[10*4]
       mov  esi,edx
       add  esi,ecx
       rol  esi,7
       xor  eax,esi
       mov  esi,eax
       add  esi,edx
       rol  esi,9
       xor  ebx,esi
       mov  esi,ebx
       add  esi,eax
       rol  esi,13
       xor  ecx,esi
       mov  esi,ecx
       add  esi,ebx
       rol  esi,18
       xor  edx,esi
       mov  dword ptr x[11*4],eax
       mov  dword ptr x[ 8*4],ebx
       mov  dword ptr x[ 9*4],ecx
       mov  dword ptr x[10*4],edx
     {round4(x[12], x[13], x[14], x[15]);}
       mov  eax,dword ptr x[12*4]
       mov  ebx,dword ptr x[13*4]
       mov  ecx,dword ptr x[14*4]
       mov  edx,dword ptr x[15*4]
       mov  esi,edx
       add  esi,ecx
       rol  esi,7
       xor  eax,esi
       mov  esi,eax
       add  esi,edx
       rol  esi,9
       xor  ebx,esi
       mov  esi,ebx
       add  esi,eax
       rol  esi,13
       xor  ecx,esi
       mov  esi,ecx
       add  esi,ebx
       rol  esi,18
       xor  edx,esi
       mov  dword ptr x[12*4],eax
       mov  dword ptr x[13*4],ebx
       mov  dword ptr x[14*4],ecx
       mov  dword ptr x[15*4],edx

       dec  edi
       jnz  @@1
    pop  edi
    pop  esi
    pop  ebx
  end;
  if finaladd then begin
    for i:=0 to 15 do TSalsaBlk(output)[i] := x[i] + input[i]
  end
  else TSalsaBlk(output) := x;
end;

{$else}

{$ifdef BASM16}

{---------------------------------------------------------------------------}
procedure salsa20_wordtobyte(var output: T64B; {$ifdef CONST} const {$else} var {$endif} input: TSalsaBlk;
                             rounds: word; finaladd: boolean);
  {-This is the Salsa20 "hash" function}
var
  x: TSalsaBlk;
begin
  {Remark; x should be dword align for optimized 32 bit access}
  {$ifdef Debug}
    if ofs(x) and 3 <>0 then begin
      writeln('ofs(x) and 3 <>0');
      halt;
    end;
  {$endif}
  asm
               push ds
               {x := input;}
               mov  ax,ss
               mov  es,ax
               cld
               lds  si,[input]
               lea  di,[x]
               mov  cx,salsa_blocklength shr 1
               rep  movsw

               mov  di,[rounds]
               shr  di,1

  @@1: db $66; mov  ax,word ptr x[ 4*4]
       db $66; mov  bx,word ptr x[ 8*4]
       db $66; mov  cx,word ptr x[12*4]
       db $66; mov  dx,word ptr x[ 0*4]
       db $66; mov  si,dx
       db $66; add  si,cx
       db $66; rol  si,7
       db $66; xor  ax,si
       db $66; mov  si,ax
       db $66; add  si,dx
       db $66; rol  si,9
       db $66; xor  bx,si
       db $66; mov  si,bx
       db $66; add  si,ax
       db $66; rol  si,13
       db $66; xor  cx,si
       db $66; mov  si,cx
       db $66; add  si,bx
       db $66; rol  si,18
       db $66; xor  dx,si
       db $66; mov  word ptr x[ 4*4],ax
       db $66; mov  word ptr x[ 8*4],bx
       db $66; mov  word ptr x[12*4],cx
       db $66; mov  word ptr x[ 0*4],dx
     {round4(x[ 9], x[13], x[ 1], x[ 5]);}
       db $66; mov  ax,word ptr x[ 9*4]
       db $66; mov  bx,word ptr x[13*4]
       db $66; mov  cx,word ptr x[ 1*4]
       db $66; mov  dx,word ptr x[ 5*4]
       db $66; mov  si,dx
       db $66; add  si,cx
       db $66; rol  si,7
       db $66; xor  ax,si
       db $66; mov  si,ax
       db $66; add  si,dx
       db $66; rol  si,9
       db $66; xor  bx,si
       db $66; mov  si,bx
       db $66; add  si,ax
       db $66; rol  si,13
       db $66; xor  cx,si
       db $66; mov  si,cx
       db $66; add  si,bx
       db $66; rol  si,18
       db $66; xor  dx,si
       db $66; mov  word ptr x[ 9*4],ax
       db $66; mov  word ptr x[13*4],bx
       db $66; mov  word ptr x[ 1*4],cx
       db $66; mov  word ptr x[ 5*4],dx
     {round4(x[14], x[ 2], x[ 6], x[10]);}
       db $66; mov  ax,word ptr x[14*4]
       db $66; mov  bx,word ptr x[ 2*4]
       db $66; mov  cx,word ptr x[ 6*4]
       db $66; mov  dx,word ptr x[10*4]
       db $66; mov  si,dx
       db $66; add  si,cx
       db $66; rol  si,7
       db $66; xor  ax,si
       db $66; mov  si,ax
       db $66; add  si,dx
       db $66; rol  si,9
       db $66; xor  bx,si
       db $66; mov  si,bx
       db $66; add  si,ax
       db $66; rol  si,13
       db $66; xor  cx,si
       db $66; mov  si,cx
       db $66; add  si,bx
       db $66; rol  si,18
       db $66; xor  dx,si
       db $66; mov  word ptr x[14*4],ax
       db $66; mov  word ptr x[ 2*4],bx
       db $66; mov  word ptr x[ 6*4],cx
       db $66; mov  word ptr x[10*4],dx
     {round4(x[ 3], x[ 7], x[11], x[15]);}
       db $66; mov  ax,word ptr x[ 3*4]
       db $66; mov  bx,word ptr x[ 7*4]
       db $66; mov  cx,word ptr x[11*4]
       db $66; mov  dx,word ptr x[15*4]
       db $66; mov  si,dx
       db $66; add  si,cx
       db $66; rol  si,7
       db $66; xor  ax,si
       db $66; mov  si,ax
       db $66; add  si,dx
       db $66; rol  si,9
       db $66; xor  bx,si
       db $66; mov  si,bx
       db $66; add  si,ax
       db $66; rol  si,13
       db $66; xor  cx,si
       db $66; mov  si,cx
       db $66; add  si,bx
       db $66; rol  si,18
       db $66; xor  dx,si
       db $66; mov  word ptr x[ 3*4],ax
       db $66; mov  word ptr x[ 7*4],bx
       db $66; mov  word ptr x[11*4],cx
       db $66; mov  word ptr x[15*4],dx
     {round4(x[ 1], x[ 2], x[ 3], x[ 0]);}
       db $66; mov  ax,word ptr x[ 1*4]
       db $66; mov  bx,word ptr x[ 2*4]
       db $66; mov  cx,word ptr x[ 3*4]
       db $66; mov  dx,word ptr x[ 0*4]
       db $66; mov  si,dx
       db $66; add  si,cx
       db $66; rol  si,7
       db $66; xor  ax,si
       db $66; mov  si,ax
       db $66; add  si,dx
       db $66; rol  si,9
       db $66; xor  bx,si
       db $66; mov  si,bx
       db $66; add  si,ax
       db $66; rol  si,13
       db $66; xor  cx,si
       db $66; mov  si,cx
       db $66; add  si,bx
       db $66; rol  si,18
       db $66; xor  dx,si
       db $66; mov  word ptr x[ 1*4],ax
       db $66; mov  word ptr x[ 2*4],bx
       db $66; mov  word ptr x[ 3*4],cx
       db $66; mov  word ptr x[ 0*4],dx
     {round4(x[ 6], x[ 7], x[ 4], x[ 5]);}
       db $66; mov  ax,word ptr x[ 6*4]
       db $66; mov  bx,word ptr x[ 7*4]
       db $66; mov  cx,word ptr x[ 4*4]
       db $66; mov  dx,word ptr x[ 5*4]
       db $66; mov  si,dx
       db $66; add  si,cx
       db $66; rol  si,7
       db $66; xor  ax,si
       db $66; mov  si,ax
       db $66; add  si,dx
       db $66; rol  si,9
       db $66; xor  bx,si
       db $66; mov  si,bx
       db $66; add  si,ax
       db $66; rol  si,13
       db $66; xor  cx,si
       db $66; mov  si,cx
       db $66; add  si,bx
       db $66; rol  si,18
       db $66; xor  dx,si
       db $66; mov  word ptr x[ 6*4],ax
       db $66; mov  word ptr x[ 7*4],bx
       db $66; mov  word ptr x[ 4*4],cx
       db $66; mov  word ptr x[ 5*4],dx
     {round4(x[11], x[ 8], x[ 9], x[10]);}
       db $66; mov  ax,word ptr x[11*4]
       db $66; mov  bx,word ptr x[ 8*4]
       db $66; mov  cx,word ptr x[ 9*4]
       db $66; mov  dx,word ptr x[10*4]
       db $66; mov  si,dx
       db $66; add  si,cx
       db $66; rol  si,7
       db $66; xor  ax,si
       db $66; mov  si,ax
       db $66; add  si,dx
       db $66; rol  si,9
       db $66; xor  bx,si
       db $66; mov  si,bx
       db $66; add  si,ax
       db $66; rol  si,13
       db $66; xor  cx,si
       db $66; mov  si,cx
       db $66; add  si,bx
       db $66; rol  si,18
       db $66; xor  dx,si
       db $66; mov  word ptr x[11*4],ax
       db $66; mov  word ptr x[ 8*4],bx
       db $66; mov  word ptr x[ 9*4],cx
       db $66; mov  word ptr x[10*4],dx
     {round4(x[12], x[13], x[14], x[15]);}
       db $66; mov  ax,word ptr x[12*4]
       db $66; mov  bx,word ptr x[13*4]
       db $66; mov  cx,word ptr x[14*4]
       db $66; mov  dx,word ptr x[15*4]
       db $66; mov  si,dx
       db $66; add  si,cx
       db $66; rol  si,7
       db $66; xor  ax,si
       db $66; mov  si,ax
       db $66; add  si,dx
       db $66; rol  si,9
       db $66; xor  bx,si
       db $66; mov  si,bx
       db $66; add  si,ax
       db $66; rol  si,13
       db $66; xor  cx,si
       db $66; mov  si,cx
       db $66; add  si,bx
       db $66; rol  si,18
       db $66; xor  dx,si
       db $66; mov  word ptr x[12*4],ax
       db $66; mov  word ptr x[13*4],bx
       db $66; mov  word ptr x[14*4],cx
       db $66; mov  word ptr x[15*4],dx

               dec  di
               jnz  @@1

               les  di,[output]

               mov  al,[finaladd]
               or   al,al
               jnz  @@2

               {No adding, move x to output}
               mov  ax,ss
               mov  ds,ax
               lea  si,[x]
               cld
               mov  cx,salsa_blocklength shr 1
               rep  movsw
               jmp  @@3

    @@2:       lds  si,[input]
       db $66; mov  ax,[si]
       db $66; add  ax,word ptr [x]
       db $66; mov  es:[di],ax

       db $66; mov  ax,[si+4]
       db $66; add  ax,word ptr [x+4]
       db $66; mov  es:[di+4],ax

       db $66; mov  ax,[si+8]
       db $66; add  ax,word ptr [x+8]
       db $66; mov  es:[di+8],ax

       db $66; mov  ax,[si+12]
       db $66; add  ax,word ptr [x+12]
       db $66; mov  es:[di+12],ax

       db $66; mov  ax,[si+16]
       db $66; add  ax,word ptr [x+16]
       db $66; mov  es:[di+16],ax

       db $66; mov  ax,[si+20]
       db $66; add  ax,word ptr [x+20]
       db $66; mov  es:[di+20],ax

       db $66; mov  ax,[si+24]
       db $66; add  ax,word ptr [x+24]
       db $66; mov  es:[di+24],ax

       db $66; mov  ax,[si+28]
       db $66; add  ax,word ptr [x+28]
       db $66; mov  es:[di+28],ax

       db $66; mov  ax,[si+32]
       db $66; add  ax,word ptr [x+32]
       db $66; mov  es:[di+32],ax

       db $66; mov  ax,[si+36]
       db $66; add  ax,word ptr [x+36]
       db $66; mov  es:[di+36],ax

       db $66; mov  ax,[si+40]
       db $66; add  ax,word ptr [x+40]
       db $66; mov  es:[di+40],ax

       db $66; mov  ax,[si+44]
       db $66; add  ax,word ptr [x+44]
       db $66; mov  es:[di+44],ax

       db $66; mov  ax,[si+48]
       db $66; add  ax,word ptr [x+48]
       db $66; mov  es:[di+48],ax

       db $66; mov  ax,[si+52]
       db $66; add  ax,word ptr [x+52]
       db $66; mov  es:[di+52],ax

       db $66; mov  ax,[si+56]
       db $66; add  ax,word ptr [x+56]
       db $66; mov  es:[di+56],ax

       db $66; mov  ax,[si+60]
       db $66; add  ax,word ptr [x+60]
       db $66; mov  es:[di+60],ax

    @@3:       pop  ds
  end;
end;

{$else}

{---------------------------------------------------------------------------}
procedure round4(var x1,x2,x3,x4: longint);
  {-quarter round function}
begin
  x1 := x1 xor RotL(x4 + x3,  7);
  x2 := x2 xor RotL(x1 + x4,  9);
  x3 := x3 xor RotL(x2 + x1, 13);
  x4 := x4 xor RotL(x3 + x2, 18);
end;


{---------------------------------------------------------------------------}
procedure salsa20_wordtobyte(var output: T64B; {$ifdef CONST} const {$else} var {$endif} input: TSalsaBlk;
                             rounds: word; finaladd: boolean);
var
  i: integer;
  x: TSalsaBlk;
begin
  x := input;
  for i:=1 to (rounds shr 1) do begin
    round4(x[ 4], x[ 8], x[12], x[ 0]);
    round4(x[ 9], x[13], x[ 1], x[ 5]);
    round4(x[14], x[ 2], x[ 6], x[10]);
    round4(x[ 3], x[ 7], x[11], x[15]);
    round4(x[ 1], x[ 2], x[ 3], x[ 0]);
    round4(x[ 6], x[ 7], x[ 4], x[ 5]);
    round4(x[11], x[ 8], x[ 9], x[10]);
    round4(x[12], x[13], x[14], x[15]);
  end;
  if finaladd then begin
    for i:=0 to 15 do TSalsaBlk(output)[i] := x[i] + input[i]
  end
  else TSalsaBlk(output) := x;
end;

{$endif BASM16}

{$endif BIT32}

{$endif Purepascal}

{---------------------------------------------------------------------------}
procedure salsa_encrypt_bytes(var ctx: salsa_ctx; ptp, ctp: pointer; msglen: longint);
  {-Bytewise encryption, msglen: message length in bytes}
var
  i: integer;
  output: T64B;
  im: integer;
begin
  {$ifdef BASM16}
    {Make x in salsa20_wordtobyte dword aligned for optimized 32 bit access}
    if (sptr and 3)=2 then asm push ax end;
  {$endif}
  while msglen>0 do begin
    salsa20_wordtobyte(output,ctx.input,ctx.rounds,true);
    {stopping at 2^70 bytes per nonce is user's responsibility}
    inc(ctx.input[8]);
    if ctx.input[8]=0 then inc(ctx.input[9]);
    if msglen<64 then im := integer(msglen) else im:=64;
    {$ifdef BASM16}
      {This was bottleneck in former versions, using stack addressing}
      {via ss:[bx] the  encryption speed more than doubled in V0.28+.}
      {Note that the 32 byte access may be unaligned and the latency }
      {will be increased, but AFAIK even then the code will be faster}
      {than a pure 8 bit access version. In the unlikely event that  }
      {the unaligned 32 bit access is too slow, remove the lines of  }
      {code from  'shr cx,2'  ... 'jz @@4'.}
      asm
                   push ds
                   lds  si,[ptp]
                   les  di,[ctp]
                   lea  bx,[output]
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
          pByte(ctp)^ := byte(ptp^) xor output[i];
          inc(Ptr2Inc(ptp));
          inc(Ptr2Inc(ctp));
        end;
      {$else}
        for i:=0 to pred(im) do P64B(ctp)^[i] := P64B(ptp)^[i] xor output[i];
        inc(Ptr2Inc(ptp),im);
        inc(Ptr2Inc(ctp),im);
      {$endif}
    {$endif}
    dec(msglen,64);
  end;
end;


{---------------------------------------------------------------------------}
procedure salsa_decrypt_bytes(var ctx: salsa_ctx; ctp, ptp: pointer; msglen: longint);
  {-Bytewise decryption, msglen: message length in bytes}
begin
  salsa_encrypt_bytes(ctx, ctp, ptp, msglen);
end;


{---------------------------------------------------------------------------}
procedure salsa_encrypt_blocks(var ctx: salsa_ctx; ptp, ctp: pointer; blocks: word);
  {-Blockwise encryption, blocks: length in 64 byte blocks}
begin
  salsa_encrypt_bytes(ctx, ptp, ctp, longint(Blocks)*salsa_blocklength);
end;


{---------------------------------------------------------------------------}
procedure salsa_decrypt_blocks(var ctx: salsa_ctx; ctp, ptp: pointer; blocks: word);
  {-Blockwise decryption, blocks: length in 64 byte blocks}
begin
  salsa_encrypt_bytes(ctx, ctp, ptp, longint(Blocks)*salsa_blocklength);
end;


{---------------------------------------------------------------------------}
procedure salsa_encrypt_packet(var ctx: salsa_ctx; IV, ptp, ctp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to supply least 64 accessible IV bits.}
begin
  salsa_ivsetup(ctx, iv);
  salsa_encrypt_bytes(ctx, ptp, ctp, msglen);
end;


{---------------------------------------------------------------------------}
procedure salsa_decrypt_packet(var ctx: salsa_ctx; IV, ctp, ptp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to supply least 64 accessible IV bits.}
begin
  salsa_ivsetup(ctx, iv);
  salsa_decrypt_bytes(ctx, ctp, ptp, msglen);
end;


{---------------------------------------------------------------------------}
procedure salsa_keystream_bytes(var ctx: salsa_ctx; keystream: pointer; kslen: longint);
  {-Generate keystream, kslen: keystream length in bytes}
var
  output: T64B;
begin
  {$ifdef BASM16}
    {Make x in salsa20_wordtobyte dword aligned for optimized 32 bit access}
    if (sptr and 3)=2 then asm push ax end;
  {$endif}
  {directly put salsa hash into keystream buffer as long as length is > 63}
  while kslen>63 do begin
    salsa20_wordtobyte(P64B(keystream)^,ctx.input,ctx.rounds,true);
    {stopping at 2^70 bytes per nonce is user's responsibility}
    inc(ctx.input[8]);  if ctx.input[8]=0 then inc(ctx.input[9]);
    inc(Ptr2Inc(keystream),64);
    dec(kslen,64);
  end;
  if kslen>0 then begin
    {here 0 < kslen < 64}
    salsa20_wordtobyte(output,ctx.input,ctx.rounds,true);
    {stopping at 2^70 bytes per nonce is user's responsibility}
    inc(ctx.input[8]); if ctx.input[8]=0 then inc(ctx.input[9]);
    move(output,keystream^,integer(kslen));
  end;
end;


{---------------------------------------------------------------------------}
procedure salsa_keystream_blocks(var ctx: salsa_ctx; keystream: pointer; blocks: word);
  {-Generate keystream, blocks: keystream length in 64 byte blocks}
begin
  salsa_keystream_bytes(ctx, keystream, longint(Blocks)*salsa_blocklength);
end;


{---------------------------------------------------------------------------}
function salsa_selftest: boolean;
  {-Simple self-test of Salsa20, tests 128/256 key bits and 8/12/20 rounds}
var
  i,idx,n,b,r: integer;
  key, iv: array[0..31] of byte;
  dig: array[0..15] of longint;
  buf: array[0..127] of longint;
  ctx: salsa_ctx;
const
  nround: array[0..2] of word = (8,12,20);
  kbits : array[0..1] of word = (128,256);
  {$ifdef StrictLong}
    {$warnings off}
    {$R-} {avoid D9 errors!}
  {$endif}
    XDT: array[0..5] of TSalsaBlk =
           (($52974958,$7b5774d1,$574b3efd,$0a6e5762,  {128_08}
             $14539c7d,$e2c520f3,$35c2cc5f,$482df540,
             $8ab98d4e,$1b4a74c2,$14578a78,$f7e8ba22,
             $a45978e5,$797443c4,$d988097f,$73dca011),
            ($2bfeb421,$1d24ef96,$ce8a0c54,$e84956b1,  {128_12}
             $42f8141f,$f7e56da8,$4811db9e,$ade63f0f,
             $558e7f81,$f7cdbe9a,$1e17fe34,$7cd2a9ae,
             $551937bb,$5522f4bf,$4976e50a,$9e564bd4),
            ($d274a2f7,$90673168,$58c07ea6,$2a0f5cf4,  {128_20}
             $fc997a06,$c03662de,$56e0f8ce,$4ce59f34,
             $74ac135f,$709553d2,$abfe34fd,$0572c506,
             $95b54939,$81217485,$2260a7a5,$d422fa3a),
            ($b6e5d149,$cb0a12af,$da7cdac4,$90dfa5f3,  {256_08}
             $d660fc0f,$ae58af71,$eb139fef,$5527182c,
             $aa05c1c7,$f3bb8639,$704dbef9,$e5a090a1,
             $0cd420c2,$0875361a,$e93097f7,$628c4700),
            ($60891461,$2e4546b8,$69cdd8b2,$1fce0aa8,  {256_12}
             $7f9673f3,$16a55bfe,$675b75f6,$b8089b66,
             $8dc136c0,$57a119a1,$05150d9c,$7210ccc4,
             $58b0119f,$8f0dd8af,$b1f46d26,$4ddf77f7),
            ($8524ec50,$9cb17d63,$9c5e796e,$80829373,  {256_20}
             $20b36d6f,$44043dfe,$d70767d5,$7f4556b4,
             $d7e8b33d,$75f35a06,$09a725a2,$74abc851,
             $95d5c44e,$f02552e8,$3fc02b8e,$6725c4e1));
  {$ifdef StrictLong}
    {$warnings on}
    {$ifdef RangeChecks_on}
      {$R+}
    {$endif}
  {$endif}

begin
  salsa_selftest := false;
  for b:=0 to 1 do begin
    {Loop over key bits (b=0: 128 bits, b=1: 256 bits)}
    for r := 0 to 2 do begin
      if b=1 then idx := r+3 else idx := r;
      {Use test data from Set 1, vector# 0}
      fillchar(key,sizeof(key),0);  key[0]:=$80;
      fillchar(IV, sizeof(IV) ,0);
      {Do 3 passes with different procedures}
      for n:=1 to 3 do begin
        fillchar(buf,sizeof(buf),0);
        fillchar(dig, sizeof(dig), 0);
        salsa_xkeysetup(ctx, @key,kbits[b] , nround[r]);
        case n of
          1: begin
               {test keystream blocks/bytes}
               salsa_ivsetup(ctx, @iv);
               salsa_keystream_blocks(ctx, @buf, 4);
               salsa_keystream_bytes (ctx, @buf[64], 256);
             end;
          2: begin
               {test encrypt blocks/bytes}
               salsa_ivsetup(ctx, @iv);
               salsa_encrypt_blocks(ctx, @buf, @buf, 4);
               salsa_encrypt_bytes (ctx, @buf[64], @buf[64],256);
             end;
          3: begin
               {test packet interface}
               salsa_encrypt_packet(ctx, @iv, @buf, @buf, 512);
             end;
        end;
        {calculate xor digest}
        for i:=0 to 127 do dig[i and 15] := dig[i and 15] xor buf[i];
        {compare with known answer, exit with false if any differences}
        for i:=0 to 15 do begin
          if dig[i]<>XDT[idx][i] then exit;
        end;
      end;
    end;
  end;
  salsa_selftest := true;
end;


{---------------------------------------------------------------------------}
{----------------------  XSalsa20 functions  -------------------------------}
{---------------------------------------------------------------------------}


{---------------------------------------------------------------------------}
procedure xsalsa_encrypt_bytes(var ctx: salsa_ctx; ptp, ctp: pointer; msglen: longint);
  {-Bytewise encryption, msglen: message length in bytes}
begin
  salsa_encrypt_bytes(ctx, ptp, ctp, msglen);
end;


{---------------------------------------------------------------------------}
procedure xsalsa_decrypt_bytes(var ctx: salsa_ctx; ctp, ptp: pointer; msglen: longint);
  {-Bytewise decryption, msglen: message length in bytes}
begin
  salsa_encrypt_bytes(ctx, ctp, ptp, msglen);
end;


{---------------------------------------------------------------------------}
function xsalsa_selftest: boolean;
  {-Simple self-test of xSalsa20}
const
  {From [5] p.39, Section "Testing: secretbox vs. onetimeauth"}
  key:   array[0..31] of byte = ($1b,$27,$55,$64,$73,$e9,$85,$d4,
                                 $62,$cd,$51,$19,$7a,$9a,$46,$c7,
                                 $60,$09,$54,$9e,$ac,$64,$74,$f2,
                                 $06,$c4,$ee,$08,$44,$f6,$83,$89);

  nonce: array[0..23] of byte = ($69,$69,$6e,$e9,$55,$b6,$2b,$73,
                                 $cd,$62,$bd,$a8,$75,$fc,$73,$d6,
                                 $82,$19,$e0,$03,$6b,$7a,$0b,$37);

  test:  array[0..31] of byte = ($ee,$a6,$a7,$25,$1c,$1e,$72,$91,
                                 $6d,$11,$c2,$cb,$21,$4d,$3c,$25,
                                 $25,$39,$12,$1d,$8e,$23,$4e,$65,
                                 $2d,$65,$1f,$a4,$c8,$cf,$f8,$80);
var
  tmp: array[0..31] of byte;
  i,j,len: integer;
begin
  xsalsa_selftest := false;
  for j:=0 to 1 do begin
    len := sizeof(test);
    if j=1 then dec(len,5);
    fillchar(tmp,sizeof(tmp),0);
    xsalsa_encrypt_packet(@key, @nonce, @tmp, @tmp, len);
    for i:=0 to pred(len) do begin
      if tmp[i]<>test[i] then exit;
    end;
    for i:=len to pred(sizeof(tmp)) do begin
      if tmp[i]<>0 then exit;
    end;
  end;
  xsalsa_selftest := true;
end;


{---------------------------------------------------------------------------}
procedure HSalsa(k256, n128: pointer; r: word; var res: T32B);
  {-Transform 256 key bits and 128 nonce bits into 256 res bits}
  { using r salsa rounds without final addition}
var
  input: TSalsaBlk;
begin
  input[1]  := P8L(k256)^[0];
  input[2]  := P8L(k256)^[1];
  input[3]  := P8L(k256)^[2];
  input[4]  := P8L(k256)^[3];
  input[11] := P8L(k256)^[4];
  input[12] := P8L(k256)^[5];
  input[13] := P8L(k256)^[6];
  input[14] := P8L(k256)^[7];
  input[0]  := T4L(sigma)[0];
  input[5]  := T4L(sigma)[1];
  input[10] := T4L(sigma)[2];
  input[15] := T4L(sigma)[3];
  input[6]  := P4L(n128)^[0];
  input[7]  := P4L(n128)^[1];
  input[8]  := P4L(n128)^[2];
  input[9]  := P4L(n128)^[3];
  {$ifdef BASM16}
    {Make x in salsa20_wordtobyte dword aligned for optimized 32 bit access}
    if (sptr and 3)=2 then asm push ax end;
  {$endif}
  salsa20_wordtobyte(T64b(input),input,r,false);
  T8L(res)[0] := input[ 0];
  T8L(res)[1] := input[ 5];
  T8L(res)[2] := input[10];
  T8L(res)[3] := input[15];
  T8L(res)[4] := input[ 6];
  T8L(res)[5] := input[ 7];
  T8L(res)[6] := input[ 8];
  T8L(res)[7] := input[ 9];
end;


{---------------------------------------------------------------------------}
procedure xsalsa_setup(var ctx: salsa_ctx; key, IV: pointer);
  {-Key/IV setup, 256 bits of key^ and 192 bits of IV^ are used. It is the}
  { user's responsibility that the required bits are accessible! Rounds=20}
var
  key2: T32B;
begin
  {HSalsa transforms the key, the sigma constant, and the first 128 bits}
  {of the IV/nonce into a secondary key key2. Key2 and the last  64 bits}
  {of the IV are used for a standard salsa20 key/IV setup with 20 rounds}
  HSalsa(key, IV, 20, key2);
  salsa_xkeysetup(ctx,@key2,256,20);
  salsa_ivsetup(ctx,@P8L(IV)^[4]);
end;


{---------------------------------------------------------------------------}
procedure xsalsa_encrypt_packet(key, IV, ptp, ctp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to supply least 192 accessible IV bits.}
var
  ctx: salsa_ctx;
begin
  xsalsa_setup(ctx, key, iv);
  salsa_encrypt_bytes(ctx, ptp, ctp, msglen);
  fillchar(ctx,sizeof(ctx),0);
end;


{---------------------------------------------------------------------------}
procedure xsalsa_decrypt_packet(key, IV, ctp, ptp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to supply least 192 accessible IV bits.}
var
  ctx: salsa_ctx;
begin
  xsalsa_setup(ctx, key, iv);
  salsa_decrypt_bytes(ctx, ctp, ptp, msglen);
  fillchar(ctx,sizeof(ctx),0);
end;



{---------------------------------------------------------------------------}
{------------------------  ChaCha functions  -------------------------------}
{---------------------------------------------------------------------------}


{---------------------------------------------------------------------------}
procedure chacha_xkeysetup(var ctx: salsa_ctx; key: pointer; keybits, rounds: word);
  {-Key setup, 128 bits of key^ are used if keybits<>256.. It is the user's }
  { responsibility to supply a pointer to at least 128 (resp 256) accessible}
  { key bits. Rounds should be even > 0 (will be forced)}
begin
  if rounds=0 then rounds := 2
  else if odd(rounds) then inc(rounds);
  ctx.rounds  := rounds;
  with ctx do begin
    input[4]  := P8L(key)^[0];
    input[5]  := P8L(key)^[1];
    input[6]  := P8L(key)^[2];
    input[7]  := P8L(key)^[3];
    if keybits=256 then begin
      input[8]  := P8L(key)^[4];
      input[9]  := P8L(key)^[5];
      input[10] := P8L(key)^[6];
      input[11] := P8L(key)^[7];
      input[0]  := T4L(sigma)[0];
      input[1]  := T4L(sigma)[1];
      input[2]  := T4L(sigma)[2];
      input[3]  := T4L(sigma)[3];
      kbits     := 256;
    end
    else begin
      input[8]  := input[4];
      input[9]  := input[5];
      input[10] := input[6];
      input[11] := input[7];
      input[0]  := T4L(tau)[0];
      input[1]  := T4L(tau)[1];
      input[2]  := T4L(tau)[2];
      input[3]  := T4L(tau)[3];
      kbits     := 128;
    end;
  end;
end;


{---------------------------------------------------------------------------}
procedure chacha_keysetup(var ctx: salsa_ctx; key: pointer);
  {-Key setup, 128 bits of key^ are used, default rounds=12. It is the user's}
  { responsibility  to supply a pointer to at least 128 accessible key bits!}
begin
  chacha_xkeysetup(ctx, key, 128, 12);
end;


{---------------------------------------------------------------------------}
procedure chacha_keysetup256(var ctx: salsa_ctx; key: pointer);
  {-Key setup, 256 bits of key^ are used, default rounds=20 It is the user's}
  { responsibility to supply a pointer to at least 256 accessible key bits!}
begin
  chacha_xkeysetup(ctx, key, 256, 20);
end;


{---------------------------------------------------------------------------}
procedure chacha_ivsetup(var ctx: salsa_ctx; IV: pointer);
  {-IV setup, 64 bits of IV^ are used. It is the user's responsibility to  }
  { supply least 64 accessible IV bits. After having called chacha_keysetup,}
  { the user is allowed to call chacha_ivsetup different times in order to  }
  { encrypt/decrypt different messages with the same key but different IV's}
begin
  with ctx do begin
    input[12] := 0;
    input[13] := 0;
    input[14] := P4L(IV)^[0];
    input[15] := P4L(IV)^[1];
  end;
end;


{$ifdef ChaChaBasm32}
{---------------------------------------------------------------------------}
procedure chacha_wordtobyte(var output: T64B; const input: TSalsaBlk; rounds: word; finaladd: boolean);
var
  i: integer;
  x: TSalsaBlk;
begin
  {Contributed by EddyHawk, Apr. 30, 2012}
  {WE June 2012: removed odd(rounds(}
  x := input;
  asm
       push  ebx
       push  edi
       movzx edi,[rounds]
       shr   edi,1

     {round4(x[ 0], x[ 4], x[ 8], x[12]);}
  @@1: mov  eax,dword ptr x[ 0*4]
       mov  ebx,dword ptr x[ 4*4]
       mov  ecx,dword ptr x[ 8*4]
       mov  edx,dword ptr x[12*4]
       add  eax,ebx
       xor  edx,eax
       rol  edx,16
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,12
       add  eax,ebx
       xor  edx,eax
       rol  edx,8
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,7
       mov  dword ptr x[ 0*4],eax
       mov  dword ptr x[ 4*4],ebx
       mov  dword ptr x[ 8*4],ecx
       mov  dword ptr x[12*4],edx
     {round4(x[ 1], x[ 5], x[ 9], x[13]);}
       mov  eax,dword ptr x[ 1*4]
       mov  ebx,dword ptr x[ 5*4]
       mov  ecx,dword ptr x[ 9*4]
       mov  edx,dword ptr x[13*4]
       add  eax,ebx
       xor  edx,eax
       rol  edx,16
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,12
       add  eax,ebx
       xor  edx,eax
       rol  edx,8
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,7
       mov  dword ptr x[ 1*4],eax
       mov  dword ptr x[ 5*4],ebx
       mov  dword ptr x[ 9*4],ecx
       mov  dword ptr x[13*4],edx
     {round4(x[ 2], x[ 6], x[10], x[14]);}
       mov  eax,dword ptr x[ 2*4]
       mov  ebx,dword ptr x[ 6*4]
       mov  ecx,dword ptr x[10*4]
       mov  edx,dword ptr x[14*4]
       add  eax,ebx
       xor  edx,eax
       rol  edx,16
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,12
       add  eax,ebx
       xor  edx,eax
       rol  edx,8
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,7
       mov  dword ptr x[ 2*4],eax
       mov  dword ptr x[ 6*4],ebx
       mov  dword ptr x[10*4],ecx
       mov  dword ptr x[14*4],edx
     {round4(x[ 3], x[ 7], x[11], x[15]);}
       mov  eax,dword ptr x[ 3*4]
       mov  ebx,dword ptr x[ 7*4]
       mov  ecx,dword ptr x[11*4]
       mov  edx,dword ptr x[15*4]
       add  eax,ebx
       xor  edx,eax
       rol  edx,16
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,12
       add  eax,ebx
       xor  edx,eax
       rol  edx,8
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,7
       mov  dword ptr x[ 3*4],eax
       mov  dword ptr x[ 7*4],ebx
       mov  dword ptr x[11*4],ecx
       mov  dword ptr x[15*4],edx
       {round4(x[ 0], x[ 5], x[10], x[15]);}
       mov  eax,dword ptr x[ 0*4]
       mov  ebx,dword ptr x[ 5*4]
       mov  ecx,dword ptr x[10*4]
       mov  edx,dword ptr x[15*4]
       add  eax,ebx
       xor  edx,eax
       rol  edx,16
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,12
       add  eax,ebx
       xor  edx,eax
       rol  edx,8
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,7
       mov  dword ptr x[ 0*4],eax
       mov  dword ptr x[ 5*4],ebx
       mov  dword ptr x[10*4],ecx
       mov  dword ptr x[15*4],edx
     {round4(x[ 1], x[ 6], x[11], x[12]);}
       mov  eax,dword ptr x[ 1*4]
       mov  ebx,dword ptr x[ 6*4]
       mov  ecx,dword ptr x[11*4]
       mov  edx,dword ptr x[12*4]
       add  eax,ebx
       xor  edx,eax
       rol  edx,16
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,12
       add  eax,ebx
       xor  edx,eax
       rol  edx,8
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,7
       mov  dword ptr x[ 1*4],eax
       mov  dword ptr x[ 6*4],ebx
       mov  dword ptr x[11*4],ecx
       mov  dword ptr x[12*4],edx
     {round4(x[ 2], x[ 7], x[ 8], x[13]);}
       mov  eax,dword ptr x[ 2*4]
       mov  ebx,dword ptr x[ 7*4]
       mov  ecx,dword ptr x[ 8*4]
       mov  edx,dword ptr x[13*4]
       add  eax,ebx
       xor  edx,eax
       rol  edx,16
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,12
       add  eax,ebx
       xor  edx,eax
       rol  edx,8
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,7
       mov  dword ptr x[ 2*4],eax
       mov  dword ptr x[ 7*4],ebx
       mov  dword ptr x[ 8*4],ecx
       mov  dword ptr x[13*4],edx
     {round4(x[ 3], x[ 4], x[ 9], x[14]);}
       mov  eax,dword ptr x[ 3*4]
       mov  ebx,dword ptr x[ 4*4]
       mov  ecx,dword ptr x[ 9*4]
       mov  edx,dword ptr x[14*4]
       add  eax,ebx
       xor  edx,eax
       rol  edx,16
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,12
       add  eax,ebx
       xor  edx,eax
       rol  edx,8
       add  ecx,edx
       xor  ebx,ecx
       rol  ebx,7
       mov  dword ptr x[ 3*4],eax
       mov  dword ptr x[ 4*4],ebx
       mov  dword ptr x[ 9*4],ecx
       mov  dword ptr x[14*4],edx

       dec  edi
       jnz  @@1
    pop  edi
    pop  ebx
  end;

  if finaladd then begin
    for i:=0 to 15 do TSalsaBlk(output)[i] := x[i] + input[i];
  end
  else TSalsaBlk(output) := x;
end;

{$else}

{$ifdef BIT16}
  {---------------------------------------------------------------------------}
  procedure chacha_wordtobyte(var output: T64B; {$ifdef CONST} const {$else} var {$endif} input: TSalsaBlk;
                              rounds: word; finaladd: boolean);
    {-This is the ChaCha "hash" function}
  var
    i: integer;
    x: TSalsaBlk;
  begin
    x := input;
    for i:=1 to (rounds shr 1) do begin
      x[ 0] := x[ 0]+x[ 4];   x[12] := RotL(x[12] xor x[ 0], 16);
      x[ 8] := x[ 8]+x[12];   x[ 4] := RotL(x[ 4] xor x[ 8], 12);
      x[ 0] := x[ 0]+x[ 4];   x[12] := RotL(x[12] xor x[ 0],  8);
      x[ 8] := x[ 8]+x[12];   x[ 4] := RotL(x[ 4] xor x[ 8],  7);

      x[ 1] := x[ 1]+x[ 5];   x[13] := RotL(x[13] xor x[ 1], 16);
      x[ 9] := x[ 9]+x[13];   x[ 5] := RotL(x[ 5] xor x[ 9], 12);
      x[ 1] := x[ 1]+x[ 5];   x[13] := RotL(x[13] xor x[ 1],  8);
      x[ 9] := x[ 9]+x[13];   x[ 5] := RotL(x[ 5] xor x[ 9],  7);

      x[ 2] := x[ 2]+x[ 6];   x[14] := RotL(x[14] xor x[ 2], 16);
      x[10] := x[10]+x[14];   x[ 6] := RotL(x[ 6] xor x[10], 12);
      x[ 2] := x[ 2]+x[ 6];   x[14] := RotL(x[14] xor x[ 2],  8);
      x[10] := x[10]+x[14];   x[ 6] := RotL(x[ 6] xor x[10],  7);

      x[ 3] := x[ 3]+x[ 7];   x[15] := RotL(x[15] xor x[ 3], 16);
      x[11] := x[11]+x[15];   x[ 7] := RotL(x[ 7] xor x[11], 12);
      x[ 3] := x[ 3]+x[ 7];   x[15] := RotL(x[15] xor x[ 3],  8);
      x[11] := x[11]+x[15];   x[ 7] := RotL(x[ 7] xor x[11],  7);

      x[ 0] := x[ 0]+x[ 5];   x[15] := RotL(x[15] xor x[ 0], 16);
      x[10] := x[10]+x[15];   x[ 5] := RotL(x[ 5] xor x[10], 12);
      x[ 0] := x[ 0]+x[ 5];   x[15] := RotL(x[15] xor x[ 0],  8);
      x[10] := x[10]+x[15];   x[ 5] := RotL(x[ 5] xor x[10],  7);

      x[ 1] := x[ 1]+x[ 6];   x[12] := RotL(x[12] xor x[ 1], 16);
      x[11] := x[11]+x[12];   x[ 6] := RotL(x[ 6] xor x[11], 12);
      x[ 1] := x[ 1]+x[ 6];   x[12] := RotL(x[12] xor x[ 1],  8);
      x[11] := x[11]+x[12];   x[ 6] := RotL(x[ 6] xor x[11],  7);

      x[ 2] := x[ 2]+x[ 7];   x[13] := RotL(x[13] xor x[ 2], 16);
      x[ 8] := x[ 8]+x[13];   x[ 7] := RotL(x[ 7] xor x[ 8], 12);
      x[ 2] := x[ 2]+x[ 7];   x[13] := RotL(x[13] xor x[ 2],  8);
      x[ 8] := x[ 8]+x[13];   x[ 7] := RotL(x[ 7] xor x[ 8],  7);

      x[ 3] := x[ 3]+x[ 4];   x[14] := RotL(x[14] xor x[ 3], 16);
      x[ 9] := x[ 9]+x[14];   x[ 4] := RotL(x[ 4] xor x[ 9], 12);
      x[ 3] := x[ 3]+x[ 4];   x[14] := RotL(x[14] xor x[ 3],  8);
      x[ 9] := x[ 9]+x[14];   x[ 4] := RotL(x[ 4] xor x[ 9],  7);
    end;

    if finaladd then begin
      for i:=0 to 15 do TSalsaBlk(output)[i] := x[i] + input[i];
    end
    else TSalsaBlk(output) := x;
  end;

{$else}

  {Improved PurePascal version contributed by Martok}

  {---------------------------------------------------------------------------}
  procedure chacha_wordtobyte(var output: T64B; const input: TSalsaBlk; rounds: word; finaladd: boolean);
    {-This is the ChaCha "hash" function}
  var
    i: integer;
    x: TSalsaBlk;
    a,b,c,d: longint;
  begin
    x := input;
    for i:= (rounds shr 1)-1 downto 0 do begin
      a := x[0];   b := x[4];      c := x[8];      d:= x[12];
      inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
      inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
      inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
      inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
      x[0] := a;   x[4] := b;      x[8] := c;      x[12] := d;

      a := x[1];   b := x[5];      c := x[9];      d := x[13];
      inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
      inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
      inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
      inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
      x[1] := a;   x[5] := b;      x[9] := c;      x[13] := d;

      a := x[2];   b := x[6];      c := x[10];     d := x[14];
      inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
      inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
      inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
      inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
      x[2] := a;   x[6] := b;      x[10] := c;     x[14] := d;

      a := x[3];   b := x[7];      c := x[11];     d := x[15];
      inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
      inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
      inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
      inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
      x[3] := a;   x[7] := b;      x[11] := c;     x[15] := d;

      a := x[0];   b := x[5];      c := x[10];     d := x[15];
      inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
      inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
      inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
      inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
      x[0] := a;   x[5] := b;      x[10] := c;     x[15] := d;

      a := x[1];   b := x[6];      c := x[11];     d := x[12];
      inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
      inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
      inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
      inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
      x[1] := a;   x[6] := b;      x[11] := c;     x[12] := d;

      a := x[2];   b := x[7];      c := x[8];      d := x[13];
      inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
      inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
      inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
      inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
      x[2] := a;   x[7] := b;      x[8] := c;      x[13] := d;

      a := x[3];   b := x[4];      c := x[9];      d := x[14];
      inc(a, b);   d := a xor d;   d := (d shl 16) or (d shr (32-16));
      inc(c, d);   b := c xor b;   b := (b shl 12) or (b shr (32-12));
      inc(a, b);   d := a xor d;   d := (d shl  8) or (d shr (32- 8));
      inc(c, d);   b := c xor b;   b := (b shl  7) or (b shr (32- 7));
      x[3] := a;   x[4] := b;      x[9] := c;      x[14] := d;
    end;

    if finaladd then begin
      for i:=0 to 15 do TSalsaBlk(output)[i] := x[i] + input[i];
    end
    else TSalsaBlk(output) := x;
  end;


{$endif}

{$endif}

{---------------------------------------------------------------------------}
procedure chacha_keystream_bytes(var ctx: salsa_ctx; keystream: pointer; kslen: longint);
  {-Generate keystream, kslen: keystream length in bytes}
var
  output: T64B;
begin
  {directly put ChaCha hash into keystream buffer as long as length is > 63}
  while kslen>63 do begin
    chacha_wordtobyte(P64B(keystream)^,ctx.input,ctx.rounds,true);
    {stopping at 2^70 bytes per nonce is user's responsibility}
    inc(ctx.input[12]);  if ctx.input[12]=0 then inc(ctx.input[13]);
    inc(Ptr2Inc(keystream),64);
    dec(kslen,64);
  end;
  if kslen>0 then begin
    {here 0 < kslen < 64}
    chacha_wordtobyte(output,ctx.input,ctx.rounds,true);
    {stopping at 2^70 bytes per nonce is user's responsibility}
    inc(ctx.input[12]); if ctx.input[12]=0 then inc(ctx.input[13]);
    move(output,keystream^,integer(kslen));
  end;
end;


{---------------------------------------------------------------------------}
procedure chacha_keystream_blocks(var ctx: salsa_ctx; keystream: pointer; blocks: word);
  {-Generate keystream, blocks: keystream length in 64 byte blocks}
begin
  chacha_keystream_bytes(ctx, keystream, longint(Blocks)*salsa_blocklength);
end;


{---------------------------------------------------------------------------}
procedure chacha_encrypt_bytes(var ctx: salsa_ctx; ptp, ctp: pointer; msglen: longint);
  {-Bytewise encryption, msglen: message length in bytes}
var
  i: integer;
  output: T64B;
  im: integer;
begin
  while msglen>0 do begin
    chacha_wordtobyte(output,ctx.input,ctx.rounds,true);
    {stopping at 2^70 bytes per nonce is user's responsibility}
    inc(ctx.input[12]);
    if ctx.input[12]=0 then inc(ctx.input[13]);
    if msglen<64 then im := integer(msglen) else im:=64;
    {Same code as for salsa_encrypt_bytes}
    {$ifdef BASM16}
      asm
                   push ds
                   lds  si,[ptp]
                   les  di,[ctp]
                   lea  bx,[output]
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
          pByte(ctp)^ := byte(ptp^) xor output[i];
          inc(Ptr2Inc(ptp));
          inc(Ptr2Inc(ctp));
        end;
      {$else}
        for i:=0 to pred(im) do P64B(ctp)^[i] := P64B(ptp)^[i] xor output[i];
        inc(Ptr2Inc(ptp),im);
        inc(Ptr2Inc(ctp),im);
      {$endif}
    {$endif}
    dec(msglen,64);
  end;
end;


{---------------------------------------------------------------------------}
procedure chacha_decrypt_bytes(var ctx: salsa_ctx; ctp, ptp: pointer; msglen: longint);
  {-Bytewise decryption, msglen: message length in bytes}
begin
  chacha_encrypt_bytes(ctx, ctp, ptp, msglen);
end;


{---------------------------------------------------------------------------}
procedure chacha_encrypt_blocks(var ctx: salsa_ctx; ptp, ctp: pointer; blocks: word);
  {-Blockwise encryption, blocks: length in 64 byte blocks}
begin
  chacha_encrypt_bytes(ctx, ptp, ctp, longint(Blocks)*salsa_blocklength);
end;


{---------------------------------------------------------------------------}
procedure chacha_decrypt_blocks(var ctx: salsa_ctx; ctp, ptp: pointer; blocks: word);
  {-Blockwise decryption, blocks: length in 64 byte blocks}
begin
  chacha_encrypt_bytes(ctx, ctp, ptp, longint(Blocks)*salsa_blocklength);
end;


{---------------------------------------------------------------------------}
procedure chacha_encrypt_packet(var ctx: salsa_ctx; IV, ptp, ctp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to supply least 64 accessible IV bits.}
begin
  chacha_ivsetup(ctx, iv);
  chacha_encrypt_bytes(ctx, ptp, ctp, msglen);
end;


{---------------------------------------------------------------------------}
procedure chacha_decrypt_packet(var ctx: salsa_ctx; IV, ctp, ptp: pointer; msglen: longint);
  {-All-in-one encryption of (short) packets, msglen: message length in bytes}
  { It is the user's responsibility to supply least 64 accessible IV bits.}
begin
  chacha_ivsetup(ctx, iv);
  chacha_decrypt_bytes(ctx, ctp, ptp, msglen);
end;


{---------------------------------------------------------------------------}
function chacha_selftest: boolean;
  {-Simple self-test of ChaCha, tests 128/256 key bits and 8/12/20 rounds}
var
  i,idx,n,b,r: integer;
  key, iv: array[0..31] of byte;
  dig: array[0..15] of longint;
  buf: array[0..127] of longint;
  ctx: salsa_ctx;
const
  nround: array[0..2] of word = (8,12,20);
  kbits : array[0..1] of word = (128,256);
  {$ifdef StrictLong}
    {$warnings off}
    {$R-} {avoid D9 errors!}
  {$endif}
    {values are the xor digests of test vectors calculated from}
    {D.J. Bernstein's code using Pelles C compiler V4.50.113}
    XDT: array[0..5] of TSalsaBlk =
          (($ab144dd2,$6096ceb8,$8e5e1a45,$46982857,   {128-8 }
            $db0b7c50,$4bd4e9ba,$9037934b,$d3679395,
            $3776fecd,$704a28e2,$da576cc0,$1991c0aa,
            $49700f6e,$bc637132,$8c1909d0,$1c050c47),
           ($14d18a20,$814fb9ad,$57ed7482,$d94ec55f,   {128-12}
            $08d815c7,$20622bad,$380ac73f,$0fad38b4,
            $229b3120,$a153a4ef,$7a4480c3,$699fa2b9,
            $e4258ea5,$8fb60398,$bf190487,$77c9107c),
           ($ada52ec6,$c396a0b1,$4c862266,$d817eb3c,   {128-20}
            $9defd2a9,$518ad675,$00d61cc6,$d0e439db,
            $9e49e47a,$82c5a29b,$28e79f10,$9c8db69a,
            $ea7d50fc,$7ab0f832,$0c27d877,$7a347541),
           ($39595f2c,$ec6bf171,$53bd4e78,$7a8593ec,   {256-8 }
            $157867e0,$1c31e951,$a52410d9,$0030d51b,
            $6f038346,$a1661f02,$e3ec6649,$1260100a,
            $033d4ba4,$0e81a71c,$c2d788fb,$648e42bd),
           ($8a8c7024,$fb2d1693,$4febc96d,$6ebfaa6d,   {256-12}
            $d2a1dfae,$078f704a,$616e7552,$cb747659,
            $862c2f43,$a35c51b5,$528c8489,$8900e0e5,
            $ee39abda,$738cd3a5,$0336faa4,$c7d28d39),
           ($96175f52,$fe56d50e,$ccf73266,$b941451e,   {256-20}
            $ad167609,$3271e81d,$47ff7821,$3940215d,
            $69b56bd5,$1f16e0d8,$0c228e23,$39aca058,
            $29740ec4,$c1ff6f62,$1366c412,$d8f9471e));
  {$ifdef StrictLong}
    {$warnings on}
    {$ifdef RangeChecks_on}
      {$R+}
    {$endif}
  {$endif}

begin
  chacha_selftest := false;
  for b:=0 to 1 do begin
    {Loop over key bits (b=0: 128 bits, b=1: 256 bits)}
    for r := 0 to 2 do begin
      if b=1 then idx := r+3 else idx := r;
      {Use test data from Set 1, vector# 0}
      fillchar(key,sizeof(key),0);  key[0]:=$80;
      fillchar(IV, sizeof(IV) ,0);
      {Do 3 passes with different procedures}
      for n:=1 to 3 do begin
        fillchar(buf,sizeof(buf),0);
        fillchar(dig, sizeof(dig), 0);
        chacha_xkeysetup(ctx, @key,kbits[b] , nround[r]);
        case n of
          1: begin
               {test keystream blocks/bytes}
               chacha_ivsetup(ctx, @iv);
               chacha_keystream_blocks(ctx, @buf, 4);
               chacha_keystream_bytes (ctx, @buf[64], 256);
             end;
          2: begin
               {test encrypt blocks/bytes}
               chacha_ivsetup(ctx, @iv);
               chacha_encrypt_blocks(ctx, @buf, @buf, 4);
               chacha_encrypt_bytes (ctx, @buf[64], @buf[64],256);
             end;
          3: begin
               {test packet interface}
               chacha_encrypt_packet(ctx, @iv, @buf, @buf, 512);
             end;
        end;
        {calculate xor digest}
        for i:=0 to 127 do dig[i and 15] := dig[i and 15] xor buf[i];
        {compare with known answer, exit with false if any differences}
        for i:=0 to 15 do begin
          if dig[i]<>XDT[idx][i] then exit;
        end;
      end;
    end;
  end;
  chacha_selftest := true;
end;


end.
