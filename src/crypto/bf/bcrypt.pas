unit bcrypt;

(*************************************************************************

 DESCRIPTION     :  bcrypt password hashing

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12/D17-D18, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 REMARKS         :  - Only version $2a$ is supported
                    - Passwords in BStrings should be UTF-8 encoded

 REFERENCES      :  - http://www.usenix.org/event/usenix99/provos/provos.pdf
                    - http://www.openbsd.org/papers/bcrypt-paper.ps
                    - Damien Miller's Java implementation jBCrypt-0.3 from
                      http://www.mindrot.org/projects/jBCrypt/

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     15.10.13  W.Ehrhardt  Expandkey, EksBlowfishSetup, CryptRaw
 0.11     16.10.13  we          encode_bsdbase64
 0.12     16.10.13  we          BFC_MakeDigest
 0.13     17.10.13  we          decode_bsdbase64
 0.14     17.10.13  we          D12+ string adjustments
 0.15     18.10.13  we          BFC_VerifyPassword
 0.16     19.10.13  we          BFC_Selftest
 0.17     19.10.13  we          bcrypt unit
 0.18     20.10.13  we          selftest level parameter
 0.19     20.10.13  we          All-in-one BFC_HashPassword
 0.20     20.10.13  we          TP5-6 const adjustments

**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2013 Wolfgang Ehrhardt

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


{$i STD.INC}


interface

uses
  BTypes, bf_base;

type
  TBCDigest = packed array[0..23] of byte;
  TBCSalt   = packed array[0..15] of byte;
  TBCKey    = packed array[0..55] of byte;

const
  BF_Err_Invalid_Cost  = -32;  {Cost factor not in [4..31]}
  BF_Err_Invalid_Hash  = -33;  {Invalid hash format}
  BF_Err_Verify_failed = -34;  {Password verification failed}

{$ifdef CONST}

function BFC_HashPassword(const password: Bstring; const salt: TBCSalt; cost: integer; var HashStr: BString): integer;
  {-Compute formatted bcrypt hash string from password, cost, salt}

function BFC_VerifyPassword(const password: Bstring; const HashStr: BString): integer;
  {-Verify password against formatted hash string, OK if result=0}

function BFC_Selftest(trace: boolean; level: integer): integer;
  {-Run selftest, return failed test nbr or 0; level 0..3: run tests with cost <= 2*level + 6}

function BFC_MakeDigest(const password: Bstring; const salt: TBCSalt; cost: integer; var hash: TBCDigest): integer;
  {-Get binary hash digest from salt, password/key, and cost}

function BFC_ParseStr(const HashStr: BString; var cost: integer; var salt: TBCSalt; var hash: TBCDigest): integer;
  {-Parse a formatted hash string: get cost, salt, binary hash digest; result=error code}

function BFC_FormatHash(cost: integer; const salt: TBCSalt; const digest: TBCDigest): BString;
  {-Get formatted hash string from cost, salt, and binary hash digest}

{$else}

function BFC_HashPassword(password: Bstring; var salt: TBCSalt; cost: integer; var HashStr: BString): integer;
  {-Compute formatted bcrypt hash string from password, cost, salt}

function BFC_VerifyPassword(password: Bstring; HashStr: BString): integer;
  {-Verify password against formatted hash string, OK if result=0}

function BFC_Selftest(trace: boolean; level: integer): integer;
  {-Run selftest, return failed test nbr or 0; level 0..3: run tests with cost <= 2*level + 6}

function BFC_MakeDigest(password: Bstring; var salt: TBCSalt; cost: integer; var hash: TBCDigest): integer;
  {-Get binary hash digest from salt, password/key, and cost}

function BFC_ParseStr(HashStr: BString; var cost: integer; var salt: TBCSalt; var hash: TBCDigest): integer;
  {-Parse a formatted hash string: get cost, salt, binary hash digest; result=error code}

function BFC_FormatHash(cost: integer; var salt: TBCSalt; var digest: TBCDigest): BString;
  {-Get formatted hash string from cost, salt, and binary hash digest}

{$endif}


implementation


{---------------------------------------------------------------------------}
function RB(A: longint): longint;
  {-reverse byte order in longint}
begin
  RB := ((A and $FF) shl 24) or ((A and $FF00) shl 8) or ((A and $FF0000) shr 8) or ((A and longint($FF000000)) shr 24);
end;


{---------------------------------------------------------------------------}
{$ifdef CONST}
function Expandkey(var ctx: TBFContext; const salt: TBCSalt; const key; len: integer): integer;
{$else}
function Expandkey(var ctx: TBFContext; var salt: TBCSalt; var key; len: integer): integer;
{$endif}
  {-Expensive key setup for Blowfish}
var
  i,j,k,h: integer;
  KL: longint;
  tmp: TBFBlock;
var
  KB: packed array[0..71] of byte absolute key;
begin
  if (len<1) or (len > 56) then begin
    Expandkey := BF_Err_Invalid_Key_Size;
    exit;
  end
  else Expandkey := 0;

  {Text explanations and comments are from the N.Provos & D.Mazieres paper.}

  {ExpandKey(state,salt,key) modifies the P-Array and S-boxes based on the }
  {value of the 128-bit salt and the variable length key. First XOR all the}
  {subkeys in the P-array with the encryption key. The first 32 bits of the}
  {key are XORed with P1, the next 32 bits with P2, and so on. The key is  }
  {viewed as being cyclic; when the process reaches the end of the key, it }
  {starts reusing bits from the beginning to XOR with subkeys.             }

  {WE: Same as standard key part except that PArray[i] is used for _bf_p[i]}
  k := 0;
  for i:=0 to 17 do begin
    KL := 0;
    for j:=0 to 3 do begin
      KL := (KL shl 8) or KB[k];
      inc(k);
      if k=len then k:=0;
    end;
    ctx.PArray[i] := ctx.PArray[i] xor KL;
  end;

  {Subsequently, ExpandKey blowfish-encrypts the first 64 bits of}
  {its salt argument using the current state of the key schedule.}
  BF_Encrypt(ctx, PBFBlock(@salt[0])^, tmp);

  {The resulting ciphertext replaces subkeys P_1 and P_2.}
  ctx.PArray[0] := RB(TBF2Long(tmp).L);
  ctx.PArray[1] := RB(TBF2Long(tmp).R);

  {That same ciphertext is also XORed with the second 64-bits of }
  {salt, and the result encrypted with the new state of the key  }
  {schedule. The output of the second encryption replaces subkeys}
  {P_3 and P_4. It is also XORed with the first 64-bits of salt  }
  {and encrypted to replace P_5 and P_6. The process continues,  }
  {alternating between the first and second 64 bits salt.        }
  h := 8;
  for i:=1 to 8 do begin
    BF_XorBlock(tmp, PBFBlock(@salt[h])^, tmp);
    h := h xor 8;
    BF_Encrypt(ctx, tmp, tmp);
    ctx.PArray[2*i]   := RB(TBF2Long(tmp).L);
    ctx.PArray[2*i+1] := RB(TBF2Long(tmp).R);
  end;

  {When ExpandKey finishes replacing entries in the P-Array, it continues}
  {on replacing S-box entries two at a time. After replacing the last two}
  {entries of the last S-box, ExpandKey returns the new key schedule.    }
  for j:=0 to 3 do begin
    for i:=0 to 127 do begin
      BF_XorBlock(tmp, PBFBlock(@salt[h])^, tmp);
      h := h xor 8;
      BF_Encrypt(ctx, tmp, tmp);
      ctx.SBox[j, 2*i]  := RB(TBF2Long(tmp).L);
      ctx.SBox[j, 2*i+1]:= RB(TBF2Long(tmp).R);
    end;
  end;
end;


{---------------------------------------------------------------------------}
{$ifdef CONST}
function EksBlowfishSetup(var ctx: TBFContext; const salt: TBCSalt; const key: TBCKey; klen, cost: integer): integer;
{$else}
function EksBlowfishSetup(var ctx: TBFContext; var salt: TBCSalt; var key: TBCKey; klen, cost: integer): integer;
{$endif}
  {-Expensive key schedule for Blowfish}
var
  i,rounds: longint;
  err: integer;
const
  zero: TBCSalt = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
begin
  if (cost<4) or (cost>31) then begin
    EksBlowfishSetup := BF_Err_Invalid_Cost;
    exit;
  end;

  {number of rounds = 2^cost, loop includes 0}
  if cost=31 then rounds := MaxLongint
  else rounds := (longint(1) shl cost) - 1;

  {Just copy the boxes into the context}
  BF_InitState(ctx);
  err := ExpandKey(ctx, salt, key, klen);
  EksBlowfishSetup := err;
  if err<>0 then exit;

  {This is the time consuming part}
  for i:=rounds downto 0 do begin
    err := ExpandKey(ctx, zero, key,  klen);
    if err=0 then err := ExpandKey(ctx, zero, salt, 16);
    if err<>0 then begin
      EksBlowfishSetup := err;
      exit;
    end;
  end;
end;


{---------------------------------------------------------------------------}
{$ifdef CONST}
function CryptRaw(const salt: TBCSalt; const key: TBCKey; klen, cost: integer; var digest: TBCDigest): integer;
{$else}
function CryptRaw(var salt: TBCSalt; var key: TBCKey; klen, cost: integer; var digest: TBCDigest): integer;
{$endif}
  {-Raw bcrypt function: get binary hash digest from salt, key, and cost}
var
  i, err: integer;
  ctx: TBFContext;
const
  ctext: TBCDigest = ($4F,$72,$70,$68,$65,$61,$6E,$42, {'OrpheanBeholderScryDoubt'}
                      $65,$68,$6F,$6C,$64,$65,$72,$53,
                      $63,$72,$79,$44,$6F,$75,$62,$74);
begin
  {Expensive key schedule for Blowfish}
  err := EksBlowfishSetup(ctx,salt,key,klen,cost);
  CryptRaw := err;
  if err<>0 then exit;
  digest := ctext;
  {Encrypt the magic initialisation text 64 times using ECB mode}
  for i:=1 to 64 do begin
    {could be replaced with one call to BF_ECB_Encrypt from unit BF_ECB}
    BF_Encrypt(ctx, PBFBlock(@digest[ 0])^, PBFBlock(@digest[ 0])^);
    BF_Encrypt(ctx, PBFBlock(@digest[ 8])^, PBFBlock(@digest[ 8])^);
    BF_Encrypt(ctx, PBFBlock(@digest[16])^, PBFBlock(@digest[16])^);
    CryptRaw := err;
    if err<>0 then exit;
  end;
end;


{---------------------------------------------------------------------------}
{$ifdef CONST}
function BFC_MakeDigest(const password: Bstring; const salt: TBCSalt; cost: integer; var hash: TBCDigest): integer;
{$else}
function BFC_MakeDigest(password: Bstring; var salt: TBCSalt; cost: integer; var hash: TBCDigest): integer;
{$endif}
  {-Get binary hash digest from salt, password/key, and cost}
var
  key: TBCKey;
  len: Integer;
begin
  len := length(password);
  if len > 55 then len := 55;
  if len > 0 then Move(Password[1], key[0], len);
  key[len] := 0;
  BFC_MakeDigest := CryptRaw(salt, key, len+1, cost, hash);
end;


{---------------------------------------------------------------------------}
function encode_bsdbase64(psrc: pointer; len: integer): BString;
  {-BSD type base64 string from memory block of length len pointed by psrc}
const
  CT64: array[0..63] of char8 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
var
  c1,c2: word;
  bs: BString;
begin
  bs := '';
  if psrc<>nil then begin
    while len>0 do begin
      c1 := pByte(psrc)^;  inc(Ptr2Inc(psrc)); dec(len);
      bs := bs + CT64[(c1 shr 2) and $3f];
      c1 := (c1 and $03) shl 4;
      if len<=0 then bs := bs + CT64[c1 and $3f]
      else begin
        c2 := pByte(psrc)^; inc(Ptr2Inc(psrc)); dec(len);
        c1 := c1 or ((c2 shr 4) and $0f);
        bs := bs + CT64[c1 and $3f];
        c1 := (c2 and $0f) shl 2;
        if len<=0 then bs := bs + CT64[c1 and $3f]
        else begin
          c2 := pByte(psrc)^; inc(Ptr2Inc(psrc)); dec(len);
          c1 := c1 or ((c2 shr 6) and $03);
          bs := bs + CT64[c1 and $3f] + CT64[c2 and $3f];
        end;
      end;
    end;
  end;
  encode_bsdbase64 := bs;
end;


{---------------------------------------------------------------------------}
procedure decode_bsdbase64(psrc,pdest: pointer; lsrc,ldest: integer; var LA: integer);
  {-Decode lsrc chars from psrc, write to pdest max ldest bytes, LA bytes deocoded}
const
  BT: array[#0..#127] of shortint = (
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,  0,  1,
        54, 55, 56, 57, 58, 59, 60, 61, 62, 63, -1, -1, -1, -1, -1, -1,
        -1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, -1, -1, -1, -1, -1,
        -1, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
        43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, -1, -1, -1, -1, -1);

  function getc: integer;
    {-Get next char from psrc, convert to integer, dec lsrc, inc psrc}
  var
    c: char8;
  begin
    getc := -1;
    if lsrc>0 then begin
      c := pchar8(psrc)^;
      inc(Ptr2Inc(psrc));
      dec(lsrc);
      if ord(c)<128 then getc := BT[c];
    end;
  end;

  procedure putb(b: integer);
    {-Put next byte into pdest if LA<ldest, inc LA and pdest}
  begin
    if LA<ldest then begin
      inc(LA);
      pByte(pdest)^ := byte(b and $ff);
      inc(Ptr2Inc(pdest));
    end;
  end;

var
  c1,c2,c3,c4: integer;
begin
  LA := 0;
  if (psrc=nil) or (pdest=nil) or (ldest<1) or (lsrc<1) then exit;
  while lsrc>0 do begin
    c1 := getc; if c1<0 then exit;
    c2 := getc; if c2<0 then exit;
    putb(((c1 and $3f) shl 2) or (c2 shr 4));

    c3 := getc; if c3<0 then exit;
    putb(((c2 and $0f) shl 4) or (c3 shr 2));

    c4 := getc; if c4<0 then exit;
    putb(((c3 and $03) shl 6) or c4);
  end;
end;


{---------------------------------------------------------------------------}
{$ifdef CONST}
function BFC_FormatHash(cost: integer; const salt: TBCSalt; const digest: TBCDigest): BString;
{$else}
function BFC_FormatHash(cost: integer; var salt: TBCSalt; var digest: TBCDigest): BString;
{$endif}
  {-Get formatted hash string from cost, salt, and binary hash digest}
var
  sh: Bstring;
begin
  BFC_FormatHash := '';
  if (cost<4) or (cost>31) then exit;
  {$ifdef D12Plus}
    sh := BString('$2a$');
  {$else}
    sh := '$2a$';
  {$endif}
  sh := sh + char8(ord('0')+cost div 10)+char8(ord('0')+cost mod 10) + '$';
  sh := sh + encode_bsdbase64(@salt, sizeof(salt))
           + encode_bsdbase64(@digest, sizeof(digest) - 1);  {Note the -1!!!!!}
  BFC_FormatHash := sh;
end;


{---------------------------------------------------------------------------}
{$ifdef CONST}
function BFC_HashPassword(const password: Bstring; const salt: TBCSalt; cost: integer; var HashStr: BString): integer;
{$else}
function BFC_HashPassword(password: Bstring; var salt: TBCSalt; cost: integer; var HashStr: BString): integer;
{$endif}
  {-Compute formatted bcrypt hash string from password, cost, salt}
var
  hash: TBCDigest;
  err: integer;
begin
  err := BFC_MakeDigest(password, salt, cost, hash);
  BFC_HashPassword := err;
  if err<>0 then HashStr := ''
  else HashStr := BFC_FormatHash(cost, salt, hash);
end;


{---------------------------------------------------------------------------}
{$ifdef CONST}
function BFC_ParseStr(const HashStr: BString; var cost: integer; var salt: TBCSalt; var hash: TBCDigest): integer;
{$else}
function BFC_ParseStr(HashStr: BString; var cost: integer; var salt: TBCSalt; var hash: TBCDigest): integer;
{$endif}
  {-Parse a formatted hash string: get cost, salt, binary hash digest; result=error code}
var
  LA: integer;
  d0,d1: integer;
begin
{ 123456789012345678901234567890123456789012345678901234567890
  $2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q
         1234567890123456789012
                               1234567890123456789012345678901}
  BFC_ParseStr := BF_Err_Invalid_Hash;
  if length(HashStr)<>60 then exit;
  if (HashStr[1]<>'$') or (HashStr[4]<>'$') or (HashStr[7]<>'$') then exit;
  if (HashStr[2]<>'2') or (HashStr[3]<>'a') then exit;
  decode_bsdbase64(@HashStr[8], @salt[0], 22, sizeof(salt),LA);
  if LA<>sizeof(salt) then exit;
  decode_bsdbase64(@HashStr[30], @hash[0], 31, sizeof(hash),LA);
  if LA<>sizeof(hash)-1 then exit;
  d0 := ord(HashStr[6])-48;
  d1 := ord(HashStr[5])-48;
  cost := 10*d1+d0;
  if (d1<0) or (d1>9) or (d1<0) or (d1>3) or (cost<4) or (cost>31) then begin
    BFC_ParseStr := BF_Err_Invalid_Cost;
  end
  else BFC_ParseStr := 0;
end;


{---------------------------------------------------------------------------}
{$ifdef CONST}
function BFC_VerifyPassword(const password: Bstring; const HashStr: BString): integer;
{$else}
function BFC_VerifyPassword(password: Bstring; HashStr: BString): integer;
{$endif}
  {-Verify password against formatted hash string, OK if result=0}
var
  cost,err: integer;
  salt: TBCSalt;
  digest: TBCDigest;
  NewHashStr: BString;
begin
  err := BFC_ParseStr(HashStr,cost,salt,digest);
  if err<>0 then begin
    BFC_VerifyPassword := err;
    exit;
  end;
  err := BFC_MakeDigest(password, salt, cost, digest);
  if err<>0 then begin
    BFC_VerifyPassword := err;
    exit;
  end;
  NewHashStr := BFC_FormatHash(cost, salt, digest);
  if NewHashStr<>HashStr then begin
    BFC_VerifyPassword := BF_Err_Verify_failed;
    exit;
  end
  else BFC_VerifyPassword := 0;
end;


{-------------------------------------------------------------------------}
{ Test vectors are from Damien Miller's Java implementation jBCrypt-0.3:  }

{ Copyright (c) 2006 Damien Miller <djm@mindrot.org>                      }
{                                                                         }
{ Permission to use, copy, modify, and distribute this software for any   }
{ purpose with or without fee is hereby granted, provided that the above  }
{ copyright notice and this permission notice appear in all copies.       }
{                                                                         }
{ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES}
{ WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF        }
{ MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR }
{ ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES  }
{ WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN   }
{ ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF }
{ OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.          }


{---------------------------------------------------------------------------}
function BFC_Selftest(trace: boolean; level: integer): integer;
  {-Run selftest, return failed test nbr or 0; level 0..3: run tests with cost <= 2*level + 6}
type
  TPair = record
            pn: byte;
            bs: string[60];
          end;
const
  PW: array[0..4] of string[40] = ('', 'a', 'abc',
         'abcdefghijklmnopqrstuvwxyz', '~!@#$%^&*()      ~!@#$%^&*()PNBFRD');
const
  test: array[1..20] of TPair = (
          (pn: 0; bs: '$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.'),
          (pn: 0; bs: '$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye'),
          (pn: 0; bs: '$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW'),
          (pn: 0; bs: '$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO'),
          (pn: 1; bs: '$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe'),
          (pn: 1; bs: '$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V.'),
          (pn: 1; bs: '$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u'),
          (pn: 1; bs: '$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS'),
          (pn: 2; bs: '$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i'),
          (pn: 2; bs: '$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm'),
          (pn: 2; bs: '$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi'),
          (pn: 2; bs: '$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q'),
          (pn: 3; bs: '$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC'),
          (pn: 3; bs: '$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz.'),
          (pn: 3; bs: '$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq'),
          (pn: 3; bs: '$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG'),
          (pn: 4; bs: '$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO'),
          (pn: 4; bs: '$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW'),
          (pn: 4; bs: '$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS'),
          (pn: 4; bs: '$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC'));
var
  i: integer;
begin
  for i:=1 to 20 do begin
    if (i-1) and 3 < level then begin
      if trace then write('.');
      if BFC_VerifyPassword(PW[test[i].pn], test[i].bs)<>0 then begin
        BFC_Selftest := i;
        exit;
      end;
    end;
  end;
  BFC_Selftest := 0;
end;

end.

