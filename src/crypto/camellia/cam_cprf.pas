unit cam_cprf;

{Variable-length key Camellia CMAC Pseudo-Random Function-128}

{$i STD.INC}

interface

uses
  CAM_Base, CAM_OMAC;


(*************************************************************************

 DESCRIPTION   : Variable-length key  Camellia CMAC Pseudo-Random Function-128

 REQUIREMENTS  : TP5-7, D1-D7/D9-D10, FPC, VP

 EXTERNAL DATA : ---

 MEMORY USAGE  : ---

 DISPLAY MODE  : ---

 REFERENCES    : [1]  The Camellia-CMAC-96 and Camellia-CMAC-PRF-128 Algorithms
                      and Its Use with IPsec, available from
                      http://tools.ietf.org/html/draft-kato-ipsec-camellia-cmac96and128-02}


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     17.06.08  W.Ehrhardt  Initial version analog aes_cprf
**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2008 Wolfgang Ehrhardt

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


function CAM_CPRF128({$ifdef CONST} const {$else} var {$endif} Key; KeyBytes: word;
                     msg: pointer; msglen: longint; var PRV: TCAMBlock): integer;
  {-Calculate variable-length key Camellia CMAC Pseudo-Random Function-128 for msg}
  { returns CAM_OMAC error and 128-bit pseudo-random value PRV}
  {$ifdef DLL} stdcall; {$endif}

function CAM_CPRF128_selftest: boolean;
  {-Selftest with ipsec-camellia-cmac96and128 test vectors}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
function CAM_CPRF128({$ifdef CONST} const {$else} var {$endif} Key; KeyBytes: word;
                     msg: pointer; msglen: longint; var PRV: TCAMBlock): integer;
  {-Calculate variable-length key Camellia CMAC Pseudo-Random Function-128 for msg}
  { returns CAM_OMAC error and 128-bit pseudo-random value PRV}
var
  LK : TCAMBlock;    {local 128 bit key}
  ctx: TCAMContext;
  err: integer;
const
  ZB: TCAMBlock = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
begin
  if KeyBytes=16 then begin
    {If the key, is exactly 128 bits, then we use it as-is (copy to local)}
    move(Key, LK, 16);
    err := 0;
  end
  else begin
    {If key length is not 128 bits, then we derive the local key LK by
    applying the CAM-CMAC algorithm using a 128-bit zero as the CMAC key
    and Key as the input message: LK := CAM-CMAC(0, Key, KeyBytes)}
    err := CAM_OMAC_Init(ZB, 128, ctx);
    if err=0 then err := CAM_OMAC_Update(@Key, KeyBytes, ctx);
    if err=0 then CAM_OMAC_Final(LK, ctx);
  end;
  {PRV := CAM-CMAC(LK, msg, msglen)}
  if err=0 then err := CAM_OMAC_Init(LK, 128, ctx);
  if err=0 then err := CAM_OMAC_Update(msg, msglen, ctx);
  if err=0 then CAM_OMAC_Final(PRV, ctx);
  CAM_CPRF128 := err;
end;


{---------------------------------------------------------------------------}
function CAM_CPRF128_selftest: boolean;
  {-Selftest with ipsec-camellia-cmac96and128 test vectors}

const
  {TV from http://tools.ietf.org/html/draft-kato-ipsec-camellia-cmac96and128-02}
  Msg: array[0..39] of byte = ($6b,$c1,$be,$e2,$2e,$40,$9f,$96,
                               $e9,$3d,$7e,$11,$73,$93,$17,$2a,
                               $ae,$2d,$8a,$57,$1e,$03,$ac,$9c,
                               $9e,$b7,$6f,$ac,$45,$af,$8e,$51,
                               $30,$c8,$1c,$46,$a3,$5c,$e4,$11);
  vk1: array[0..31] of byte = ($60,$3d,$eb,$10,$15,$ca,$71,$be,
                               $2b,$73,$ae,$f0,$85,$7d,$77,$81,
                               $1f,$35,$2c,$07,$3b,$61,$08,$d7,
                               $2d,$98,$10,$a3,$09,$14,$df,$f4);
  vk2: array[0..23] of byte = ($8e,$73,$b0,$f7,$da,$0e,$64,$52,
                               $c8,$10,$f3,$2b,$80,$90,$79,$e5,
                               $62,$f8,$ea,$d2,$52,$2c,$6b,$7b);
  vk3: array[0..15] of byte = ($2b,$7e,$15,$16,$28,$ae,$d2,$a6,
                               $ab,$f7,$15,$88,$09,$cf,$4f,$3c);
   t1: TCAMBlock = ($2d,$36,$84,$e9,$1c,$b1,$b3,$03,$a7,$db,$86,$48,$f2,$5e,$e1,$6c);
   t2: TCAMBlock = ($42,$b9,$d4,$7f,$4f,$58,$bc,$29,$85,$b6,$f8,$2c,$23,$b1,$21,$cb);
   t3: TCAMBlock = ($5c,$18,$d1,$19,$cc,$d6,$76,$61,$44,$ac,$18,$66,$13,$1d,$9f,$22);

   function Test1({$ifdef CONST} const {$else} var {$endif}Key; nk: word; tag: TCAMBlock): boolean;
   var
     PRV: TCAMBlock;
     j: integer;
   begin
     Test1 := false;
     if CAM_CPRF128(Key, nk, @msg, sizeof(msg), PRV)<>0 then exit;
     for j:=0 to 15 do if PRV[j]<>tag[j] then exit;
     Test1 := true;
   end;
begin
  CAM_CPRF128_selftest := Test1(vk1,32,t1) and Test1(vk2,24,t2) and Test1(vk3,16,t3);
end;


end.
