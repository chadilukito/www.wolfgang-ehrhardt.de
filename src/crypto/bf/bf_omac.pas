unit BF_OMAC;

(*************************************************************************

 DESCRIPTION     :  Blowfish  OMAC1/2 routines

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  [1] OMAC page: http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
                    [2] T.Iwata and K.Kurosawa. OMAC: One-Key CBC MAC - Addendum
                        (http://csrc.nist.gov/CryptoToolkit/modes/proposedmodes/omac/omac-ad.pdf)


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     16.06.07  W.Ehrhardt  Initial version analog AES_OMAC
 0.11     23.11.08  we          Uses BTypes
 0.12     05.08.10  we          BF_OMAC_Update with ILen: longint, XL Version with $define OLD_XL_Version
**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2007-2010 Wolfgang Ehrhardt

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

{.$define OLD_XL_Version}

interface

uses
  BTypes, BF_Base;

function  BF_OMAC_Init({$ifdef CONST} const Key {$else} var Key {$endif};
                        KeyBytes: word; var ctx: TBFContext): integer;
  {-OMAC init: BF key expansion, error if inv. key size}
  {$ifdef DLL} stdcall; {$endif}

function  BF_OMAC_Update(data: pointer; ILen: longint; var ctx: TBFContext): integer;
  {-OMAC data input, may be called more than once}
  {$ifdef DLL} stdcall; {$endif}

procedure BF_OMAC_Final(var tag: TBFBlock; var ctx: TBFContext);
  {-end data input, calculate OMAC=OMAC1 tag}
  {$ifdef DLL} stdcall; {$endif}

procedure BF_OMAC1_Final(var tag: TBFBlock; var ctx: TBFContext);
  {-end data input, calculate OMAC1 tag}
  {$ifdef DLL} stdcall; {$endif}

procedure BF_OMAC2_Final(var tag: TBFBlock; var ctx: TBFContext);
  {-end data input, calculate OMAC2 tag}
  {$ifdef DLL} stdcall; {$endif}

{$ifdef OLD_XL_Version}
{---------------------------------------------------------------------------}
function  BF_OMAC_UpdateXL(data: pointer; ILen: longint; var ctx: TBFContext): integer;
  {-OMAC data input, may be called more than once}
{$endif}


implementation


{---------------------------------------------------------------------------}
function BF_OMAC_Init({$ifdef CONST} const Key {$else} var Key {$endif};
                       KeyBytes: word; var ctx: TBFContext): integer;
  {-OMAC init: BF key expansion, error if inv. key size}
begin
  {BF key expansion, error if inv. key size}
  {IV = Y[0] = [0]}
  BF_OMAC_Init := BF_Init(Key, KeyBytes, ctx);
  if BF_GetFastInit then fillchar(ctx.IV,sizeof(ctx.IV),0);
end;


{---------------------------------------------------------------------------}
function BF_OMAC_Update(data: pointer; ILen: longint; var ctx: TBFContext): integer;
  {-OMAC data input, may be called more than once}
var
  n: word;
begin
  if (data=nil) and (ILen<>0) then begin
    BF_OMAC_Update := BF_Err_NIL_Pointer;
    exit;
  end;

  {$ifdef BIT16}
    if (ofs(data^)+ILen>$FFFF) then begin
      BF_OMAC_Update:= BF_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  BF_OMAC_Update := 0;

  while ILen>0 do with ctx do begin
    if bLen>=BFBLKSIZE then begin
      {process full buffer}
      {X[i] := M[i] xor Y[i-1]}
      BF_XorBlock(buf, IV, buf);
      BF_Encrypt(ctx, buf, IV);
      bLen := 0;
      while ILen>BFBLKSIZE do with ctx do begin
        {continue with full blocks if more }
        {than one block remains unprocessed}
        {X[i] := M[i] xor Y[i-1]}
        BF_XorBlock(PBFBlock(data)^, IV, buf);
        {Y[i] := EK[X[i]}
        BF_Encrypt(ctx, buf, IV);
        inc(Ptr2Inc(data), BFBLKSIZE);
        dec(ILen, BFBLKSIZE); {ILen>0!}
      end;
    end;
    n := BFBLKSIZE-bLen; if ILen<n then n:=ILen;
    {n>0 because ILen>0 and bLen<BFBLKSIZE}
    move(data^, buf[bLen], n);
    inc(bLen,n);
    inc(Ptr2Inc(data),n);
    dec(ILen,n);
  end;
end;

{$ifdef OLD_XL_Version}
{---------------------------------------------------------------------------}
function BF_OMAC_UpdateXL(data: pointer; ILen: longint; var ctx: TBFContext): integer;
  {-OMAC data input, may be called more than once}
begin
  BF_OMAC_UpdateXL := BF_OMAC_Update(data, ILen, ctx);
end;
{$endif}


{---------------------------------------------------------------------------}
procedure BF_OMACx_Final(OMAC2: boolean; var tag: TBFBlock; var ctx: TBFContext);
  {-end data input, calculate OMAC tag}

  {Turn off range checking for byte shifts}
  {$ifopt R+} {$define SetRPlus} {$else} {$undef SetRPlus} {$endif}
  {$R-}
  {---------------------------------------}
  procedure mul_u(var L: TBFBlock);
    {-Calculate L.u}
  const
    masks: array[0..1] of byte = (0,$1B);
  var
    i: integer;
    mask: byte;
  begin
    mask := masks[L[0] shr 7];
    for i:=0 to BFBLKSIZE-2 do L[i] := (L[i] shl 1) or (L[i+1] shr 7);
    L[BFBLKSIZE-1] := (L[BFBLKSIZE-1] shl 1) xor mask;
  end;
  {---------------------------------------}
  procedure div_u(var L: TBFBlock);
    {-Calculate L.u^-1}
  const
    mask1: array[0..1] of byte = (0, $0D);
    mask2: array[0..1] of byte = (0, $80);
  var
    i,j: integer;
  begin
    j := L[BFBLKSIZE-1] and 1;
    for i:=BFBLKSIZE-1 downto 1 do L[i] := (L[i] shr 1) or (L[i-1] shl 7);
    L[0] := (L[0] shr 1) xor mask2[j];
    L[BFBLKSIZE-1] := L[BFBLKSIZE-1] xor mask1[j];
  end;
  {$ifdef SetRPlus}
    {$R+}
  {$endif}

begin
  with ctx do begin
    fillchar(tag, sizeof(tag), 0);
    {L := EK(0)}
    BF_Encrypt(ctx, tag, tag);
    if blen>=BFBLKSIZE then begin
      {Complete last block, no padding and use L.u}
      mul_u(tag);
    end
    else begin
      {Incomplete last block, pad buf and use L.u^2 or L.u^-1}
      buf[bLen] := $80;
      inc(bLen);
      while blen<BFBLKSIZE do begin
        buf[bLen] := 0;
        inc(bLen);
      end;
      if OMAC2 then begin
        {calc L.u^-1}
        div_u(tag);
      end
      else begin
        {calc L.u^2}
        mul_u(tag);
        mul_u(tag);
      end;
    end;
    {X[m] := pad(M[n]) xor Y[m-1]}
    BF_XorBlock(buf, IV, buf);
    {X[m] := X[m] xor L.u^e, e=-1,1,2}
    BF_XorBlock(buf, tag, buf);
    {T := EK(X[m])}
    BF_Encrypt(ctx, buf, tag);
  end;
end;


{---------------------------------------------------------------------------}
procedure BF_OMAC_Final(var tag: TBFBlock; var ctx: TBFContext);
  {-end data input, calculate OMAC=OMAC1 tag}
begin
  BF_OMACx_Final(false, tag, ctx);
end;


{---------------------------------------------------------------------------}
procedure BF_OMAC1_Final(var tag: TBFBlock; var ctx: TBFContext);
  {-end data input, calculate OMAC1 tag}
begin
  BF_OMACx_Final(false, tag, ctx);
end;


{---------------------------------------------------------------------------}
procedure BF_OMAC2_Final(var tag: TBFBlock; var ctx: TBFContext);
  {-end data input, calculate OMAC2 tag}
begin
  BF_OMACx_Final(true, tag, ctx);
end;


end.

