unit ANU_OMAC;

(*************************************************************************

 DESCRIPTION   :  Anubis (tweaked) OMAC1/2 routines

 REQUIREMENTS  :  TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA :  ---

 MEMORY USAGE  :  ---

 DISPLAY MODE  :  ---

 REFERENCES    :  OMAC page: http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
                  T.Iwata and K.Kurosawa. OMAC: One-Key CBC MAC - Addendum
                  (http://csrc.nist.gov/CryptoToolkit/modes/proposedmodes/omac/omac-ad.pdf)


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     05.08.08  W.Ehrhardt  Initial version analog AES_OMAC
 0.11     24.11.08  we          Uses BTypes
 0.12     01.08.10  we          EAX_OMAC_Update with ILen: longint, XL Version with $define OLD_XL_Version
**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2008-2010 Wolfgang Ehrhardt

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
  BTypes, ANU_Base;

function  ANU_OMAC_Init({$ifdef CONST} const Key {$else} var Key {$endif};
                        KeyBits: word; var ctx: TANUContext): integer;
  {-OMAC init: Anubis key expansion, error if inv. key size}
  {$ifdef DLL} stdcall; {$endif}

function  ANU_OMAC_Update(data: pointer; ILen: longint; var ctx: TANUContext): integer;
  {-OMAC data input, may be called more than once}
  {$ifdef DLL} stdcall; {$endif}

procedure ANU_OMAC_Final(var tag: TANUBlock; var ctx: TANUContext);
  {-end data input, calculate OMAC=OMAC1 tag}
  {$ifdef DLL} stdcall; {$endif}

procedure ANU_OMAC1_Final(var tag: TANUBlock; var ctx: TANUContext);
  {-end data input, calculate OMAC1 tag}
  {$ifdef DLL} stdcall; {$endif}

procedure ANU_OMAC2_Final(var tag: TANUBlock; var ctx: TANUContext);
  {-end data input, calculate OMAC2 tag}
  {$ifdef DLL} stdcall; {$endif}

{$ifdef OLD_XL_Version}
function  ANU_OMAC_UpdateXL(data: pointer; ILen: longint; var ctx: TANUContext): integer;
  {-OMAC data input, may be called more than once}
{$endif}


{---------------------------------------------------------------------------}
{interfaced for ANU_CMAC, no need for OMAC usage}
procedure ANU_OMACx_Final(OMAC2: boolean; var tag: TANUBlock; var ctx: TANUContext);
  {-end data input, calculate OMAC tag}
  {$ifdef DLL} stdcall; {$endif}

implementation

{---------------------------------------------------------------------------}
function ANU_OMAC_Init({$ifdef CONST} const Key {$else} var Key {$endif};
                       KeyBits: word; var ctx: TANUContext): integer;
  {-OMAC init: Anubis key expansion, error if inv. key size}
begin
  {Anubis key expansion, error if inv. key size}
  {IV = Y[0] = [0]}
  ANU_OMAC_Init := ANU_Init_Encr(Key, KeyBits, ctx);
  if ANU_GetFastInit then fillchar(ctx.IV,sizeof(ctx.IV),0);
end;


{---------------------------------------------------------------------------}
function ANU_OMAC_Update(data: pointer; ILen: longint; var ctx: TANUContext): integer;
  {-OMAC data input, may be called more than once}
var
  n: word;
begin
  if (data=nil) and (ILen<>0) then begin
    ANU_OMAC_Update := ANU_Err_NIL_Pointer;
    exit;
  end;

  {$ifdef BIT16}
    if (ofs(data^)+ILen>$FFFF) then begin
      ANU_OMAC_Update := ANU_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  ANU_OMAC_Update := 0;

  while ILen>0 do with ctx do begin
    if bLen>=ANUBLKSIZE then begin
      {process full buffer}
      {X[i] := M[i] xor Y[i-1]}
      ANU_XorBlock(buf, IV, buf);
      ANU_Encrypt(ctx, buf, IV);
      bLen := 0;
      while ILen>ANUBLKSIZE do with ctx do begin
        {continue with full blocks if more }
        {than one block remains unprocessed}
        {X[i] := M[i] xor Y[i-1]}
        ANU_XorBlock(PANUBlock(data)^, IV, buf);
        {Y[i] := EK[X[i]}
        ANU_Encrypt(ctx, buf, IV);
        inc(Ptr2Inc(data), ANUBLKSIZE);
        dec(ILen, ANUBLKSIZE); {ILen>0!}
      end;
    end;
    n := ANUBLKSIZE-bLen; if ILen<n then n:=ILen;
    {n>0 because ILen>0 and bLen<ANUBLKSIZE}
    move(data^, buf[bLen], n);
    inc(bLen,n);
    inc(Ptr2Inc(data),n);
    dec(ILen,n);
  end;
end;

{$ifdef OLD_XL_Version}
{---------------------------------------------------------------------------}
function  ANU_OMAC_UpdateXL(data: pointer; ILen: longint; var ctx: TANUContext): integer;
  {-OMAC data input, may be called more than once}
begin
  ANU_OMAC_UpdateXL := ANU_OMAC_Update(data, ILen, ctx);
end;
{$endif}



{---------------------------------------------------------------------------}
procedure ANU_OMACx_Final(OMAC2: boolean; var tag: TANUBlock; var ctx: TANUContext);
  {-end data input, calculate OMAC tag}

  {Turn off range checking for byte shifts}
  {$ifopt R+} {$define SetRPlus} {$else} {$undef SetRPlus} {$endif}
  {$R-}
  {---------------------------------------}
  procedure mul_u(var L: TANUBlock);
    {-Calculate L.u}
  const
    masks: array[0..1] of byte = (0,$87);
  var
    i: integer;
    mask: byte;
  begin
    mask := masks[L[0] shr 7];
    for i:=0 to ANUBLKSIZE-2 do L[i] := (L[i] shl 1) or (L[i+1] shr 7);
    L[ANUBLKSIZE-1] := (L[ANUBLKSIZE-1] shl 1) xor mask;
  end;
  {---------------------------------------}
  procedure div_u(var L: TANUBlock);
    {-Calculate L.u^-1}
  const
    mask1: array[0..1] of byte = (0, $43);
    mask2: array[0..1] of byte = (0, $80);
  var
    i,j: integer;
  begin
    j := L[ANUBLKSIZE-1] and 1;
    for i:=ANUBLKSIZE-1 downto 1 do L[i] := (L[i] shr 1) or (L[i-1] shl 7);
    L[0] := (L[0] shr 1) xor mask2[j];
    L[ANUBLKSIZE-1] := L[ANUBLKSIZE-1] xor mask1[j];
  end;
  {$ifdef SetRPlus}
    {$R+}
  {$endif}

begin
  with ctx do begin
    fillchar(tag, sizeof(tag), 0);
    {L := EK(0)}
    ANU_Encrypt(ctx, tag, tag);
    if blen>=ANUBLKSIZE then begin
      {Complete last block, no padding and use L.u}
      mul_u(tag);
    end
    else begin
      {Incomplete last block, pad buf and use L.u^2 or L.u^-1}
      buf[bLen] := $80;
      inc(bLen);
      while blen<ANUBLKSIZE do begin
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
    ANU_XorBlock(buf, IV, buf);
    {X[m] := X[m] xor L.u^e, e=-1,1,2}
    ANU_XorBlock(buf, tag, buf);
    {T := EK(X[m])}
    ANU_Encrypt(ctx, buf, tag);
  end;
end;


{---------------------------------------------------------------------------}
procedure ANU_OMAC_Final(var tag: TANUBlock; var ctx: TANUContext);
  {-end data input, calculate OMAC=OMAC1 tag}
begin
  ANU_OMACx_Final(false, tag, ctx);
end;


{---------------------------------------------------------------------------}
procedure ANU_OMAC1_Final(var tag: TANUBlock; var ctx: TANUContext);
  {-end data input, calculate OMAC1 tag}
begin
  ANU_OMACx_Final(false, tag, ctx);
end;


{---------------------------------------------------------------------------}
procedure ANU_OMAC2_Final(var tag: TANUBlock; var ctx: TANUContext);
  {-end data input, calculate OMAC2 tag}
begin
  ANU_OMACx_Final(true, tag, ctx);
end;


end.

