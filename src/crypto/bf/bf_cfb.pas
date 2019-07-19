unit BF_CFB;

(*************************************************************************

 DESCRIPTION     :  Blowfish CFB64 functions
                    Because of buffering en/decrypting is associative

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., ch. 14.3/9.6


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     30.11.04  we          Initial version analog AES_CFB
 0.11     30.11.04  we          BF_CFB_Reset
 0.12     23.11.08  we          Uses BTypes
 0.13     05.08.10  we          Longint ILen
**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2004-2010 Wolfgang Ehrhardt

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
  BTypes, BF_Base;

{$ifdef CONST}

function  BF_CFB_Init(const Key; KeyBytes: word; const IV: TBFBlock; var ctx: TBFContext): integer;
  {-BF key expansion, error if invalid key size, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}

procedure BF_CFB_Reset(const IV: TBFBlock; var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  BF_CFB_Init(var Key; KeyBytes: word; var IV: TBFBlock; var ctx: TBFContext): integer;
  {-BF key expansion, error if invalid key size, encrypt IV}

procedure BF_CFB_Reset(var IV: TBFBlock; var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}

{$endif}

function  BF_CFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB128 mode}
  {$ifdef DLL} stdcall; {$endif}

function  BF_CFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB128 mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
{$ifdef CONST}
function BF_CFB_Init(const Key; KeyBytes: word; const IV: TBFBlock; var ctx: TBFContext): integer;
{$else}
function BF_CFB_Init(var Key; KeyBytes: word; var IV: TBFBlock; var ctx: TBFContext): integer;
{$endif}
  {-BF key expansion, error if invalid key size, encrypt IV}
var
  err: integer;
begin
  err := BF_Init(Key, KeyBytes, ctx);
  BF_CFB_Init := err;
  if err=0 then begin
    {encrypt IV}
    BF_Encrypt(ctx, IV, ctx.IV);
  end;
end;


{---------------------------------------------------------------------------}
procedure BF_CFB_Reset({$ifdef CONST}const {$else} var {$endif} IV: TBFBlock; var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}
begin
  BF_Reset(ctx);
  BF_Encrypt(ctx, IV, ctx.IV);
end;


{---------------------------------------------------------------------------}
function BF_CFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB128 mode}
begin
  BF_CFB_Encrypt := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      BF_CFB_Encrypt := BF_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      BF_CFB_Encrypt := BF_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  if ctx.blen=0 then begin
    {Handle full blocks first}
    while ILen>=BFBLKSIZE do with ctx do begin
      {Cipher text = plain text xor encr(IV/CT)}
      BF_XorBlock(PBFBlock(ptp)^, IV, PBFBlock(ctp)^);
      BF_Encrypt(ctx, PBFBlock(ctp)^, IV);
      inc(Ptr2Inc(ptp), BFBLKSIZE);
      inc(Ptr2Inc(ctp), BFBLKSIZE);
      dec(ILen, BFBLKSIZE);
    end;
  end;

  {Handle remaining bytes}
  while ILen>0 do with ctx do begin
    {Test buffer empty}
    if bLen>=BFBLKSIZE then begin
      BF_Encrypt(ctx, buf, IV);
      bLen := 0;
    end;
    buf[bLen] := IV[bLen] xor pByte(ptp)^;
    pByte(ctp)^ := buf[bLen];
    inc(bLen);
    inc(Ptr2Inc(ptp));
    inc(Ptr2Inc(ctp));
    dec(ILen);
  end;
end;


{---------------------------------------------------------------------------}
function BF_CFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB128 mode}
begin
  BF_CFB_Decrypt := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      BF_CFB_Decrypt := BF_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      BF_CFB_Decrypt := BF_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}
  if ctx.blen=0 then begin
    {Handle full blocks first}
    while ILen>=BFBLKSIZE do with ctx do begin
      {plain text = cypher text xor encr(IV/CT)}
      {must use buf, otherwise overwrite bug if ctp=ptp}
      buf := PBFBlock(ctp)^;
      BF_XorBlock(buf, IV, PBFBlock(ptp)^);
      BF_Encrypt(ctx, buf, IV);
      inc(Ptr2Inc(ptp), BFBLKSIZE);
      inc(Ptr2Inc(ctp), BFBLKSIZE);
      dec(ILen, BFBLKSIZE);
    end;
  end;

  {Handle remaining bytes}
  while ILen>0 do with ctx do begin
    {Test buffer empty}
    if bLen>=BFBLKSIZE then begin
      BF_Encrypt(ctx, buf, IV);
      bLen := 0;
    end;
    buf[bLen] := pByte(ctp)^;
    pByte(ptp)^ := buf[bLen] xor IV[bLen];
    inc(bLen);
    inc(Ptr2Inc(ptp));
    inc(Ptr2Inc(ctp));
    dec(ILen);
  end;
end;

end.
