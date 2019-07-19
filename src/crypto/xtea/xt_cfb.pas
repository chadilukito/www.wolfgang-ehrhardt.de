unit XT_CFB;

(*************************************************************************

 DESCRIPTION     :  XTEA CFB64 functions
                    Because of buffering en/decrypting is associative

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP, WDOSX

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., ch. 9.6


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     01.01.05  W.Ehrhardt  Initial version analog BF_CFB
 0.11     24.11.08  we          Uses BTypes
 0.12     06.08.10  we          Longint ILen
**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2005-2010 Wolfgang Ehrhardt

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
  BTypes, XT_Base;

{$ifdef CONST}

function  XT_CFB_Init(const Key; KeyBytes: word; const IV: TXTBlock; var ctx: TXTContext): integer;
  {-XTEA key expansion, error if invalid key size, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}

procedure XT_CFB_Reset(const IV: TXTBlock; var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  XT_CFB_Init(var Key; KeyBytes: word; var IV: TXTBlock; var ctx: TXTContext): integer;
  {-XTEA key expansion, error if invalid key size, encrypt IV}

procedure XT_CFB_Reset(var IV: TXTBlock; var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}

{$endif}

function  XT_CFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB mode}
  {$ifdef DLL} stdcall; {$endif}

function  XT_CFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
{$ifdef CONST}
function XT_CFB_Init(const Key; KeyBytes: word; const IV: TXTBlock; var ctx: TXTContext): integer;
{$else}
function XT_CFB_Init(var Key; KeyBytes: word; var IV: TXTBlock; var ctx: TXTContext): integer;
{$endif}
  {-XTEA key expansion, error if invalid key size, encrypt IV}
var
  err: integer;
begin
  err := XT_Init(Key, KeyBytes, ctx);
  XT_CFB_Init := err;
  if err=0 then begin
    {encrypt IV}
    XT_Encrypt(ctx, IV, ctx.IV);
  end;
end;


{---------------------------------------------------------------------------}
procedure XT_CFB_Reset({$ifdef CONST}const {$else} var {$endif} IV: TXTBlock; var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}
begin
  XT_Reset(ctx);
  XT_Encrypt(ctx, IV, ctx.IV);
end;


{---------------------------------------------------------------------------}
function XT_CFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB mode}
begin
  XT_CFB_Encrypt := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      XT_CFB_Encrypt := XT_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      XT_CFB_Encrypt := XT_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  if ctx.blen=0 then begin
    {Handle full blocks first}
    while ILen>=XTBLKSIZE do with ctx do begin
      {Cipher text = plain text xor encr(IV/CT)}
      XT_XorBlock(PXTBlock(ptp)^, IV, PXTBlock(ctp)^);
      XT_Encrypt(ctx, PXTBlock(ctp)^, IV);
      inc(Ptr2Inc(ptp), XTBLKSIZE);
      inc(Ptr2Inc(ctp), XTBLKSIZE);
      dec(ILen, XTBLKSIZE);
    end;
  end;

  {Handle remaining bytes}
  while ILen>0 do with ctx do begin
    {Test buffer empty}
    if bLen>=XTBLKSIZE then begin
      XT_Encrypt(ctx, buf, IV);
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
function XT_CFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB mode}
begin
  XT_CFB_Decrypt := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      XT_CFB_Decrypt := XT_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      XT_CFB_Decrypt := XT_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  if ctx.blen=0 then begin
    {Handle full blocks first}
    while ILen>=XTBLKSIZE do with ctx do begin
      {plain text = cypher text xor encr(IV/CT)}
      {must use buf, otherwise overwrite bug if ctp=ptp}
      buf := PXTBlock(ctp)^;
      XT_XorBlock(buf, IV, PXTBlock(ptp)^);
      XT_Encrypt(ctx, buf, IV);
      inc(Ptr2Inc(ptp), XTBLKSIZE);
      inc(Ptr2Inc(ctp), XTBLKSIZE);
      dec(ILen, XTBLKSIZE);
    end;
  end;

  {Handle remaining bytes}
  while ILen>0 do with ctx do begin
    {Test buffer empty}
    if bLen>=XTBLKSIZE then begin
      XT_Encrypt(ctx, buf, IV);
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
