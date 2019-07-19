unit SC_CFB;

(*************************************************************************

 DESCRIPTION     :  SHACAL-2 CFB functions
                    Because of buffering en/decrypting is associative

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., ch. 14.3/9.6


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     02.01.05  we          Initial version analog AES_CFB
 0.11     02.01.05  we          SC_CFB_Reset
 0.12     24.11.08  we          Uses BTypes
 0.13     06.08.10  we          Longint ILen
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
  BTypes, SC_Base;

{$ifdef CONST}

function  SC_CFB_Init(const Key; KeyBytes: word; const IV: TSCBlock; var ctx: TSCContext): integer;
  {-SHACAL-2 key expansion, error if invalid key size, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}

procedure SC_CFB_Reset(const IV: TSCBlock; var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  SC_CFB_Init(var Key; KeyBytes: word; var IV: TSCBlock; var ctx: TSCContext): integer;
  {-SHACAL-2 key expansion, error if invalid key size, encrypt IV}

procedure SC_CFB_Reset(var IV: TSCBlock; var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}

{$endif}

function  SC_CFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB mode}
  {$ifdef DLL} stdcall; {$endif}

function  SC_CFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
{$ifdef CONST}
function SC_CFB_Init(const Key; KeyBytes: word; const IV: TSCBlock; var ctx: TSCContext): integer;
{$else}
function SC_CFB_Init(var Key; KeyBytes: word; var IV: TSCBlock; var ctx: TSCContext): integer;
{$endif}
  {-SHACAL-2 key expansion, error if invalid key size, encrypt IV}
var
  err: integer;
begin
  err := SC_Init(Key, KeyBytes, ctx);
  SC_CFB_Init := err;
  if err=0 then begin
    {encrypt IV}
    SC_Encrypt(ctx, IV, ctx.IV);
  end;
end;


{---------------------------------------------------------------------------}
procedure SC_CFB_Reset({$ifdef CONST}const {$else} var {$endif} IV: TSCBlock; var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}
begin
  SC_Reset(ctx);
  SC_Encrypt(ctx, IV, ctx.IV);
end;


{---------------------------------------------------------------------------}
function SC_CFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CFB mode}
begin
  SC_CFB_Encrypt := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SC_CFB_Encrypt := SC_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SC_CFB_Encrypt := SC_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  if ctx.blen=0 then begin
    {Handle full blocks first}
    while ILen>=SCBLKSIZE do with ctx do begin
      {Cipher text = plain text xor encr(IV/CT)}
      SC_XorBlock(PSCBlock(ptp)^, IV, PSCBlock(ctp)^);
      SC_Encrypt(ctx, PSCBlock(ctp)^, IV);
      inc(Ptr2Inc(ptp), SCBLKSIZE);
      inc(Ptr2Inc(ctp), SCBLKSIZE);
      dec(ILen, SCBLKSIZE);
    end;
  end;

  {Handle remaining bytes}
  while ILen>0 do with ctx do begin
    {Test buffer empty}
    if bLen>=SCBLKSIZE then begin
      SC_Encrypt(ctx, buf, IV);
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
function SC_CFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CFB mode}
begin
  SC_CFB_Decrypt := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SC_CFB_Decrypt := SC_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SC_CFB_Decrypt := SC_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  if ctx.blen=0 then begin
    {Handle full blocks first}
    while ILen>=SCBLKSIZE do with ctx do begin
      {plain text = cypher text xor encr(IV/CT)}
      {must use buf, otherwise overwrite bug if ctp=ptp}
      buf := PSCBlock(ctp)^;
      SC_XorBlock(buf, IV, PSCBlock(ptp)^);
      SC_Encrypt(ctx, buf, IV);
      inc(Ptr2Inc(ptp), SCBLKSIZE);
      inc(Ptr2Inc(ctp), SCBLKSIZE);
      dec(ILen, SCBLKSIZE);
    end;
  end;

  {Handle remaining bytes}
  while ILen>0 do with ctx do begin
    {Test buffer empty}
    if bLen>=SCBLKSIZE then begin
      SC_Encrypt(ctx, buf, IV);
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
