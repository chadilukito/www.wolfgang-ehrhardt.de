unit BF_OFB;

(*************************************************************************

 DESCRIPTION     :  Blowfish OFB functions
                    Because of buffering en/decrypting is associative

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., ch. 14.3/9.8


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     30.11.04  we          Initial version analog AES_OFB
 0.11     30.11.04  we          BF_OFB_Reset
 0.12     16.06.07  we          Cut&paste bug: KeyBits -> KeyBytes
 0.13     23.11.08  we          Uses BTypes
 0.14     05.08.10  we          Longint ILen
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
function  BF_OFB_Init(const Key; KeyBytes: word; const IV: TBFBlock; var ctx: TBFContext): integer;
  {-BF key expansion, error if invalid key size, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}

procedure BF_OFB_Reset(const IV: TBFBlock; var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  BF_OFB_Init(var Key; KeyBytes: word; var IV: TBFBlock; var ctx: TBFContext): integer;
  {-BF key expansion, error if invalid key size, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}

procedure BF_OFB_Reset(var IV: TBFBlock; var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}
{$endif}

function  BF_OFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}
  {$ifdef DLL} stdcall; {$endif}

function  BF_OFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
{$ifdef CONST}
function BF_OFB_Init(const Key; KeyBytes: word; const IV: TBFBlock; var ctx: TBFContext): integer;
{$else}
function BF_OFB_Init(var Key; KeyBytes: word; var IV: TBFBlock; var ctx: TBFContext): integer;
{$endif}
  {-BF key expansion, error if invalid key size, encrypt IV}
begin
  BF_OFB_Init := BF_Init(Key, KeyBytes, ctx);
  BF_Encrypt(ctx, IV, ctx.IV);
end;


{---------------------------------------------------------------------------}
procedure BF_OFB_Reset({$ifdef CONST}const {$else} var {$endif} IV: TBFBlock; var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}
begin
  BF_Reset(ctx);
  BF_Encrypt(ctx, IV, ctx.IV);
end;



{---------------------------------------------------------------------------}
function BF_OFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}
begin
  BF_OFB_Encrypt := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      BF_OFB_Encrypt := BF_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      BF_OFB_Encrypt := BF_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  if ctx.blen=0 then begin
    {Handle full blocks first}
    while ILen>=BFBLKSIZE do with ctx do begin
      {Cipher text = plain text xor repeated encr(IV)}
      BF_XorBlock(PBFBlock(ptp)^, IV, PBFBlock(ctp)^);
      BF_Encrypt(ctx, IV, IV);
      inc(Ptr2Inc(ptp), BFBLKSIZE);
      inc(Ptr2Inc(ctp), BFBLKSIZE);
      dec(ILen, BFBLKSIZE);
    end;
  end;

  {Handle remaining bytes}
  while ILen>0 do with ctx do begin
    {Test buffer empty}
    if bLen>=BFBLKSIZE then begin
      BF_Encrypt(ctx, IV, IV);
      bLen := 0;
    end;
    pByte(ctp)^ := IV[bLen] xor pByte(ptp)^;
    inc(bLen);
    inc(Ptr2Inc(ptp));
    inc(Ptr2Inc(ctp));
    dec(ILen);
  end;
end;


{---------------------------------------------------------------------------}
function BF_OFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}
begin
  {Decrypt = encrypt for OFB mode}
  BF_OFB_Decrypt := BF_OFB_Encrypt(ctp, ptp, ILen, ctx);
end;

end.
