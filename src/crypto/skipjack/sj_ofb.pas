unit SJ_OFB;

(*************************************************************************

 DESCRIPTION     :  SkipJack OFB functions
                    Because of buffering en/decrypting is associative

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP, WDOSX

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., ch. 9.8


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     03.06.09  W.Ehrhardt  Initial version a la XT_OFB
 0.11     06.08.10  we          Longint ILen
**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2009-2010 Wolfgang Ehrhardt

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
  BTypes, SJ_Base;

{$ifdef CONST}

function  SJ_OFB_Init(const Key; KeyBits: word; const IV: TSJBlock; var ctx: TSJContext): integer;
  {-SkipJack key expansion, error if invalid key size, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_OFB_Reset(const IV: TSJBlock; var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}


{$else}

function  SJ_OFB_Init(var Key; KeyBits: word; var IV: TSJBlock; var ctx: TSJContext): integer;
  {-SkipJack key expansion, error if invalid key size, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_OFB_Reset(var IV: TSJBlock; var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}


{$endif}

function  SJ_OFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}
  {$ifdef DLL} stdcall; {$endif}

function  SJ_OFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
{$ifdef CONST}
function SJ_OFB_Init(const Key; KeyBits: word; const IV: TSJBlock; var ctx: TSJContext): integer;
{$else}
function SJ_OFB_Init(var Key; KeyBits: word; var IV: TSJBlock; var ctx: TSJContext): integer;
{$endif}
  {-SkipJack key expansion, error if invalid key size, encrypt IV}
begin
  SJ_OFB_Init := SJ_Init(Key, KeyBits, ctx);
  SJ_Encrypt(ctx, IV, ctx.IV);
end;


{---------------------------------------------------------------------------}
procedure SJ_OFB_Reset({$ifdef CONST}const {$else} var {$endif} IV: TSJBlock; var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}
begin
  SJ_Reset(ctx);
  SJ_Encrypt(ctx, IV, ctx.IV);
end;



{---------------------------------------------------------------------------}
function SJ_OFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}
begin
  SJ_OFB_Encrypt := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SJ_OFB_Encrypt := SJ_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SJ_OFB_Encrypt := SJ_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  if ctx.blen=0 then begin
    {Handle full blocks first}
    while ILen>=SJBLKSIZE do with ctx do begin
      {Cipher text = plain text xor repeated encr(IV)}
      SJ_XorBlock(PSJBlock(ptp)^, IV, PSJBlock(ctp)^);
      SJ_Encrypt(ctx, IV, IV);
      inc(Ptr2Inc(ptp), SJBLKSIZE);
      inc(Ptr2Inc(ctp), SJBLKSIZE);
      dec(ILen, SJBLKSIZE);
    end;
  end;

  {Handle remaining bytes}
  while ILen>0 do with ctx do begin
    {Test buffer empty}
    if bLen>=SJBLKSIZE then begin
      SJ_Encrypt(ctx, IV, IV);
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
function SJ_OFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}
begin
  {Decrypt = encrypt for OFB mode}
  SJ_OFB_Decrypt := SJ_OFB_Encrypt(ctp, ptp, ILen, ctx);
end;

end.
