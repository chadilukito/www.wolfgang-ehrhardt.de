unit CAM_OFB;

(*************************************************************************

 DESCRIPTION     :  Camellia OFB functions
                    Because of buffering en/decrypting is associative

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., ch. 9.8


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     16.06.08  W.Ehrhardt  Initial version analog TF_OFB
 0.11     23.11.08  we          Uses BTypes
 0.12     29.07.10  we          Longint ILen in CAM_OFB_En/Decrypt
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


interface


uses
  BTypes, CAM_Base;

{$ifdef CONST}

function  CAM_OFB_Init(const Key; KeyBits: word; const IV: TCAMBlock; var ctx: TCAMContext): integer;
  {-Camellia key expansion, error if invalid key size, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}

procedure CAM_OFB_Reset(const IV: TCAMBlock; var ctx: TCAMContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}


{$else}

function  CAM_OFB_Init(var Key; KeyBits: word; var IV: TCAMBlock; var ctx: TCAMContext): integer;
  {-Camellia key expansion, error if invalid key size, encrypt IV}
  {$ifdef DLL} stdcall; {$endif}

procedure CAM_OFB_Reset(var IV: TCAMBlock; var ctx: TCAMContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}


{$endif}

function  CAM_OFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}
  {$ifdef DLL} stdcall; {$endif}

function  CAM_OFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
{$ifdef CONST}
function CAM_OFB_Init(const Key; KeyBits: word; const IV: TCAMBlock; var ctx: TCAMContext): integer;
{$else}
function CAM_OFB_Init(var Key; KeyBits: word; var IV: TCAMBlock; var ctx: TCAMContext): integer;
{$endif}
  {-Camellia key expansion, error if invalid key size, encrypt IV}
begin
  CAM_OFB_Init := CAM_Init(Key, KeyBits, ctx);
  CAM_Encrypt(ctx, IV, ctx.IV);
end;


{---------------------------------------------------------------------------}
procedure CAM_OFB_Reset({$ifdef CONST}const {$else} var {$endif} IV: TCAMBlock; var ctx: TCAMContext);
  {-Clears ctx fields bLen and Flag, encrypt IV}
begin
  CAM_Reset(ctx);
  CAM_Encrypt(ctx, IV, ctx.IV);
end;



{---------------------------------------------------------------------------}
function CAM_OFB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in OFB mode}
begin
  CAM_OFB_Encrypt := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      CAM_OFB_Encrypt := CAM_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      CAM_OFB_Encrypt := CAM_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  if ctx.blen=0 then begin
    {Handle full blocks first}
    while ILen>=CAMBLKSIZE do with ctx do begin
      {Cipher text = plain text xor repeated encr(IV)}
      CAM_XorBlock(PCAMBlock(ptp)^, IV, PCAMBlock(ctp)^);
      CAM_Encrypt(ctx, IV, IV);
      inc(Ptr2Inc(ptp), CAMBLKSIZE);
      inc(Ptr2Inc(ctp), CAMBLKSIZE);
      dec(ILen, CAMBLKSIZE);
    end;
  end;

  {Handle remaining bytes}
  while ILen>0 do with ctx do begin
    {Test buffer empty}
    if bLen>=CAMBLKSIZE then begin
      CAM_Encrypt(ctx, IV, IV);
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
function CAM_OFB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in OFB mode}
begin
  {Decrypt = encrypt for OFB mode}
  CAM_OFB_Decrypt := CAM_OFB_Encrypt(ctp, ptp, ILen, ctx);
end;

end.
