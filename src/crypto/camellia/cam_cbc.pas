unit CAM_CBC;

(*************************************************************************

 DESCRIPTION     :  Camellia CBC functions

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., ch. 9.3


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     16.06.08  W.Ehrhardt  Initial version analog TF_CBC
 0.11     23.11.08  we          Uses BTypes
 0.12     29.07.10  we          Longint ILen in CAM_CBC_En/Decrypt
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

function  CAM_CBC_Init(const Key; KeyBits: word; const IV: TCAMBlock; var ctx: TCAMContext): integer;
  {-Camellia key expansion, error if invalid key size, save IV}
  {$ifdef DLL} stdcall; {$endif}

procedure CAM_CBC_Reset(const IV: TCAMBlock; var ctx: TCAMContext);
  {-Clears ctx fields bLen and Flag, save IV}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  CAM_CBC_Init(var Key; KeyBits: word; var IV: TCAMBlock; var ctx: TCAMContext): integer;
  {-Camellia key expansion, error if invalid key size, save IV}

procedure CAM_CBC_Reset(var IV: TCAMBlock; var ctx: TCAMContext);
  {-Clears ctx fields bLen and Flag, save IV}

{$endif}


function  CAM_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}
  {$ifdef DLL} stdcall; {$endif}

function  CAM_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
{$ifdef CONST}
  function CAM_CBC_Init(const Key; KeyBits: word; const IV: TCAMBlock; var ctx: TCAMContext): integer;
{$else}
  function CAM_CBC_Init(var Key; KeyBits: word; var IV: TCAMBlock; var ctx: TCAMContext): integer;
{$endif}
  {-Camellia key expansion, error if invalid key size, encrypt IV}
begin
  CAM_CBC_Init := CAM_Init(Key, KeyBits, ctx);
  ctx.IV := IV;
end;



{---------------------------------------------------------------------------}
procedure CAM_CBC_Reset({$ifdef CONST}const {$else} var {$endif} IV: TCAMBlock; var ctx: TCAMContext);
  {-Clears ctx fields bLen and Flag, save IV}
begin
  CAM_Reset(ctx);
  ctx.IV := IV;
end;



{---------------------------------------------------------------------------}
function CAM_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}
var
  i,n: longint;
  m: word;
begin

  CAM_CBC_Encrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      CAM_CBC_Encrypt := CAM_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      CAM_CBC_Encrypt := CAM_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div CAMBLKSIZE; {Full blocks}
  m := ILen mod CAMBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      CAM_CBC_Encrypt := CAM_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    CAM_CBC_Encrypt := CAM_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      {ct[i] = encr(ct[i-1] xor pt[i])}
      CAM_xorblock(PCAMBlock(ptp)^, IV, IV);
      CAM_Encrypt(ctx, IV, IV);
      PCAMBlock(ctp)^ := IV;
      inc(Ptr2Inc(ptp),CAMBLKSIZE);
      inc(Ptr2Inc(ctp),CAMBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      CAM_xorblock(PCAMBlock(ptp)^, IV, IV);
      CAM_Encrypt(ctx, IV, IV);
      buf := IV;
      inc(Ptr2Inc(ptp),CAMBLKSIZE);
      for i:=0 to m-1 do IV[i] := IV[i] xor PCAMBlock(ptp)^[i];
      CAM_Encrypt(ctx, IV, PCAMBlock(ctp)^);
      inc(Ptr2Inc(ctp),CAMBLKSIZE);
      move(buf,PCAMBlock(ctp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;

end;



{---------------------------------------------------------------------------}
function CAM_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TCAMContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}
var
  i,n: longint;
  m: word;
  tmp: TCAMBlock;
begin

  CAM_CBC_Decrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      CAM_CBC_Decrypt := CAM_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      CAM_CBC_Decrypt := CAM_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div CAMBLKSIZE; {Full blocks}
  m := ILen mod CAMBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      CAM_CBC_Decrypt := CAM_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    CAM_CBC_Decrypt := CAM_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      {pt[i] = decr(ct[i]) xor ct[i-1])}
      buf := IV;
      IV  := PCAMBlock(ctp)^;
      CAM_Decrypt(ctx, IV, PCAMBlock(ptp)^);
      CAM_xorblock(PCAMBlock(ptp)^, buf, PCAMBlock(ptp)^);
      inc(Ptr2Inc(ptp),CAMBLKSIZE);
      inc(Ptr2Inc(ctp),CAMBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing, L=ILen (Schneier's n)}
      buf := IV;                       {C(L-2)}
      CAM_Decrypt(ctx, PCAMBlock(ctp)^, IV);
      inc(Ptr2Inc(ctp),CAMBLKSIZE);
      fillchar(tmp,sizeof(tmp),0);
      move(PCAMBlock(ctp)^,tmp,m);     {c[L]|0}
      CAM_xorblock(tmp,IV,IV);
      tmp := IV;
      move(PCAMBlock(ctp)^,tmp,m);     {c[L]| C'}
      CAM_Decrypt(ctx,tmp,tmp);
      CAM_xorblock(tmp, buf, PCAMBlock(ptp)^);
      inc(Ptr2Inc(ptp),CAMBLKSIZE);
      move(IV,PCAMBlock(ptp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;

end;

end.
