unit SEA_CBC;

(*************************************************************************

 DESCRIPTION     :  SEED CBC functions

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., ch. 9.3


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     07.06.07  W.Ehrhardt  Initial version analog TF_CBC
 0.11     23.11.08  we          Uses BTypes
 0.12     26.07.10  we          Longint ILen
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

interface


uses
  BTypes, SEA_Base;

{$ifdef CONST}

function  SEA_CBC_Init(const Key; KeyBits: word; const IV: TSEABlock; var ctx: TSEAContext): integer;
  {-SEED key expansion, error if invalid key size, save IV}
  {$ifdef DLL} stdcall; {$endif}

procedure SEA_CBC_Reset(const IV: TSEABlock; var ctx: TSEAContext);
  {-Clears ctx fields bLen and Flag, save IV}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  SEA_CBC_Init(var Key; KeyBits: word; var IV: TSEABlock; var ctx: TSEAContext): integer;
  {-SEED key expansion, error if invalid key size, save IV}

procedure SEA_CBC_Reset(var IV: TSEABlock; var ctx: TSEAContext);
  {-Clears ctx fields bLen and Flag, save IV}

{$endif}


function  SEA_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}
  {$ifdef DLL} stdcall; {$endif}

function  SEA_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
{$ifdef CONST}
  function SEA_CBC_Init(const Key; KeyBits: word; const IV: TSEABlock; var ctx: TSEAContext): integer;
{$else}
  function SEA_CBC_Init(var Key; KeyBits: word; var IV: TSEABlock; var ctx: TSEAContext): integer;
{$endif}
  {-SEED key expansion, error if invalid key size, encrypt IV}
begin
  SEA_CBC_Init := SEA_Init(Key, KeyBits, ctx);
  ctx.IV := IV;
end;


{---------------------------------------------------------------------------}
procedure SEA_CBC_Reset({$ifdef CONST}const {$else} var {$endif} IV: TSEABlock; var ctx: TSEAContext);
  {-Clears ctx fields bLen and Flag, save IV}
begin
  SEA_Reset(ctx);
  ctx.IV := IV;
end;


{---------------------------------------------------------------------------}
function SEA_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}
var
  i,n: longint;
  m: word;
begin

  SEA_CBC_Encrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SEA_CBC_Encrypt := SEA_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SEA_CBC_Encrypt := SEA_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div SEABLKSIZE; {Full blocks}
  m := ILen mod SEABLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      SEA_CBC_Encrypt := SEA_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    SEA_CBC_Encrypt := SEA_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      {ct[i] = encr(ct[i-1] xor pt[i])}
      SEA_xorblock(PSEABlock(ptp)^, IV, IV);
      SEA_Encrypt(ctx, IV, IV);
      PSEABlock(ctp)^ := IV;
      inc(Ptr2Inc(ptp),SEABLKSIZE);
      inc(Ptr2Inc(ctp),SEABLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      SEA_xorblock(PSEABlock(ptp)^, IV, IV);
      SEA_Encrypt(ctx, IV, IV);
      buf := IV;
      inc(Ptr2Inc(ptp),SEABLKSIZE);
      for i:=0 to m-1 do IV[i] := IV[i] xor PSEABlock(ptp)^[i];
      SEA_Encrypt(ctx, IV, PSEABlock(ctp)^);
      inc(Ptr2Inc(ctp),SEABLKSIZE);
      move(buf,PSEABlock(ctp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;

end;


{---------------------------------------------------------------------------}
function SEA_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}
var
  i,n: longint;
  m: word;
  tmp: TSEABlock;
begin

  SEA_CBC_Decrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SEA_CBC_Decrypt := SEA_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SEA_CBC_Decrypt := SEA_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div SEABLKSIZE; {Full blocks}
  m := ILen mod SEABLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      SEA_CBC_Decrypt := SEA_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    SEA_CBC_Decrypt := SEA_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      {pt[i] = decr(ct[i]) xor ct[i-1])}
      buf := IV;
      IV  := PSEABlock(ctp)^;
      SEA_Decrypt(ctx, IV, PSEABlock(ptp)^);
      SEA_xorblock(PSEABlock(ptp)^, buf, PSEABlock(ptp)^);
      inc(Ptr2Inc(ptp),SEABLKSIZE);
      inc(Ptr2Inc(ctp),SEABLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing, L=ILen (Schneier's n)}
      buf := IV;                       {C(L-2)}
      SEA_Decrypt(ctx, PSEABlock(ctp)^, IV);
      inc(Ptr2Inc(ctp),SEABLKSIZE);
      fillchar(tmp,sizeof(tmp),0);
      move(PSEABlock(ctp)^,tmp,m);     {c[L]|0}
      SEA_xorblock(tmp,IV,IV);
      tmp := IV;
      move(PSEABlock(ctp)^,tmp,m);     {c[L]| C'}
      SEA_Decrypt(ctx,tmp,tmp);
      SEA_xorblock(tmp, buf, PSEABlock(ptp)^);
      inc(Ptr2Inc(ptp),SEABLKSIZE);
      move(IV,PSEABlock(ptp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;

end;

end.
