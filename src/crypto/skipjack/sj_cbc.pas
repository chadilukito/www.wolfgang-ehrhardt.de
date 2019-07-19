unit SJ_CBC;

(*************************************************************************

 DESCRIPTION     :  SkipJack CBC functions

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP, WDOSX

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., ch. 9.3


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     03.06.09  W.Ehrhardt  Initial version a la XT_CBC
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

function  SJ_CBC_Init(const Key; KeyBytes: word; const IV: TSJBlock; var ctx: TSJContext): integer;
  {-SkipJack key expansion, error if invalid key size, save IV}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_CBC_Reset(const IV: TSJBlock; var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag, save IV}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  SJ_CBC_Init(var Key; KeyBytes: word; var IV: TSJBlock; var ctx: TSJContext): integer;
  {-SkipJack key expansion, error if invalid key size, save IV}

procedure SJ_CBC_Reset(var IV: TSJBlock; var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag, save IV}

{$endif}


function  SJ_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}
  {$ifdef DLL} stdcall; {$endif}

function  SJ_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
{$ifdef CONST}
  function SJ_CBC_Init(const Key; KeyBytes: word; const IV: TSJBlock; var ctx: TSJContext): integer;
{$else}
  function SJ_CBC_Init(var Key; KeyBytes: word; var IV: TSJBlock; var ctx: TSJContext): integer;
{$endif}
  {-SkipJack key expansion, error if invalid key size, encrypt IV}
begin
  SJ_CBC_Init := SJ_Init(Key, KeyBytes, ctx);
  ctx.IV := IV;
end;



{---------------------------------------------------------------------------}
procedure SJ_CBC_Reset({$ifdef CONST}const {$else} var {$endif} IV: TSJBlock; var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag, save IV}
begin
  SJ_Reset(ctx);
  ctx.IV := IV;
end;



{---------------------------------------------------------------------------}
function SJ_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}
var
  i,n: longint;
  m: word;
begin

  SJ_CBC_Encrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SJ_CBC_Encrypt := SJ_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SJ_CBC_Encrypt := SJ_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div SJBLKSIZE; {Full blocks}
  m := ILen mod SJBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      SJ_CBC_Encrypt := SJ_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    SJ_CBC_Encrypt := SJ_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      {ct[i] = encr(ct[i-1] xor pt[i])}
      SJ_xorblock(PSJBlock(ptp)^, IV, IV);
      SJ_Encrypt(ctx, IV, IV);
      PSJBlock(ctp)^ := IV;
      inc(Ptr2Inc(ptp),SJBLKSIZE);
      inc(Ptr2Inc(ctp),SJBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      SJ_xorblock(PSJBlock(ptp)^, IV, IV);
      SJ_Encrypt(ctx, IV, IV);
      buf := IV;
      inc(Ptr2Inc(ptp),SJBLKSIZE);
      for i:=0 to m-1 do IV[i] := IV[i] xor PSJBlock(ptp)^[i];
      SJ_Encrypt(ctx, IV, PSJBlock(ctp)^);
      inc(Ptr2Inc(ctp),SJBLKSIZE);
      move(buf,PSJBlock(ctp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;

end;



{---------------------------------------------------------------------------}
function SJ_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}
var
  i,n: longint;
  m: word;
  tmp: TSJBlock;
begin

  SJ_CBC_Decrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SJ_CBC_Decrypt := SJ_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SJ_CBC_Decrypt := SJ_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div SJBLKSIZE; {Full blocks}
  m := ILen mod SJBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      SJ_CBC_Decrypt := SJ_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    SJ_CBC_Decrypt := SJ_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      {pt[i] = decr(ct[i]) xor ct[i-1])}
      buf := IV;
      IV  := PSJBlock(ctp)^;
      SJ_Decrypt(ctx, IV, PSJBlock(ptp)^);
      SJ_xorblock(PSJBlock(ptp)^, buf, PSJBlock(ptp)^);
      inc(Ptr2Inc(ptp),SJBLKSIZE);
      inc(Ptr2Inc(ctp),SJBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing, L=ILen (Schneier's n)}
      buf := IV;                       {C(L-2)}
      SJ_Decrypt(ctx, PSJBlock(ctp)^, IV);
      inc(Ptr2Inc(ctp),SJBLKSIZE);
      fillchar(tmp,sizeof(tmp),0);
      move(PSJBlock(ctp)^,tmp,m);     {c[L]|0}
      SJ_xorblock(tmp,IV,IV);
      tmp := IV;
      move(PSJBlock(ctp)^,tmp,m);     {c[L]| C'}
      SJ_Decrypt(ctx,tmp,tmp);
      SJ_xorblock(tmp, buf, PSJBlock(ptp)^);
      inc(Ptr2Inc(ptp),SJBLKSIZE);
      move(IV,PSJBlock(ptp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;

end;

end.
