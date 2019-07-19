unit XT_CBC;

(*************************************************************************

 DESCRIPTION     :  XTEA CBC functions

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP, WDOSX

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., ch. 9.3


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     01.01.05  W.Ehrhardt  Initial version analog BF_CBC
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

function  XT_CBC_Init(const Key; KeyBytes: word; const IV: TXTBlock; var ctx: TXTContext): integer;
  {-XTEA key expansion, error if invalid key size, save IV}
  {$ifdef DLL} stdcall; {$endif}

procedure XT_CBC_Reset(const IV: TXTBlock; var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag, save IV}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  XT_CBC_Init(var Key; KeyBytes: word; var IV: TXTBlock; var ctx: TXTContext): integer;
  {-XTEA key expansion, error if invalid key size, save IV}

procedure XT_CBC_Reset(var IV: TXTBlock; var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag, save IV}

{$endif}


function  XT_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}
  {$ifdef DLL} stdcall; {$endif}

function  XT_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
{$ifdef CONST}
  function XT_CBC_Init(const Key; KeyBytes: word; const IV: TXTBlock; var ctx: TXTContext): integer;
{$else}
  function XT_CBC_Init(var Key; KeyBytes: word; var IV: TXTBlock; var ctx: TXTContext): integer;
{$endif}
  {-XTEA key expansion, error if invalid key size, encrypt IV}
begin
  XT_CBC_Init := XT_Init(Key, KeyBytes, ctx);
  ctx.IV := IV;
end;


{---------------------------------------------------------------------------}
procedure XT_CBC_Reset({$ifdef CONST}const {$else} var {$endif} IV: TXTBlock; var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag, save IV}
begin
  XT_Reset(ctx);
  ctx.IV := IV;
end;


{---------------------------------------------------------------------------}
function XT_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}
var
  i,n: longint;
  m: word;
begin

  XT_CBC_Encrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      XT_CBC_Encrypt := XT_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      XT_CBC_Encrypt := XT_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div XTBLKSIZE; {Full blocks}
  m := ILen mod XTBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      XT_CBC_Encrypt := XT_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    XT_CBC_Encrypt := XT_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      {ct[i] = encr(ct[i-1] xor pt[i])}
      XT_xorblock(PXTBlock(ptp)^, IV, IV);
      XT_Encrypt(ctx, IV, IV);
      PXTBlock(ctp)^ := IV;
      inc(Ptr2Inc(ptp),XTBLKSIZE);
      inc(Ptr2Inc(ctp),XTBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      XT_xorblock(PXTBlock(ptp)^, IV, IV);
      XT_Encrypt(ctx, IV, IV);
      buf := IV;
      inc(Ptr2Inc(ptp),XTBLKSIZE);
      for i:=0 to m-1 do IV[i] := IV[i] xor PXTBlock(ptp)^[i];
      XT_Encrypt(ctx, IV, PXTBlock(ctp)^);
      inc(Ptr2Inc(ctp),XTBLKSIZE);
      move(buf,PXTBlock(ctp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;

end;


{---------------------------------------------------------------------------}
function XT_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}
var
  i,n: longint;
  m: word;
  tmp: TXTBlock;
begin

  XT_CBC_Decrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      XT_CBC_Decrypt := XT_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      XT_CBC_Decrypt := XT_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div XTBLKSIZE; {Full blocks}
  m := ILen mod XTBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      XT_CBC_Decrypt := XT_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    XT_CBC_Decrypt := XT_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      {pt[i] = decr(ct[i]) xor ct[i-1])}
      buf := IV;
      IV  := PXTBlock(ctp)^;
      XT_Decrypt(ctx, IV, PXTBlock(ptp)^);
      XT_xorblock(PXTBlock(ptp)^, buf, PXTBlock(ptp)^);
      inc(Ptr2Inc(ptp),XTBLKSIZE);
      inc(Ptr2Inc(ctp),XTBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing, L=ILen (Schneier's n)}
      buf := IV;                       {C(L-2)}
      XT_Decrypt(ctx, PXTBlock(ctp)^, IV);
      inc(Ptr2Inc(ctp),XTBLKSIZE);
      fillchar(tmp,sizeof(tmp),0);
      move(PXTBlock(ctp)^,tmp,m);     {c[L]|0}
      XT_xorblock(tmp,IV,IV);
      tmp := IV;
      move(PXTBlock(ctp)^,tmp,m);     {c[L]| C'}
      XT_Decrypt(ctx,tmp,tmp);
      XT_xorblock(tmp, buf, PXTBlock(ptp)^);
      inc(Ptr2Inc(ptp),XTBLKSIZE);
      move(IV,PXTBlock(ptp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;

end;

end.
