unit BF_CBC;

(*************************************************************************

 DESCRIPTION     :  Blowfish CBC functions

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  Blowfish: B.Schneier, Applied Cryptography, 2nd ed., ch. 14.3/9.3
                    Cipher text stealing: Schneier, ch.9.3


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     30.11.04  we          Initial version analog AES_CBC
 0.11     30.11.04  we          BF_CBC_Reset
 0.12     01.12.04  we          No more processing after short block
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

function  BF_CBC_Init(const Key; KeyBytes: word; const IV: TBFBlock; var ctx: TBFContext): integer;
  {-BF key expansion, error if invalid key size, save IV}
  {$ifdef DLL} stdcall; {$endif}

procedure BF_CBC_Reset(const IV: TBFBlock; var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag, save IV}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  BF_CBC_Init(var Key; KeyBytes: word; var IV: TBFBlock; var ctx: TBFContext): integer;
  {-BF key expansion, error if invalid key size, save IV}

procedure BF_CBC_Reset(var IV: TBFBlock; var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag, save IV}

{$endif}


function  BF_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}
  {$ifdef DLL} stdcall; {$endif}

function  BF_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
{$ifdef CONST}
  function BF_CBC_Init(const Key; KeyBytes: word; const IV: TBFBlock; var ctx: TBFContext): integer;
{$else}
  function BF_CBC_Init(var Key; KeyBytes: word; var IV: TBFBlock; var ctx: TBFContext): integer;
{$endif}
  {-BF key expansion, error if invalid key size, encrypt IV}
begin
  BF_CBC_Init := BF_Init(Key, KeyBytes, ctx);
  ctx.IV := IV;
end;



{---------------------------------------------------------------------------}
procedure BF_CBC_Reset({$ifdef CONST}const {$else} var {$endif} IV: TBFBlock; var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag, save IV}
begin
  BF_Reset(ctx);
  ctx.IV := IV;
end;



{---------------------------------------------------------------------------}
function BF_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}
var
  i,n: longint;
  m: word;
begin

  BF_CBC_Encrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      BF_CBC_Encrypt := BF_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      BF_CBC_Encrypt := BF_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div BFBLKSIZE; {Full blocks}
  m := ILen mod BFBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      BF_CBC_Encrypt := BF_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    BF_CBC_Encrypt := BF_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      {ct[i] = encr(ct[i-1] xor pt[i])}
      BF_xorblock(PBFBlock(ptp)^, IV, IV);
      BF_Encrypt(ctx, IV, IV);
      PBFBlock(ctp)^ := IV;
      inc(Ptr2Inc(ptp),BFBLKSIZE);
      inc(Ptr2Inc(ctp),BFBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      BF_xorblock(PBFBlock(ptp)^, IV, IV);
      BF_Encrypt(ctx, IV, IV);
      buf := IV;
      inc(Ptr2Inc(ptp),BFBLKSIZE);
      for i:=0 to m-1 do IV[i] := IV[i] xor PBFBlock(ptp)^[i];
      BF_Encrypt(ctx, IV, PBFBlock(ctp)^);
      inc(Ptr2Inc(ctp),BFBLKSIZE);
      move(buf,PBFBlock(ctp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;

end;



{---------------------------------------------------------------------------}
function BF_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}
var
  i,n: longint;
  m: word;
  tmp: TBFBlock;
begin

  BF_CBC_Decrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      BF_CBC_Decrypt := BF_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      BF_CBC_Decrypt := BF_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div BFBLKSIZE; {Full blocks}
  m := ILen mod BFBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      BF_CBC_Decrypt := BF_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    BF_CBC_Decrypt := BF_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      {pt[i] = decr(ct[i]) xor ct[i-1])}
      buf := IV;
      IV  := PBFBlock(ctp)^;
      BF_Decrypt(ctx, IV, PBFBlock(ptp)^);
      BF_xorblock(PBFBlock(ptp)^, buf, PBFBlock(ptp)^);
      inc(Ptr2Inc(ptp),BFBLKSIZE);
      inc(Ptr2Inc(ctp),BFBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing, L=ILen (Schneier's n)}
      buf := IV;                       {C(L-2)}
      BF_Decrypt(ctx, PBFBlock(ctp)^, IV);
      inc(Ptr2Inc(ctp),BFBLKSIZE);
      fillchar(tmp,sizeof(tmp),0);
      move(PBFBlock(ctp)^,tmp,m);     {c[L]|0}
      BF_xorblock(tmp,IV,IV);
      tmp := IV;
      move(PBFBlock(ctp)^,tmp,m);     {c[L]| C'}
      BF_Decrypt(ctx,tmp,tmp);
      BF_xorblock(tmp, buf, PBFBlock(ptp)^);
      inc(Ptr2Inc(ptp),BFBLKSIZE);
      move(IV,PBFBlock(ptp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;

end;

end.
