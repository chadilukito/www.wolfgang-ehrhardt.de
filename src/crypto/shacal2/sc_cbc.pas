unit SC_CBC;

(*************************************************************************

 DESCRIPTION     :  SHACAL-2 CBC functions

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., ch. 9.3


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     02.01.05  we          Initial version analog AES_CBC
 0.11     02.01.05  we          SC_CBC_Reset
 0.12     02.01.05  we          No more processing after short block
 0.13     24.11.08  we          Uses BTypes
 0.14     06.08.10  we          Longint ILen
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

function  SC_CBC_Init(const Key; KeyBytes: word; const IV: TSCBlock; var ctx: TSCContext): integer;
  {-SHACAL-2 key expansion, error if invalid key size, save IV}
  {$ifdef DLL} stdcall; {$endif}

procedure SC_CBC_Reset(const IV: TSCBlock; var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag, save IV}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  SC_CBC_Init(var Key; KeyBytes: word; var IV: TSCBlock; var ctx: TSCContext): integer;
  {-SHACAL-2 key expansion, error if invalid key size, save IV}

procedure SC_CBC_Reset(var IV: TSCBlock; var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag, save IV}

{$endif}


function  SC_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}
  {$ifdef DLL} stdcall; {$endif}

function  SC_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
{$ifdef CONST}
  function SC_CBC_Init(const Key; KeyBytes: word; const IV: TSCBlock; var ctx: TSCContext): integer;
{$else}
  function SC_CBC_Init(var Key; KeyBytes: word; var IV: TSCBlock; var ctx: TSCContext): integer;
{$endif}
  {-SHACAL-2 key expansion, error if invalid key size, encrypt IV}
begin
  SC_CBC_Init := SC_Init(Key, KeyBytes, ctx);
  ctx.IV := IV;
end;


{---------------------------------------------------------------------------}
procedure SC_CBC_Reset({$ifdef CONST}const {$else} var {$endif} IV: TSCBlock; var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag, save IV}
begin
  SC_Reset(ctx);
  ctx.IV := IV;
end;


{---------------------------------------------------------------------------}
function SC_CBC_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CBC mode}
var
  i,n: longint;
  m: word;
begin

  SC_CBC_Encrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SC_CBC_Encrypt := SC_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SC_CBC_Encrypt := SC_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div SCBLKSIZE; {Full blocks}
  m := ILen mod SCBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      SC_CBC_Encrypt := SC_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    SC_CBC_Encrypt := SC_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      {ct[i] = encr(ct[i-1] xor pt[i])}
      SC_xorblock(PSCBlock(ptp)^, IV, IV);
      SC_Encrypt(ctx, IV, IV);
      PSCBlock(ctp)^ := IV;
      inc(Ptr2Inc(ptp),SCBLKSIZE);
      inc(Ptr2Inc(ctp),SCBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      SC_xorblock(PSCBlock(ptp)^, IV, IV);
      SC_Encrypt(ctx, IV, IV);
      buf := IV;
      inc(Ptr2Inc(ptp),SCBLKSIZE);
      for i:=0 to m-1 do IV[i] := IV[i] xor PSCBlock(ptp)^[i];
      SC_Encrypt(ctx, IV, PSCBlock(ctp)^);
      inc(Ptr2Inc(ctp),SCBLKSIZE);
      move(buf,PSCBlock(ctp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;

end;


{---------------------------------------------------------------------------}
function SC_CBC_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CBC mode}
var
  i,n: longint;
  m: word;
  tmp: TSCBlock;
begin

  SC_CBC_Decrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SC_CBC_Decrypt := SC_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SC_CBC_Decrypt := SC_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div SCBLKSIZE; {Full blocks}
  m := ILen mod SCBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      SC_CBC_Decrypt := SC_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    SC_CBC_Decrypt := SC_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      {pt[i] = decr(ct[i]) xor ct[i-1])}
      buf := IV;
      IV  := PSCBlock(ctp)^;
      SC_Decrypt(ctx, IV, PSCBlock(ptp)^);
      SC_xorblock(PSCBlock(ptp)^, buf, PSCBlock(ptp)^);
      inc(Ptr2Inc(ptp),SCBLKSIZE);
      inc(Ptr2Inc(ctp),SCBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing, L=ILen (Schneier's n)}
      buf := IV;                       {C(L-2)}
      SC_Decrypt(ctx, PSCBlock(ctp)^, IV);
      inc(Ptr2Inc(ctp),SCBLKSIZE);
      fillchar(tmp,sizeof(tmp),0);
      move(PSCBlock(ctp)^,tmp,m);     {c[L]|0}
      SC_xorblock(tmp,IV,IV);
      tmp := IV;
      move(PSCBlock(ctp)^,tmp,m);     {c[L]| C'}
      SC_Decrypt(ctx,tmp,tmp);
      SC_xorblock(tmp, buf, PSCBlock(ptp)^);
      inc(Ptr2Inc(ptp),SCBLKSIZE);
      move(IV,PSCBlock(ptp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;

end;

end.
