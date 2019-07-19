unit SEA_ECB;

(*************************************************************************

 DESCRIPTION     :  SEED ECB functions

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., ch. 9.1


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     07.06.07  W.Ehrhardt  Initial version analog TF_ECB
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


function  SEA_ECB_Init({$ifdef CONST} const {$else} var {$endif} Key; KeyBits: word; var ctx: TSEAContext): integer;
  {-SEED key expansion, error if invalid key size}
  {$ifdef DLL} stdcall; {$endif}

procedure SEA_ECB_Reset(var ctx: TSEAContext);
  {-Clears ctx fields bLen and Flag}
  {$ifdef DLL} stdcall; {$endif}

function  SEA_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}
  {$ifdef DLL} stdcall; {$endif}

function  SEA_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
procedure SEA_ECB_Reset(var ctx: TSEAContext);
  {-Clears ctx fields bLen and Flag}
begin
  SEA_Reset(ctx);
end;


{---------------------------------------------------------------------------}
function SEA_ECB_Init({$ifdef CONST} const {$else} var {$endif} Key; KeyBits: word; var ctx: TSEAContext): integer;
  {-SEED key expansion, error if invalid key size}
begin
  SEA_ECB_Init := SEA_Init(Key, KeyBits, ctx);
end;



{---------------------------------------------------------------------------}
function SEA_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}
var
  i,n: longint;
  m: word;
  tmp: TSEABlock;
begin

  SEA_ECB_Encrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SEA_ECB_Encrypt := SEA_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SEA_ECB_Encrypt := SEA_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div SEABLKSIZE; {Full blocks}
  m := ILen mod SEABLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      SEA_ECB_Encrypt := SEA_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    SEA_ECB_Encrypt := SEA_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      SEA_Encrypt(ctx, PSEABlock(ptp)^, PSEABlock(ctp)^);
      inc(Ptr2Inc(ptp),SEABLKSIZE);
      inc(Ptr2Inc(ctp),SEABLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      SEA_Encrypt(ctx, PSEABlock(ptp)^, buf);
      inc(Ptr2Inc(ptp),SEABLKSIZE);
      tmp := buf;
      move(PSEABlock(ptp)^, tmp, m);
      SEA_Encrypt(ctx, tmp, PSEABlock(ctp)^);
      inc(Ptr2Inc(ctp),SEABLKSIZE);
      move(buf,PSEABlock(ctp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;
end;


{---------------------------------------------------------------------------}
function SEA_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSEAContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}
var
  i,n: longint;
  m: word;
  tmp: TSEABlock;
begin

  SEA_ECB_Decrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SEA_ECB_Decrypt := SEA_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SEA_ECB_Decrypt := SEA_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div SEABLKSIZE; {Full blocks}
  m := ILen mod SEABLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      SEA_ECB_Decrypt := SEA_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    SEA_ECB_Decrypt := SEA_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      SEA_Decrypt(ctx, PSEABlock(ctp)^, PSEABlock(ptp)^);
      inc(Ptr2Inc(ptp),SEABLKSIZE);
      inc(Ptr2Inc(ctp),SEABLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      SEA_Decrypt(ctx, PSEABlock(ctp)^, buf);
      inc(Ptr2Inc(ctp),SEABLKSIZE);
      tmp := buf;
      move(PSEABlock(ctp)^, tmp, m);
      SEA_Decrypt(ctx, tmp, PSEABlock(ptp)^);
      inc(Ptr2Inc(ptp),SEABLKSIZE);
      move(buf,PSEABlock(ptp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;
end;


end.
