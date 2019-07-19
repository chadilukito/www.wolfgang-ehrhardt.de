unit SJ_ECB;

(*************************************************************************

 DESCRIPTION     :  SkipJack ECB functions

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP, WDOSX

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., ch. 9.1

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     03.06.09  W.Ehrhardt  Initial version a la XT_ECB
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


function  SJ_ECB_Init({$ifdef CONST} const {$else} var {$endif} Key; KeyBytes: word; var ctx: TSJContext): integer;
  {-SkipJack key expansion, error if invalid key size}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_ECB_Reset(var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag}
  {$ifdef DLL} stdcall; {$endif}

function  SJ_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}
  {$ifdef DLL} stdcall; {$endif}

function  SJ_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
procedure SJ_ECB_Reset(var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag}
begin
  SJ_Reset(ctx);
end;


{---------------------------------------------------------------------------}
function SJ_ECB_Init({$ifdef CONST} const {$else} var {$endif} Key; KeyBytes: word; var ctx: TSJContext): integer;
  {-SkipJack key expansion, error if invalid key size}
begin
  SJ_ECB_Init := SJ_Init(Key, KeyBytes, ctx);
end;



{---------------------------------------------------------------------------}
function SJ_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}
var
  i,n: longint;
  m: word;
  tmp: TSJBlock;
begin

  SJ_ECB_Encrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SJ_ECB_Encrypt := SJ_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SJ_ECB_Encrypt := SJ_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div SJBLKSIZE; {Full blocks}
  m := ILen mod SJBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      SJ_ECB_Encrypt := SJ_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    SJ_ECB_Encrypt := SJ_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      SJ_Encrypt(ctx, PSJBlock(ptp)^, PSJBlock(ctp)^);
      inc(Ptr2Inc(ptp),SJBLKSIZE);
      inc(Ptr2Inc(ctp),SJBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      SJ_Encrypt(ctx, PSJBlock(ptp)^, buf);
      inc(Ptr2Inc(ptp),SJBLKSIZE);
      tmp := buf;
      move(PSJBlock(ptp)^, tmp, m);
      SJ_Encrypt(ctx, tmp, PSJBlock(ctp)^);
      inc(Ptr2Inc(ctp),SJBLKSIZE);
      move(buf,PSJBlock(ctp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;
end;


{---------------------------------------------------------------------------}
function SJ_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}
var
  i,n: longint;
  m: word;
  tmp: TSJBlock;
begin

  SJ_ECB_Decrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SJ_ECB_Decrypt := SJ_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SJ_ECB_Decrypt := SJ_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div SJBLKSIZE; {Full blocks}
  m := ILen mod SJBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      SJ_ECB_Decrypt := SJ_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    SJ_ECB_Decrypt := SJ_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      SJ_Decrypt(ctx, PSJBlock(ctp)^, PSJBlock(ptp)^);
      inc(Ptr2Inc(ptp),SJBLKSIZE);
      inc(Ptr2Inc(ctp),SJBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      SJ_Decrypt(ctx, PSJBlock(ctp)^, buf);
      inc(Ptr2Inc(ctp),SJBLKSIZE);
      tmp := buf;
      move(PSJBlock(ctp)^, tmp, m);
      SJ_Decrypt(ctx, tmp, PSJBlock(ptp)^);
      inc(Ptr2Inc(ptp),SJBLKSIZE);
      move(buf,PSJBlock(ptp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;
end;

end.
