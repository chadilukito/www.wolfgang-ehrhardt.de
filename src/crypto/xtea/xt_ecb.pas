unit XT_ECB;

(*************************************************************************

 DESCRIPTION     :  XTEA ECB functions

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP, WDOSX

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., ch. 9.1

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     01.01.05  W.Ehrhardt  Initial version a la BF_ECB
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


function  XT_ECB_Init({$ifdef CONST} const {$else} var {$endif} Key; KeyBytes: word; var ctx: TXTContext): integer;
  {-XTEA key expansion, error if invalid key size}
  {$ifdef DLL} stdcall; {$endif}

procedure XT_ECB_Reset(var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag}
  {$ifdef DLL} stdcall; {$endif}

function  XT_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}
  {$ifdef DLL} stdcall; {$endif}

function  XT_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
procedure XT_ECB_Reset(var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag}
begin
  XT_Reset(ctx);
end;


{---------------------------------------------------------------------------}
function XT_ECB_Init({$ifdef CONST} const {$else} var {$endif} Key; KeyBytes: word; var ctx: TXTContext): integer;
  {-XTEA key expansion, error if invalid key size}
begin
  XT_ECB_Init := XT_Init(Key, KeyBytes, ctx);
end;



{---------------------------------------------------------------------------}
function XT_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}
var
  i,n: longint;
  m: word;
  tmp: TXTBlock;
begin

  XT_ECB_Encrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      XT_ECB_Encrypt := XT_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      XT_ECB_Encrypt := XT_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div XTBLKSIZE; {Full blocks}
  m := ILen mod XTBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      XT_ECB_Encrypt := XT_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    XT_ECB_Encrypt := XT_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      XT_Encrypt(ctx, PXTBlock(ptp)^, PXTBlock(ctp)^);
      inc(Ptr2Inc(ptp),XTBLKSIZE);
      inc(Ptr2Inc(ctp),XTBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      XT_Encrypt(ctx, PXTBlock(ptp)^, buf);
      inc(Ptr2Inc(ptp),XTBLKSIZE);
      tmp := buf;
      move(PXTBlock(ptp)^, tmp, m);
      XT_Encrypt(ctx, tmp, PXTBlock(ctp)^);
      inc(Ptr2Inc(ctp),XTBLKSIZE);
      move(buf,PXTBlock(ctp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;
end;


{---------------------------------------------------------------------------}
function XT_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}
var
  i,n: longint;
  m: word;
  tmp: TXTBlock;
begin

  XT_ECB_Decrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      XT_ECB_Decrypt := XT_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      XT_ECB_Decrypt := XT_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div XTBLKSIZE; {Full blocks}
  m := ILen mod XTBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      XT_ECB_Decrypt := XT_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    XT_ECB_Decrypt := XT_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      XT_Decrypt(ctx, PXTBlock(ctp)^, PXTBlock(ptp)^);
      inc(Ptr2Inc(ptp),XTBLKSIZE);
      inc(Ptr2Inc(ctp),XTBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      XT_Decrypt(ctx, PXTBlock(ctp)^, buf);
      inc(Ptr2Inc(ctp),XTBLKSIZE);
      tmp := buf;
      move(PXTBlock(ctp)^, tmp, m);
      XT_Decrypt(ctx, tmp, PXTBlock(ptp)^);
      inc(Ptr2Inc(ptp),XTBLKSIZE);
      move(buf,PXTBlock(ptp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;
end;

end.
