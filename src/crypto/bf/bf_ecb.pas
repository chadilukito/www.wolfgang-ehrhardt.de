unit BF_ECB;

(*************************************************************************

 DESCRIPTION     :  BF ECB functions

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  Blowfish: B.Schneier, Applied Cryptography, 2nd ed., ch. 14.3/9.1
                    Cipher text stealing: Schneier, ch.9.1

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     01.12.04  we          Initial version a la AES-ECB/BF_CBC
 0.11     01.12.04  we          BF_ECB_Reset
 0.12     23.11.08  we          Uses BTypes
 0.13     05.08.10  we          Longint ILen
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


function  BF_ECB_Init({$ifdef CONST} const {$else} var {$endif} Key; KeyBytes: word; var ctx: TBFContext): integer;
  {-BF key expansion, error if invalid key size}
  {$ifdef DLL} stdcall; {$endif}

procedure BF_ECB_Reset(var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag}
  {$ifdef DLL} stdcall; {$endif}

function  BF_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}
  {$ifdef DLL} stdcall; {$endif}

function  BF_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
procedure BF_ECB_Reset(var ctx: TBFContext);
  {-Clears ctx fields bLen and Flag}
begin
  BF_Reset(ctx);
end;


{---------------------------------------------------------------------------}
function BF_ECB_Init({$ifdef CONST} const {$else} var {$endif} Key; KeyBytes: word; var ctx: TBFContext): integer;
  {-BF key expansion, error if invalid key size}
begin
  BF_ECB_Init := BF_Init(Key, KeyBytes, ctx);
end;



{---------------------------------------------------------------------------}
function BF_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}
var
  i,n: longint;
  m: word;
  tmp: TBFBlock;
begin

  BF_ECB_Encrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      BF_ECB_Encrypt := BF_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      BF_ECB_Encrypt := BF_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div BFBLKSIZE; {Full blocks}
  m := ILen mod BFBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      BF_ECB_Encrypt := BF_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    BF_ECB_Encrypt := BF_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      BF_Encrypt(ctx, PBFBlock(ptp)^, PBFBlock(ctp)^);
      inc(Ptr2Inc(ptp),BFBLKSIZE);
      inc(Ptr2Inc(ctp),BFBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      BF_Encrypt(ctx, PBFBlock(ptp)^, buf);
      inc(Ptr2Inc(ptp),BFBLKSIZE);
      tmp := buf;
      move(PBFBlock(ptp)^, tmp, m);
      BF_Encrypt(ctx, tmp, PBFBlock(ctp)^);
      inc(Ptr2Inc(ctp),BFBLKSIZE);
      move(buf,PBFBlock(ctp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;
end;


{---------------------------------------------------------------------------}
function BF_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TBFContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}
var
  i,n: longint;
  m: word;
  tmp: TBFBlock;
begin

  BF_ECB_Decrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      BF_ECB_Decrypt := BF_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      BF_ECB_Decrypt := BF_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div BFBLKSIZE; {Full blocks}
  m := ILen mod BFBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      BF_ECB_Decrypt := BF_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    BF_ECB_Decrypt := BF_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      BF_Decrypt(ctx, PBFBlock(ctp)^, PBFBlock(ptp)^);
      inc(Ptr2Inc(ptp),BFBLKSIZE);
      inc(Ptr2Inc(ctp),BFBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      BF_Decrypt(ctx, PBFBlock(ctp)^, buf);
      inc(Ptr2Inc(ctp),BFBLKSIZE);
      tmp := buf;
      move(PBFBlock(ctp)^, tmp, m);
      BF_Decrypt(ctx, tmp, PBFBlock(ptp)^);
      inc(Ptr2Inc(ptp),BFBLKSIZE);
      move(buf,PBFBlock(ptp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;
end;

end.
