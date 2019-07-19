unit SC_ECB;

(*************************************************************************

 DESCRIPTION     :  SHACAL-2 ECB functions

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  B.Schneier, Applied Cryptography, 2nd ed., 9.1

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     02.01.05  we          Initial version a la AES-ECB/SC_CBC
 0.11     02.01.05  we          SC_ECB_Reset
 0.12     24.11.08  we          Uses BTypes
 0.13     06.08.10  we          Longint ILen
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


function  SC_ECB_Init({$ifdef CONST} const {$else} var {$endif} Key; KeyBytes: word; var ctx: TSCContext): integer;
  {-SHACAL-2 key expansion, error if invalid key size}
  {$ifdef DLL} stdcall; {$endif}

procedure SC_ECB_Reset(var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag}
  {$ifdef DLL} stdcall; {$endif}

function  SC_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}
  {$ifdef DLL} stdcall; {$endif}

function  SC_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
procedure SC_ECB_Reset(var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag}
begin
  SC_Reset(ctx);
end;


{---------------------------------------------------------------------------}
function SC_ECB_Init({$ifdef CONST} const {$else} var {$endif} Key; KeyBytes: word; var ctx: TSCContext): integer;
  {-SHACAL-2 key expansion, error if invalid key size}
begin
  SC_ECB_Init := SC_Init(Key, KeyBytes, ctx);
end;


{---------------------------------------------------------------------------}
function SC_ECB_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in ECB mode}
var
  i,n: longint;
  m: word;
  tmp: TSCBlock;
begin

  SC_ECB_Encrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SC_ECB_Encrypt := SC_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SC_ECB_Encrypt := SC_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div SCBLKSIZE; {Full blocks}
  m := ILen mod SCBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      SC_ECB_Encrypt := SC_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    SC_ECB_Encrypt := SC_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      SC_Encrypt(ctx, PSCBlock(ptp)^, PSCBlock(ctp)^);
      inc(Ptr2Inc(ptp),SCBLKSIZE);
      inc(Ptr2Inc(ctp),SCBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      SC_Encrypt(ctx, PSCBlock(ptp)^, buf);
      inc(Ptr2Inc(ptp),SCBLKSIZE);
      tmp := buf;
      move(PSCBlock(ptp)^, tmp, m);
      SC_Encrypt(ctx, tmp, PSCBlock(ctp)^);
      inc(Ptr2Inc(ctp),SCBLKSIZE);
      move(buf,PSCBlock(ctp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;
end;


{---------------------------------------------------------------------------}
function SC_ECB_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in ECB mode}
var
  i,n: longint;
  m: word;
  tmp: TSCBlock;
begin

  SC_ECB_Decrypt := 0;
  if ILen<0 then ILen := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SC_ECB_Decrypt := SC_Err_NIL_Pointer;
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SC_ECB_Decrypt := SC_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  n := ILen div SCBLKSIZE; {Full blocks}
  m := ILen mod SCBLKSIZE; {Remaining bytes in short block}
  if m<>0 then begin
    if n=0 then begin
      SC_ECB_Decrypt := SC_Err_Invalid_Length;
      exit;
    end;
    dec(n);           {CTS: special treatment of last TWO blocks}
  end;

  {Short block must be last, no more processing allowed}
  if ctx.Flag and 1 <> 0 then begin
    SC_ECB_Decrypt := SC_Err_Data_After_Short_Block;
    exit;
  end;

  with ctx do begin
    for i:=1 to n do begin
      SC_Decrypt(ctx, PSCBlock(ctp)^, PSCBlock(ptp)^);
      inc(Ptr2Inc(ptp),SCBLKSIZE);
      inc(Ptr2Inc(ctp),SCBLKSIZE);
    end;
    if m<>0 then begin
      {Cipher text stealing}
      SC_Decrypt(ctx, PSCBlock(ctp)^, buf);
      inc(Ptr2Inc(ctp),SCBLKSIZE);
      tmp := buf;
      move(PSCBlock(ctp)^, tmp, m);
      SC_Decrypt(ctx, tmp, PSCBlock(ptp)^);
      inc(Ptr2Inc(ptp),SCBLKSIZE);
      move(buf,PSCBlock(ptp)^,m);
      {Set short block flag}
      Flag := Flag or 1;
    end;
  end;
end;

end.
