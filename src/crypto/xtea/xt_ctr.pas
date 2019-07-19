unit XT_CTR;

(*************************************************************************

 DESCRIPTION   : XTEA CTR mode functions
                 Because of buffering en/decrypting is associative
                 User can supply a custom increment function

 REQUIREMENTS  : TP5-7, D1-D7/D9-D10/D12, FPC, VP, WDOSX

 EXTERNAL DATA : ---

 MEMORY USAGE  : ---

 DISPLAY MODE  : ---

 REFERENCES    : B.Schneier, Applied Cryptography, 2nd ed., ch. 9.9

 REMARKS       : - If a predefined or user-supplied INCProc is used, it must
                   be set before using XT_CTR_Seek.
                 - XT_CTR_Seek may be time-consuming for user-defined
                   INCProcs, because this function is called many times.
                   See XT_CTR_Seek how to provide user-supplied short-cuts.

 WARNING       : - CTR mode demands that the same key / initial CTR pair is
                   never reused for encryption. This requirement is especially
                   important for the CTR_Seek function. If different data is
                   written to the same position there will be leakage of
                   information about the plaintexts. Therefore CTR_Seek should
                   normally be used for random reads only.

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     01.01.05  W.Ehrhardt  Initial version a la BF_CTR
 0.11     22.06.08  we          Make IncProcs work with FPC -dDebug
 0.12     24.11.08  we          Uses BTypes
 0.13     06.08.10  we          Longint ILen
 0.14     06.08.10  we          XT_CTR_Seek, XT_CTR_Seek64 via xt_seek.inc
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

function  XT_CTR_Init(const Key; KeyBytes: word; const CTR: TXTBlock; var ctx: TXTContext): integer;
  {-XTEA key expansion, error if inv. key size, encrypt CTR}
  {$ifdef DLL} stdcall; {$endif}

procedure XT_CTR_Reset(const CTR: TXTBlock; var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag, encrypt CTR}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  XT_CTR_Init(var Key; KeyBytes: word; var CTR: TXTBlock; var ctx: TXTContext): integer;
  {-XTEA key expansion, error if inv. key size, encrypt CTR}

procedure XT_CTR_Reset(var CTR: TXTBlock; var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag, encrypt CTR}

{$endif}

{$ifndef DLL}
function  XT_CTR_Seek({$ifdef CONST}const{$else}var{$endif} iCTR: TXTBlock;
                      SOL, SOH: longint; var ctx: TXTContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SOH*2^32+SOL,}
  { SOH >= 0. iCTR is the initial CTR for offset 0, i.e. the same as in XT_CTR_Init.}

{$ifdef HAS_INT64}
function XT_CTR_Seek64(const iCTR: TXTBlock; SO: int64; var ctx: TXTContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SO >= 0;}
  { iCTR is the initial CTR value for offset 0, i.e. the same as in XT_CTR_Init.}
{$endif}
{$endif}

function  XT_CTR_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}
  {$ifdef DLL} stdcall; {$endif}

function  XT_CTR_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}
  {$ifdef DLL} stdcall; {$endif}

function  XT_SetIncProc(IncP: TXTIncProc; var ctx: TXTContext): integer;
  {-Set user supplied IncCTR proc}
  {$ifdef DLL} stdcall; {$endif}

procedure XT_IncMSBFull(var CTR: TXTBlock);
  {-Increment CTR[7]..CTR[0]}
  {$ifdef DLL} stdcall; {$endif}

procedure XT_IncLSBFull(var CTR: TXTBlock);
  {-Increment CTR[0]..CTR[7]}
  {$ifdef DLL} stdcall; {$endif}

procedure XT_IncMSBPart(var CTR: TXTBlock);
  {-Increment CTR[7]..CTR[4]}
  {$ifdef DLL} stdcall; {$endif}

procedure XT_IncLSBPart(var CTR: TXTBlock);
  {-Increment CTR[0]..CTR[3]}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
procedure XT_IncMSBPart(var CTR: TXTBlock);
  {-Increment CTR[7]..CTR[4]}
var
  j: integer;
begin
  for j:=7 downto 4 do begin
    if CTR[j]=$FF then CTR[j] := 0
    else begin
      inc(CTR[j]);
      exit;
    end;
  end;
end;


{---------------------------------------------------------------------------}
procedure XT_IncLSBPart(var CTR: TXTBlock);
  {-Increment CTR[0]..CTR[3]}
var
  j: integer;
begin
  for j:=0 to 3 do begin
    if CTR[j]=$FF then CTR[j] := 0
    else begin
      inc(CTR[j]);
      exit;
    end;
  end;
end;


{---------------------------------------------------------------------------}
procedure XT_IncMSBFull(var CTR: TXTBlock);
  {-Increment CTR[7]..CTR[0]}
var
  j: integer;
begin
  for j:=7 downto 0 do begin
    if CTR[j]=$FF then CTR[j] := 0
    else begin
      inc(CTR[j]);
      exit;
    end;
  end;
end;


{---------------------------------------------------------------------------}
procedure XT_IncLSBFull(var CTR: TXTBlock);
  {-Increment CTR[0]..CTR[7]}
var
  j: integer;
begin
  for j:=0 to 7 do begin
    if CTR[j]=$FF then CTR[j] := 0
    else begin
      inc(CTR[j]);
      exit;
    end;
  end;
end;


{---------------------------------------------------------------------------}
function XT_SetIncProc(IncP: TXTIncProc; var ctx: TXTContext): integer;
  {-Set user supplied IncCTR proc}
begin
  XT_SetIncProc := XT_Err_MultipleIncProcs;
  with ctx do begin
    {$ifdef FPC}
      if IncProc=nil then begin
        IncProc := IncP;
        XT_SetIncProc := 0;
      end;
    {$else}
      if @IncProc=nil then begin
        IncProc := IncP;
        XT_SetIncProc := 0;
      end;
    {$endif}
  end;
end;


{---------------------------------------------------------------------------}
{$ifdef CONST}
function XT_CTR_Init(const Key; KeyBytes: word; const CTR: TXTBlock; var ctx: TXTContext): integer;
{$else}
function XT_CTR_Init(var Key; KeyBytes: word; var CTR: TXTBlock; var ctx: TXTContext): integer;
{$endif}
  {-XTEA key expansion, error if inv. key size, encrypt CTR}
var
  err: integer;
begin
  err := XT_Init(Key, KeyBytes, ctx);
  if err=0 then begin
    ctx.IV := CTR;
    {encrypt CTR}
    XT_Encrypt(ctx, CTR, ctx.buf);
  end;
  XT_CTR_Init := err;
end;


{---------------------------------------------------------------------------}
procedure XT_CTR_Reset({$ifdef CONST}const {$else} var {$endif}  CTR: TXTBlock; var ctx: TXTContext);
  {-Clears ctx fields bLen and Flag, encrypt CTR}
begin
  XT_Reset(ctx);
  ctx.IV := CTR;
  XT_Encrypt(ctx, CTR, ctx.buf);
end;


{---------------------------------------------------------------------------}
function XT_CTR_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}
begin
  XT_CTR_Encrypt := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      XT_CTR_Encrypt := XT_Err_NIL_Pointer; {nil pointer to block with nonzero length}
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      XT_CTR_Encrypt := XT_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  if ctx.blen=0 then begin
    {Handle full blocks first}
    while ILen>=XTBLKSIZE do with ctx do begin
      {Cipher text = plain text xor encr(CTR)}
      XT_XorBlock(PXTBlock(ptp)^, buf, PXTBlock(ctp)^);
      inc(Ptr2Inc(ptp), XTBLKSIZE);
      inc(Ptr2Inc(ctp), XTBLKSIZE);
      dec(ILen, XTBLKSIZE);
      {use XT_IncMSBFull if IncProc=nil}
      {$ifdef FPC}
        if IncProc=nil then XT_IncMSBFull(IV) else IncProc(IV);
      {$else}
        if @IncProc=nil then XT_IncMSBFull(IV) else IncProc(IV);
      {$endif}
      XT_Encrypt(ctx, IV, buf);
    end;
  end;

  {Handle remaining bytes}
  while ILen>0 do with ctx do begin
    {Refill buffer with encrypted CTR}
    if bLen>=XTBLKSIZE then begin
      {use XT_IncMSBFull if IncProc=nil}
      {$ifdef FPC}
        if IncProc=nil then XT_IncMSBFull(IV) else IncProc(IV);
      {$else}
        if @IncProc=nil then XT_IncMSBFull(IV) else IncProc(IV);
      {$endif}
      XT_Encrypt(ctx, IV, buf);
      bLen := 0;
    end;
    {Cipher text = plain text xor encr(CTR)}
    pByte(ctp)^ := buf[bLen] xor pByte(ptp)^;
    inc(bLen);
    inc(Ptr2Inc(ptp));
    inc(Ptr2Inc(ctp));
    dec(ILen);
  end;
end;


{---------------------------------------------------------------------------}
function XT_CTR_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TXTContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}
begin
  {Decrypt = encrypt for CTR mode}
  XT_CTR_Decrypt := XT_CTR_Encrypt(ctp, ptp, ILen, ctx);
end;


{$ifndef DLL}
  {$i xt_seek.inc}
{$endif}


end.
