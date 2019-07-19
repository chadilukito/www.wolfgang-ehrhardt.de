unit SJ_CTR;

(*************************************************************************

 DESCRIPTION   : SkipJack CTR mode functions
                 Because of buffering en/decrypting is associative
                 User can supply custom increment functions

 REQUIREMENTS  : TP5-7, D1-D7/D9-D10/D12, FPC, VP, WDOSX

 EXTERNAL DATA : ---

 MEMORY USAGE  : ---

 DISPLAY MODE  : ---

 REFERENCES    : B.Schneier, Applied Cryptography, 2nd ed., ch. 9.9

 REMARKS       : - If a predefined or user-supplied INCProc is used, it must
                   be set before using SJ_CTR_Seek.
                 - SJ_CTR_Seek may be time-consuming for user-defined
                   INCProcs, because this function is called many times.
                   See SJ_CTR_Seek how to provide user-supplied short-cuts.

 WARNING       : - CTR mode demands that the same key / initial CTR pair is
                   never reused for encryption. This requirement is especially
                   important for the CTR_Seek function. If different data is
                   written to the same position there will be leakage of
                   information about the plaintexts. Therefore CTR_Seek should
                   normally be used for random reads only.

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     03.06.09  W.Ehrhardt  Initial version a la XT_CTR
 0.11     06.08.10  we          Longint ILen, XT_CTR_Seek/64 via xt_seek.inc
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

function  SJ_CTR_Init(const Key; KeyBytes: word; const CTR: TSJBlock; var ctx: TSJContext): integer;
  {-SkipJack key expansion, error if inv. key size, encrypt CTR}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_CTR_Reset(const CTR: TSJBlock; var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag, encrypt CTR}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  SJ_CTR_Init(var Key; KeyBytes: word; var CTR: TSJBlock; var ctx: TSJContext): integer;
  {-SkipJack key expansion, error if inv. key size, encrypt CTR}

procedure SJ_CTR_Reset(var CTR: TSJBlock; var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag, encrypt CTR}

{$endif}

{$ifndef DLL}
function  SJ_CTR_Seek({$ifdef CONST}const{$else}var{$endif} iCTR: TSJBlock;
                       SOL, SOH: longint; var ctx: TSJContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SOH*2^32+SOL,}
  { SOH >= 0. iCTR is the initial CTR for offset 0, i.e. the same as in SJ_CTR_Init.}

{$ifdef HAS_INT64}
function SJ_CTR_Seek64(const iCTR: TSJBlock; SO: int64; var ctx: TSJContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SO >= 0;}
  { iCTR is the initial CTR value for offset 0, i.e. the same as in SJ_CTR_Init.}
{$endif}
{$endif}

function  SJ_CTR_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}
  {$ifdef DLL} stdcall; {$endif}

function  SJ_CTR_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}
  {$ifdef DLL} stdcall; {$endif}

function  SJ_SetIncProc(IncP: TSJIncProc; var ctx: TSJContext): integer;
  {-Set user supplied IncCTR proc}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_IncMSBFull(var CTR: TSJBlock);
  {-Increment CTR[7]..CTR[0]}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_IncLSBFull(var CTR: TSJBlock);
  {-Increment CTR[0]..CTR[7]}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_IncMSBPart(var CTR: TSJBlock);
  {-Increment CTR[7]..CTR[4]}
  {$ifdef DLL} stdcall; {$endif}

procedure SJ_IncLSBPart(var CTR: TSJBlock);
  {-Increment CTR[0]..CTR[3]}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
procedure SJ_IncMSBPart(var CTR: TSJBlock);
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
procedure SJ_IncLSBPart(var CTR: TSJBlock);
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
procedure SJ_IncMSBFull(var CTR: TSJBlock);
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
procedure SJ_IncLSBFull(var CTR: TSJBlock);
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
function SJ_SetIncProc(IncP: TSJIncProc; var ctx: TSJContext): integer;
  {-Set user supplied IncCTR proc}
begin
  SJ_SetIncProc := SJ_Err_MultipleIncProcs;
  with ctx do begin
    {$ifdef FPC}
      if IncProc=nil then begin
        IncProc := IncP;
        SJ_SetIncProc := 0;
      end;
    {$else}
      if @IncProc=nil then begin
        IncProc := IncP;
        SJ_SetIncProc := 0;
      end;
    {$endif}
  end;
end;


{---------------------------------------------------------------------------}
{$ifdef CONST}
function SJ_CTR_Init(const Key; KeyBytes: word; const CTR: TSJBlock; var ctx: TSJContext): integer;
{$else}
function SJ_CTR_Init(var Key; KeyBytes: word; var CTR: TSJBlock; var ctx: TSJContext): integer;
{$endif}
  {-SkipJack key expansion, error if inv. key size, encrypt CTR}
var
  err: integer;
begin
  err := SJ_Init(Key, KeyBytes, ctx);
  if err=0 then begin
    ctx.IV := CTR;
    {encrypt CTR}
    SJ_Encrypt(ctx, CTR, ctx.buf);
  end;
  SJ_CTR_Init := err;
end;


{---------------------------------------------------------------------------}
procedure SJ_CTR_Reset({$ifdef CONST}const {$else} var {$endif}  CTR: TSJBlock; var ctx: TSJContext);
  {-Clears ctx fields bLen and Flag, encrypt CTR}
begin
  SJ_Reset(ctx);
  ctx.IV := CTR;
  SJ_Encrypt(ctx, CTR, ctx.buf);
end;


{---------------------------------------------------------------------------}
function SJ_CTR_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}
begin
  SJ_CTR_Encrypt := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SJ_CTR_Encrypt := SJ_Err_NIL_Pointer; {nil pointer to block with nonzero length}
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SJ_CTR_Encrypt := SJ_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  if ctx.blen=0 then begin
    {Handle full blocks first}
    while ILen>=SJBLKSIZE do with ctx do begin
      {Cipher text = plain text xor encr(CTR)}
      SJ_XorBlock(PSJBlock(ptp)^, buf, PSJBlock(ctp)^);
      inc(Ptr2Inc(ptp), SJBLKSIZE);
      inc(Ptr2Inc(ctp), SJBLKSIZE);
      dec(ILen, SJBLKSIZE);
      {use SJ_IncMSBFull if IncProc=nil}
      {$ifdef FPC}
        if IncProc=nil then SJ_IncMSBFull(IV) else IncProc(IV);
      {$else}
        if @IncProc=nil then SJ_IncMSBFull(IV) else IncProc(IV);
      {$endif}
      SJ_Encrypt(ctx, IV, buf);
    end;
  end;

  {Handle remaining bytes}
  while ILen>0 do with ctx do begin
    {Refill buffer with encrypted CTR}
    if bLen>=SJBLKSIZE then begin
      {use SJ_IncMSBFull if IncProc=nil}
      {$ifdef FPC}
        if IncProc=nil then SJ_IncMSBFull(IV) else IncProc(IV);
      {$else}
        if @IncProc=nil then SJ_IncMSBFull(IV) else IncProc(IV);
      {$endif}
      SJ_Encrypt(ctx, IV, buf);
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
function SJ_CTR_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSJContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}
begin
  {Decrypt = encrypt for CTR mode}
  SJ_CTR_Decrypt := SJ_CTR_Encrypt(ctp, ptp, ILen, ctx);
end;


{$ifndef DLL}
  {$i sj_seek.inc}
{$endif}


end.
