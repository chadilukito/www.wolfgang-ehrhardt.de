unit SC_CTR;

(*************************************************************************

 DESCRIPTION   : SHACAL-2 CTR mode functions
                 Because of buffering en/decrypting is associative
                 User can supply a custom increment function

 REQUIREMENTS  : TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA : ---

 MEMORY USAGE  : ---

 DISPLAY MODE  : ---

 REFERENCES    : B.Schneier, Applied Cryptography, 2nd ed., ch. 9.9

 REMARKS       : - If a predefined or user-supplied INCProc is used, it must
                   be set before using SC_CTR_Seek.
                 - SC_CTR_Seek may be time-consuming for user-defined
                   INCProcs, because this function is called many times.
                   See SC_CTR_Seek how to provide user-supplied short-cuts.

 WARNING       : - CTR mode demands that the same key / initial CTR pair is
                   never reused for encryption. This requirement is especially
                   important for the CTR_Seek function. If different data is
                   written to the same position there will be leakage of
                   information about the plaintexts. Therefore CTR_Seek should
                   normally be used for random reads only.

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     02.01.05  we          Initial version a la AES-CTR/SC_CBC
 0.11     02.01.05  we          SC_CTR_Reset
 0.12     01.06.05  we          Bugfix SC_IncXXX boundaries
 0.13     22.06.08  we          Make IncProcs work with FPC -dDebug
 0.14     24.11.08  we          Uses BTypes
 0.15     06.08.10  we          SC_CTR_Seek, SC_CTR_Seek64 via sc_seek.inc
 0.16     06.08.10  we          Longint ILen
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

function  SC_CTR_Init(const Key; KeyBytes: word; const CTR: TSCBlock; var ctx: TSCContext): integer;
  {-SHACAL-2 key expansion, error if inv. key size, encrypt CTR}
  {$ifdef DLL} stdcall; {$endif}

procedure SC_CTR_Reset(const CTR: TSCBlock; var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag, encrypt CTR}
  {$ifdef DLL} stdcall; {$endif}

{$else}

function  SC_CTR_Init(var Key; KeyBytes: word; var CTR: TSCBlock; var ctx: TSCContext): integer;
  {-SHACAL-2 key expansion, error if inv. key size, encrypt CTR}

procedure SC_CTR_Reset(var CTR: TSCBlock; var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag, encrypt CTR}

{$endif}


{$ifndef DLL}
function  SC_CTR_Seek({$ifdef CONST}const{$else}var{$endif} iCTR: TSCBlock;
                      SOL, SOH: longint; var ctx: TSCContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SOH*2^32+SOL,}
  { SOH >= 0. iCTR is the initial CTR for offset 0, i.e. the same as in SC_CTR_Init.}

{$ifdef HAS_INT64}
function SC_CTR_Seek64(const iCTR: TSCBlock; SO: int64; var ctx: TSCContext): integer;
  {-Setup ctx for random access crypto stream starting at 64 bit offset SO >= 0;}
  { iCTR is the initial CTR value for offset 0, i.e. the same as in SC_CTR_Init.}
{$endif}
{$endif}



function  SC_CTR_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}
  {$ifdef DLL} stdcall; {$endif}

function  SC_CTR_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}
  {$ifdef DLL} stdcall; {$endif}

function  SC_SetIncProc(IncP: TSCIncProc; var ctx: TSCContext): integer;
  {-Set user supplied IncCTR proc}
  {$ifdef DLL} stdcall; {$endif}

procedure SC_IncMSBFull(var CTR: TSCBlock);
  {-Increment CTR[31]..CTR[0]}
  {$ifdef DLL} stdcall; {$endif}

procedure SC_IncLSBFull(var CTR: TSCBlock);
  {-Increment CTR[0]..CTR[31]}
  {$ifdef DLL} stdcall; {$endif}

procedure SC_IncMSBPart(var CTR: TSCBlock);
  {-Increment CTR[31]..CTR[16]}
  {$ifdef DLL} stdcall; {$endif}

procedure SC_IncLSBPart(var CTR: TSCBlock);
  {-Increment CTR[0]..CTR[15]}
  {$ifdef DLL} stdcall; {$endif}


implementation


{---------------------------------------------------------------------------}
procedure SC_IncMSBPart(var CTR: TSCBlock);
  {-Increment CTR[31]..CTR[16]}
var
  j: integer;
begin
  for j:=31 downto 16 do begin
    if CTR[j]=$FF then CTR[j] := 0
    else begin
      inc(CTR[j]);
      exit;
    end;
  end;
end;


{---------------------------------------------------------------------------}
procedure SC_IncLSBPart(var CTR: TSCBlock);
  {-Increment CTR[0]..CTR[15]}
var
  j: integer;
begin
  for j:=0 to 15 do begin
    if CTR[j]=$FF then CTR[j] := 0
    else begin
      inc(CTR[j]);
      exit;
    end;
  end;
end;


{---------------------------------------------------------------------------}
procedure SC_IncMSBFull(var CTR: TSCBlock);
  {-Increment CTR[31]..CTR[0]}
var
  j: integer;
begin
  for j:=31 downto 0 do begin
    if CTR[j]=$FF then CTR[j] := 0
    else begin
      inc(CTR[j]);
      exit;
    end;
  end;
end;


{---------------------------------------------------------------------------}
procedure SC_IncLSBFull(var CTR: TSCBlock);
  {-Increment CTR[0]..CTR[31]}
var
  j: integer;
begin
  for j:=0 to 31 do begin
    if CTR[j]=$FF then CTR[j] := 0
    else begin
      inc(CTR[j]);
      exit;
    end;
  end;
end;


{---------------------------------------------------------------------------}
function SC_SetIncProc(IncP: TSCIncProc; var ctx: TSCContext): integer;
  {-Set user supplied IncCTR proc}
begin
  SC_SetIncProc := SC_Err_MultipleIncProcs;
  with ctx do begin
    {$ifdef FPC}
      if IncProc=nil then begin
        IncProc := IncP;
        SC_SetIncProc := 0;
      end;
    {$else}
      if @IncProc=nil then begin
        IncProc := IncP;
        SC_SetIncProc := 0;
      end;
    {$endif}
  end;
end;


{---------------------------------------------------------------------------}
{$ifdef CONST}
function SC_CTR_Init(const Key; KeyBytes: word; const CTR: TSCBlock; var ctx: TSCContext): integer;
{$else}
function SC_CTR_Init(var Key; KeyBytes: word; var CTR: TSCBlock; var ctx: TSCContext): integer;
{$endif}
  {-SHACAL-2 key expansion, error if inv. key size, encrypt CTR}
var
  err: integer;
begin
  err := SC_Init(Key, KeyBytes, ctx);
  if err=0 then begin
    ctx.IV := CTR;
    {encrypt CTR}
    SC_Encrypt(ctx, CTR, ctx.buf);
  end;
  SC_CTR_Init := err;
end;


{---------------------------------------------------------------------------}
procedure SC_CTR_Reset({$ifdef CONST}const {$else} var {$endif}  CTR: TSCBlock; var ctx: TSCContext);
  {-Clears ctx fields bLen and Flag, encrypt CTR}
begin
  SC_Reset(ctx);
  ctx.IV := CTR;
  SC_Encrypt(ctx, CTR, ctx.buf);
end;


{---------------------------------------------------------------------------}
function SC_CTR_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode}
begin
  SC_CTR_Encrypt := 0;

  if (ptp=nil) or (ctp=nil) then begin
    if ILen>0 then begin
      SC_CTR_Encrypt := SC_Err_NIL_Pointer; {nil pointer to block with nonzero length}
      exit;
    end;
  end;

  {$ifdef BIT16}
    if (ofs(ptp^)+ILen>$FFFF) or (ofs(ctp^)+ILen>$FFFF) then begin
      SC_CTR_Encrypt := SC_Err_Invalid_16Bit_Length;
      exit;
    end;
  {$endif}

  if ctx.blen=0 then begin
    {Handle full blocks first}
    while ILen>=SCBLKSIZE do with ctx do begin
      {Cipher text = plain text xor encr(CTR)}
      SC_XorBlock(PSCBlock(ptp)^, buf, PSCBlock(ctp)^);
      inc(Ptr2Inc(ptp), SCBLKSIZE);
      inc(Ptr2Inc(ctp), SCBLKSIZE);
      dec(ILen, SCBLKSIZE);
      {use SC_IncMSBFull if IncProc=nil}
      {$ifdef FPC}
        if IncProc=nil then SC_IncMSBFull(IV) else IncProc(IV);
      {$else}
        if @IncProc=nil then SC_IncMSBFull(IV) else IncProc(IV);
      {$endif}
      SC_Encrypt(ctx, IV, buf);
    end;
  end;

  {Handle remaining bytes}
  while ILen>0 do with ctx do begin
    {Refill buffer with encrypted CTR}
    if bLen>=SCBLKSIZE then begin
      {use SC_IncMSBFull if IncProc=nil}
      {$ifdef FPC}
        if IncProc=nil then SC_IncMSBFull(IV) else IncProc(IV);
      {$else}
        if @IncProc=nil then SC_IncMSBFull(IV) else IncProc(IV);
      {$endif}
      SC_Encrypt(ctx, IV, buf);
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
function SC_CTR_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TSCContext): integer;
  {-Decrypt ILen bytes from ctp^ to ptp^ in CTR mode}
begin
  {Decrypt = encrypt for CTR mode}
  SC_CTR_Decrypt := SC_CTR_Encrypt(ctp, ptp, ILen, ctx);
end;


{$ifndef DLL}
  {$i sc_seek.inc}
{$endif}


end.
