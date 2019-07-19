unit ANU_EAX;

(*************************************************************************

 DESCRIPTION   :  Anubis (tweaked) EAX mode functions

 REQUIREMENTS  :  TP5-7, D1-D7/D9-D10/D12, FPC, VP

 EXTERNAL DATA :  ---

 MEMORY USAGE  :  Stack: local EAX ctx in ANU_EAX_Enc_Auth/ANU_EAX_Dec_Veri

 DISPLAY MODE  :  ---

 REFERENCES    :  [1] EAX: A Conventional Authenticated-Encryption Mode,
                      M.Bellare, P.Rogaway, D.Wagner <http://eprint.iacr.org/2003/069>
                  [2] http://csrc.nist.gov/CryptoToolkit/modes/proposedmodes/eax/eax-spec.pdf


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     05.08.08  W.Ehrhardt  Initial version analog AES_EAX
 0.11     06.08.08  we          Suppress D4+ warning
 0.12     09.08.08  we          Check tLen in ANU_EAX_Dec_Veri
 0.13     24.11.08  we          Uses BTypes
 0.14     01.08.10  we          Longint ILen in ANU_EAX_En/Decrypt
**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2008-2010 Wolfgang Ehrhardt

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
  BTypes, ANU_Base, ANU_CTR, ANU_OMAC;


type
  TANU_EAXContext = packed record
                      HdrOMAC : TANUContext; {Hdr OMAC1  context}
                      MsgOMAC : TANUContext; {Msg OMAC1  context}
                      ctr_ctx : TANUContext; {Msg ANUCTR context}
                      NonceTag: TANUBlock;   {nonce tag         }
                      tagsize : word;        {tag size (unused) }
                      flags   : word;        {ctx flags (unused)}
                    end;


{$ifdef CONST}
function ANU_EAX_Init(const Key; KBits: word; const nonce; nLen: word; var ctx: TANU_EAXContext): integer;
  {$ifdef DLL} stdcall; {$endif}
  {-Init hdr and msg OMACs, setp ANUCTR with nonce tag}

{$else}
function ANU_EAX_Init(var Key; KBits: word; var nonce; nLen: word; var ctx: TANU_EAXContext): integer;
  {-Init hdr and msg OMACs, setp ANUCTR with nonce tag}
{$endif}

function ANU_EAX_Provide_Header(Hdr: pointer; hLen: word; var ctx: TANU_EAXContext): integer;
  {$ifdef DLL} stdcall; {$endif}
  {-Supply a message header. The header "grows" with each call}

function ANU_EAX_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TANU_EAXContext): integer;
  {$ifdef DLL} stdcall; {$endif}
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update OMACs}

function ANU_EAX_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TANU_EAXContext): integer;
  {$ifdef DLL} stdcall; {$endif}
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update OMACs}

procedure ANU_EAX_Final(var tag: TANUBlock; var ctx: TANU_EAXContext);
  {$ifdef DLL} stdcall; {$endif}
  {-Compute EAX tag from context}

function ANU_EAX_Enc_Auth(var tag: TANUBlock;                     {Tag record}
        {$ifdef CONST}const{$else}var{$endif}   Key; KBits: word; {key and bitlength of key}
        {$ifdef CONST}const{$else}var{$endif} nonce; nLen: word;  {nonce: address / length}
                              Hdr: pointer; hLen: word;           {header: address / length}
                              ptp: pointer; pLen: longint;        {plaintext: address / length}
                              ctp: pointer                        {ciphertext: address}
                                ): integer;
  {$ifdef DLL} stdcall; {$endif}
  {-All-in-one call to encrypt/authenticate}

function ANU_EAX_Dec_Veri(   ptag: pointer; tLen : word;          {Tag: address / length (0..16)}
        {$ifdef CONST}const{$else}var{$endif}   Key; KBits: word; {key and bitlength of key}
        {$ifdef CONST}const{$else}var{$endif} nonce; nLen : word; {nonce: address / length}
                              Hdr: pointer; hLen: word;           {header: address / length}
                              ctp: pointer; cLen: longint;        {ciphertext: address / length}
                              ptp: pointer                        {plaintext: address}
                                ): integer;
  {$ifdef DLL} stdcall; {$endif}
  {-All-in-one call to decrypt/verify. Decryption is done only if ptag^ is verified}


implementation


{---------------------------------------------------------------------------}
{$ifdef CONST}
function ANU_EAX_Init(const Key; KBits: word; const nonce; nLen: word; var ctx: TANU_EAXContext): integer;
  {-Init hdr and msg OMACs, setp ANUCTR with nonce tag}
{$else}
function ANU_EAX_Init(var Key; KBits: word; var nonce; nLen: word; var ctx: TANU_EAXContext): integer;
  {-Init hdr and msg OMACs, setp ANUCTR with nonce tag}
{$endif}
var
  err: integer;
  t_n: TANUBlock;
begin
  fillchar(ctx, sizeof(ctx), 0);
  {Initialize OMAC context with key}
  err := ANU_OMAC_Init(Key, KBits, ctx.HdrOMAC);
  if err=0 then begin
    {copy fresh context, first use MsgOMAC for nonce OMAC}
    ctx.MsgOMAC := ctx.HdrOMAC;
    fillchar(t_n, sizeof(t_n), 0);
    err := ANU_OMAC_Update(@t_n, sizeof(t_n), ctx.MsgOMAC);
    if err=0 then err := ANU_OMAC_Update(@nonce, nLen, ctx.MsgOMAC);
    if err=0 then ANU_OMAC_Final(ctx.NonceTag, ctx.MsgOMAC);
    {inititialize Anubis-CTR context}
    if err=0 then err := ANU_CTR_Init(Key, KBits, ctx.NonceTag, ctx.ctr_ctx);
    if err=0 then begin
      {initialize msg OMAC}
      ctx.MsgOMAC := ctx.HdrOMAC;
      t_n[ANUBLKSIZE-1] := 2;
      err := ANU_OMAC_Update(@t_n, sizeof(t_n), ctx.MsgOMAC);
      {initialize header OMAC}
      t_n[ANUBLKSIZE-1] := 1;
      if err=0 then err := ANU_OMAC_Update(@t_n, sizeof(t_n), ctx.HdrOMAC);
    end;
  end;
  ANU_EAX_Init := err;
end;


{---------------------------------------------------------------------------}
function ANU_EAX_Provide_Header(Hdr: pointer; hLen: word; var ctx: TANU_EAXContext): integer;
  {-Supply a message header. The header "grows" with each call}
begin
  ANU_EAX_Provide_Header := ANU_OMAC_Update(Hdr, hLen, ctx.HdrOMAC);
end;


{---------------------------------------------------------------------------}
function ANU_EAX_Encrypt(ptp, ctp: Pointer; ILen: longint; var ctx: TANU_EAXContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update OMACs}
var
  err: integer;
begin
  {encrypt (and check for nil pointers)}
  err := ANU_CTR_Encrypt(ptp, ctp, ILen, ctx.ctr_ctx);
  if err=0 then begin
    {OMAC1 ciphertext}
    err := ANU_OMAC_Update(ctp, ILen, ctx.MsgOMAC);
  end;
  ANU_EAX_Encrypt := err;
end;


{---------------------------------------------------------------------------}
function ANU_EAX_Decrypt(ctp, ptp: Pointer; ILen: longint; var ctx: TANU_EAXContext): integer;
  {-Encrypt ILen bytes from ptp^ to ctp^ in CTR mode, update OMACs}
var
  err: integer;
begin
  {OMAC1 ciphertext}
  err := ANU_OMAC_Update(ctp, ILen, ctx.MsgOMAC);
  if err=0 then begin
    {decrypt}
    err := ANU_CTR_Decrypt(ctp, ptp, ILen, ctx.ctr_ctx);
  end;
  ANU_EAX_Decrypt := err;
end;


{---------------------------------------------------------------------------}
procedure ANU_EAX_Final(var tag: TANUBlock; var ctx: TANU_EAXContext);
  {-Compute EAX tag from context}
var
  ht: TANUBlock;
begin
  ANU_OMAC1_Final(ht, ctx.HdrOMAC);
  ANU_OMAC1_Final(tag, ctx.MsgOMAC);
  ANU_XorBlock(tag,ht,tag);
  ANU_XorBlock(tag,ctx.NonceTag,tag);
end;


{---------------------------------------------------------------------------}
function ANU_EAX_Enc_Auth(var tag: TANUBlock;                     {Tag record}
        {$ifdef CONST}const{$else}var{$endif}   Key; KBits: word; {key and bitlength of key}
        {$ifdef CONST}const{$else}var{$endif} nonce; nLen: word;  {nonce: address / length}
                              Hdr: pointer; hLen: word;           {header: address / length}
                              ptp: pointer; pLen: longint;        {plaintext: address / length}
                              ctp: pointer                        {ciphertext: address}
                                ): integer;
  {-All-in-one call to encrypt/authenticate}
var
  err : integer;
  ILen: word;
  ctx : TANU_EAXContext;
const
  CHUNK=$8000;
begin
  {$ifdef BIT16}
    if (pLen>$FFFF) or (ofs(ptp^)+pLen>$FFFF) or (ofs(ctp^)+pLen>$FFFF)  then begin
      ANU_EAX_Enc_Auth := ANU_Err_EAX_Inv_Text_Length;
      exit;
    end;
  {$endif}
  if (ptp=nil) or (ctp=nil) then begin
    if pLen>0 then begin
      ANU_EAX_Enc_Auth := ANU_Err_NIL_Pointer;
      exit;
    end;
  end;
  err := ANU_EAX_Init(Key, KBits, nonce, nLen, ctx);
  if err=0 then err := ANU_EAX_Provide_Header(Hdr, hLen, ctx);
  while (err=0) and (pLen>0) do begin
    if pLen>CHUNK then ILen := CHUNK else ILen := pLen;
    err := ANU_EAX_Encrypt(ptp, ctp, ILen, ctx);
    inc(Ptr2Inc(ptp), ILen);
    inc(Ptr2Inc(ctp), ILen);
    dec(pLen, ILen);
  end;
  if err=0 then ANU_EAX_Final(tag, ctx);
  fillchar(ctx, sizeof(ctx), 0);
  ANU_EAX_Enc_Auth := err;
end;


{---------------------------------------------------------------------------}
function Internal_Veri(var ctx: TANU_EAXContext; ptag: pointer; tLen : word;
                           ctp: pointer; cLen: longint): integer;
  {-calculate and verify tLen bytes of ptag^, performs OMAC phase of EAX}
var
  err,i: integer;
  ILen: word;
  atag: TANUBlock;
const
  CHUNK=$8000;
begin
  {internal, assumes ctx is initialized, nonce and header}
  {are processed, cLen, tLen are with in allowed ranges}
  err := 0;
  {calculate the ciphertext OMAC}
  while (err=0) and (cLen>0) do begin
    if cLen>CHUNK then ILen := CHUNK else ILen := cLen;
    err := ANU_OMAC_Update(ctp, ILen, ctx.MsgOMAC);
    inc(Ptr2Inc(ctp), ILen);
    dec(cLen, ILen);
  end;
  if (err=0) and (tLen>0) then begin
    {calculate actual tag and compare with supplied tag}
    ANU_EAX_Final(atag, ctx);
    for i:=0 to pred(tLen) do begin
      if pByte(ptag)^<>atag[i] then begin
        Internal_Veri := ANU_Err_EAX_Verify_Tag;
        exit;
      end;
      inc(Ptr2Inc(ptag));
    end;
  end;
  Internal_Veri := err;
end;



{---------------------------------------------------------------------------}
function ANU_EAX_Dec_Veri(   ptag: pointer; tLen : word;          {Tag: address / length (0..16)}
        {$ifdef CONST}const{$else}var{$endif}   Key; KBits: word; {key and bitlength of key}
        {$ifdef CONST}const{$else}var{$endif} nonce; nLen : word; {nonce: address / length}
                              Hdr: pointer; hLen: word;           {header: address / length}
                              ctp: pointer; cLen: longint;        {ciphertext: address / length}
                              ptp: pointer                        {plaintext: address}
                                ): integer;
  {-All-in-one call to decrypt/verify. Decryption is done only if ptag^ is verified}
var
  err : integer;
  ILen: word;
  ctx : TANU_EAXContext;
const
  CHUNK=$8000;
begin
  {$ifdef BIT16}
    if (cLen>$FFFF) or (ofs(ptp^)+cLen>$FFFF) or (ofs(ctp^)+cLen>$FFFF)  then begin
      ANU_EAX_Dec_Veri := ANU_Err_EAX_Inv_Text_Length;
      exit;
    end;
  {$endif}
  if (ptp=nil) or (ctp=nil) then begin
    if cLen>0 then begin
      ANU_EAX_Dec_Veri := ANU_Err_NIL_Pointer;
      exit;
    end;
  end;
  if tLen>ANUBLKSIZE then begin
    ANU_EAX_Dec_Veri := ANU_Err_EAX_Inv_TAG_Length;
    exit;
  end;
  err := ANU_EAX_Init(Key, KBits, nonce, nLen, ctx);
  if err=0 then err := ANU_EAX_Provide_Header(Hdr, hLen, ctx);
  if err=0 then begin
    {First pass through ciphertext, calculated and compare tag}
    err := Internal_Veri(ctx, ptag, tLen, ctp, cLen);
    {if error or verfication failed, decrypt loop is slipped}
    while (err=0) and (cLen>0) do begin
      if cLen>CHUNK then ILen := CHUNK else ILen := cLen;
      err := ANU_CTR_Decrypt(ctp, ptp, ILen, ctx.ctr_ctx);
      inc(Ptr2Inc(ptp), ILen);
      inc(Ptr2Inc(ctp), ILen);
      dec(cLen, ILen);
    end;
  end;
  fillchar(ctx, sizeof(ctx), 0);
  ANU_EAX_Dec_Veri:= err;
end;


end.
