unit CAM_CCM;


(*************************************************************************

 DESCRIPTION   :  Camellia Counter with CBC-MAC (CCM) mode functions

 REQUIREMENTS  :  TP5-7, D1-D7/D9-D12/D17-D18, FPC, VP, WDOSX

 EXTERNAL DATA :  ---

 MEMORY USAGE  :  ---

 DISPLAY MODE  :  ---

 REMARKS       :  - The IV and buf fields of the contexts are used for temporary buffers
                  - Tag compare is constant time but if verification fails,
                    then plaintext is zero-filled
                  - Maximum header length is $FEFF
                  - Since CCM was designed for use in a packet processing
                    environment, there are no incremental functions. The ..Ex
                    functions can be used together with CAM_Init to save
                    key setup overhead if the same key is used more than once.

 REFERENCES    :  [1] RFC 3610, 2003, D. Whiting et al., Counter with CBC-MAC (CCM)
                      http://tools.ietf.org/html/rfc1320

                  [2] RFC 5528, 2009, A. Kato et al., Camellia Counter Mode
                      and Camellia Counter with CBC-MAC Mode Algorithms
                      http://tools.ietf.org/html/rfc5528


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     21.05.09  we          Initial version derived from AES-CCM
 0.11     29.07.10  we          Fix: Check ofs(dtp^) for 16 bit
 0.12     01.09.15  we          constant time compare in CAM_CCM_Dec_VeriEX
**************************************************************************)


(*-------------------------------------------------------------------------
 (C) Copyright 2009-2015 Wolfgang Ehrhardt

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
  BTypes, CAM_Base;


function CAM_CCM_Enc_AuthEx(var ctx: TCAMContext;
                            var tag: TCAMBlock; tLen : word;       {Tag & length in [4,6,8,19,12,14,16]}
         {$ifdef CONST}const{$else}var{$endif} nonce; nLen: word;  {nonce: address / length}
                                hdr: pointer; hLen: word;          {header: address / length}
                                ptp: pointer; pLen: longint;       {plaintext: address / length}
                                ctp: pointer                       {ciphertext: address}
                                  ): integer;
  {$ifdef DLL} stdcall; {$endif}
  {-CCM packet encrypt/authenticate without key setup}


function CAM_CCM_Enc_Auth(var tag: TCAMBlock; tLen : word;        {Tag & length in [4,6,8,19,12,14,16]}
        {$ifdef CONST}const{$else}var{$endif} Key; KBytes: word;  {key and byte length of key}
        {$ifdef CONST}const{$else}var{$endif} nonce; nLen: word;  {nonce: address / length}
                              hdr: pointer; hLen: word;           {header: address / length}
                              ptp: pointer; pLen: longint;        {plaintext: address / length}
                              ctp: pointer                        {ciphertext: address}
                                ): integer;
  {$ifdef DLL} stdcall; {$endif}
  {-All-in-one call for CCM packet encrypt/authenticate}


function CAM_CCM_Dec_VeriEX(var ctx: TCAMContext;
                               ptag: pointer; tLen : word;        {Tag & length in [4,6,8,19,12,14,16]}
        {$ifdef CONST}const{$else}var{$endif} nonce; nLen: word;  {nonce: address / length}
                                hdr: pointer; hLen: word;         {header: address / length}
                                ctp: pointer; cLen: longint;      {ciphertext: address / length}
                                ptp: pointer                      {plaintext: address}
                                  ): integer;
  {$ifdef DLL} stdcall; {$endif}
  {-CCM packet decrypt/verify without key setup. If ptag^ verification fails, ptp^ is zero-filled!}


function CAM_CCM_Dec_Veri(   ptag: pointer; tLen : word;          {Tag & length in [4,6,8,19,12,14,16]}
        {$ifdef CONST}const{$else}var{$endif} Key; KBytes: word;  {key and byte length of key}
        {$ifdef CONST}const{$else}var{$endif} nonce; nLen: word;  {nonce: address / length}
                              hdr: pointer; hLen: word;           {header: address / length}
                              ctp: pointer; cLen: longint;        {ciphertext: address / length}
                              ptp: pointer                        {plaintext: address}
                                ): integer;
  {$ifdef DLL} stdcall; {$endif}
  {-All-in-one CCM packet decrypt/verify. If ptag^ verification fails, ptp^ is zero-filled!}


implementation


{---------------------------------------------------------------------------}
function CAM_CCM_Core(var ctx: TCAMContext; enc_auth: boolean;
                      var tag: TCAMBlock; tLen : word;        {Tag & length in [4,6,8,19,12,14,16]}
                       pnonce: pointer; nLen: word;           {nonce: address / length}
                          hdr: pointer; hLen: word;           {header: address / length, hLen <$FF00}
                          stp: pointer; sLen: longint;        {source text: address / length}
                          dtp: pointer                        {dest. text: address}
                            ): integer;
  {-CCM core routine. Encrypt or decrypt (depending on enc_auth) source text}
  { to dest. text and calculate the CCM tag. Key setup must be done from caller}
var
  ecc: TCAMBlock; {encrypted counter}
  err: integer;
  len: longint;
  k, L: word;
  b: byte;
  pb: pByte;

  procedure IncCTR(var CTR: TCAMBlock);
    {-Increment CTR[15]..CTR[16-L]}
  var
    j: integer;
  begin
    for j:=15 downto 16-L do begin
      if CTR[j]=$FF then CTR[j] := 0
      else begin
        inc(CTR[j]);
        exit;
      end;
    end;
  end;

begin

  {Check static ranges and conditions}
  if (sLen>0) and ((stp=nil) or (dtp=nil))   then err := CAM_Err_NIL_Pointer
  else if odd(tLen) or (tLen<4) or (tLen>16) then err := CAM_Err_CCM_Tag_length
  else if (hLen>0) and (hdr=nil)             then err := CAM_Err_NIL_Pointer
  else if hLen>=$FF00                        then err := CAM_Err_CCM_Hdr_length
  else if (nLen<7) or (nLen>13)              then err := CAM_Err_CCM_Nonce_length
  {$ifdef BIT16}
  else if (ofs(stp^)+sLen>$FFFF) or (ofs(dtp^)+sLen>$FFFF) then err := CAM_Err_CCM_Text_length
  {$endif}
  else err := 0;

  CAM_CCM_Core := err;
  if err<>0 then exit;

  {calculate L value = max(number of bytes needed for sLen, 15-nLen)}
  len := sLen;
  L := 0;
  while len>0 do begin
    inc(L);
    len := len shr 8;
  end;
  if nLen+L > 15 then begin
    CAM_CCM_Core := CAM_Err_CCM_Nonce_length;
    exit;
  end;
  {Force nLen+L=15. Since nLen<=13, L is at least L}
  L := 15-nLen;

  with ctx do begin
    {compose B_0 = Flags | Nonce N | l(m)}
    {octet 0: Flags = 64*HdrPresent | 8*((tLen-2) div 2 | (L-1)}
    if hLen>0 then b := 64 else b := 0;
    buf[0] := b or ((tLen-2) shl 2) or (L-1);
    {octets 1..15-L is nonce}
    pb := pnonce;
    for k:=1 to 15-L do begin
      buf[k] := pb^;
      inc(Ptr2Inc(pb));
    end;
    {octets 16-L .. 15: l(m)}
    len := sLen;
    for k:=1 to L do begin
      buf[16-k] := len and $FF;
      len := len shr 8;
    end;
    CAM_Encrypt(ctx, buf, buf);

    {process header}
    if hLen > 0 then begin
      {octets 0..1: encoding of hLen. Note: since we allow max $FEFF bytes}
      {only these to octets are used. Generally up to 10 octets are needed.}
      buf[0] := buf[0] xor (hLen shr 8);
      buf[1] := buf[1] xor (hLen and $FF);
      {now append the hdr data}
      blen:= 2;
      pb  := hdr;
      for k:=1 to hLen do begin
        if blen=16 then begin
          CAM_Encrypt(ctx, buf, buf);
          blen := 0;
        end;
        buf[blen] := buf[blen] xor pb^;
        inc(blen);
        inc(Ptr2Inc(pb));
      end;
      if blen<>0 then CAM_Encrypt(ctx, buf, buf);
    end;

    {setup the ctr counter for source text processing}
    pb := pnonce;
    IV[0] := (L-1) and $FF;
    for k:=1 to 15 do begin
      if k<16-L then begin
        IV[k] := pb^;
        inc(Ptr2Inc(pb));
      end
      else IV[k] := 0;
    end;

    {process full source text blocks}
    while sLen>=16 do begin
      IncCTR(IV);
      CAM_Encrypt(ctx,IV,ecc);
      if enc_auth then begin
        CAM_XorBlock(PCAMBlock(stp)^, buf, buf);
        CAM_XorBlock(PCAMBlock(stp)^, ecc, PCAMBlock(dtp)^);
      end
      else begin
        CAM_XorBlock(PCAMBlock(stp)^, ecc, PCAMBlock(dtp)^);
        CAM_XorBlock(PCAMBlock(dtp)^, buf, buf);
      end;
      CAM_Encrypt(ctx, buf, buf);
      inc(Ptr2Inc(stp), CAMBLKSIZE);
      inc(Ptr2Inc(dtp), CAMBLKSIZE);
      dec(sLen, CAMBLKSIZE);
    end;

    if sLen>0 then begin
      {handle remaining bytes of source text}
      IncCTR(IV);
      CAM_Encrypt(ctx, IV, ecc);
      for k:=0 to word(sLen-1) do begin
        if enc_auth then begin
          b := pByte(stp)^;
          pByte(dtp)^ := b xor ecc[k];
        end
        else begin
          b := pByte(stp)^ xor ecc[k];
          pByte(dtp)^ := b;
        end;
        buf[k] := buf[k] xor b;
        inc(Ptr2Inc(stp));
        inc(Ptr2Inc(dtp));
      end;
      CAM_Encrypt(ctx, buf, buf);
    end;

    {setup ctr for the tag (zero the count)}
    for k:=15 downto 16-L do IV[k] := 0;
    CAM_Encrypt(ctx, IV, ecc);
    {store the TAG}
    CAM_XorBlock(buf, ecc, tag);
  end;
end;


{---------------------------------------------------------------------------}
function CAM_CCM_Enc_AuthEx(var ctx: TCAMContext;
                            var tag: TCAMBlock; tLen : word;      {Tag & length in [4,6,8,19,12,14,16]}
        {$ifdef CONST}const{$else}var{$endif} nonce; nLen: word;  {nonce: address / length}
                                hdr: pointer; hLen: word;         {header: address / length}
                                ptp: pointer; pLen: longint;      {plaintext: address / length}
                                ctp: pointer                      {ciphertext: address}
                                  ): integer;
  {-CCM packet encrypt/authenticate without key setup}
begin
  CAM_CCM_Enc_AuthEx := CAM_CCM_Core(ctx,true,tag,tLen,@nonce,nLen,hdr,hLen,ptp,pLen,ctp);
end;


{---------------------------------------------------------------------------}
function CAM_CCM_Enc_Auth(var tag: TCAMBlock; tLen : word;        {Tag & length in [4,6,8,19,12,14,16]}
        {$ifdef CONST}const{$else}var{$endif} Key; KBytes: word;  {key and byte length of key}
        {$ifdef CONST}const{$else}var{$endif} nonce; nLen: word;  {nonce: address / length}
                              hdr: pointer; hLen: word;           {header: address / length}
                              ptp: pointer; pLen: longint;        {plaintext: address / length}
                              ctp: pointer                        {ciphertext: address}
                                ): integer;
  {-All-in-one call for CCM packet encrypt/authenticate}
var
  ctx: TCAMContext;
  err: integer;
begin
  err := CAM_Init(Key, KBytes*8, ctx);
  if err<>0 then CAM_CCM_Enc_Auth := err
  else CAM_CCM_Enc_Auth := CAM_CCM_Core(ctx,true,tag,tLen,@nonce,nLen,hdr,hLen,ptp,pLen,ctp);
  fillchar(ctx, sizeof(ctx), 0);
end;


{---------------------------------------------------------------------------}
function CAM_CCM_Dec_VeriEX(var ctx: TCAMContext;
                               ptag: pointer; tLen : word;        {Tag & length in [4,6,8,19,12,14,16]}
        {$ifdef CONST}const{$else}var{$endif} nonce; nLen: word;  {nonce: address / length}
                                hdr: pointer; hLen: word;         {header: address / length}
                                ctp: pointer; cLen: longint;      {ciphertext: address / length}
                                ptp: pointer                      {plaintext: address}
                                  ): integer;
  {-CCM packet decrypt/verify without key setup. If ptag^ verification fails, ptp^ is zero-filled!}
var
  tag: TCAMBlock;
  err,i: integer;
  diff: byte;
begin
  err := CAM_CCM_Core(ctx,false,tag,tLen,@nonce,nLen,hdr,hLen,ctp,cLen,ptp);
  if err=0 then begin
    diff := 0;
    for i:=0 to pred(tLen) do begin
      diff := diff or (pByte(ptag)^ xor tag[i]);
      inc(Ptr2Inc(ptag));
    end;
    err := (((integer(diff)-1) shr 8) and 1)-1;  {0 compare, -1 otherwise}
    err := err and CAM_Err_CCM_Verify_Tag;
  end;
  fillchar(tag, sizeof(tag),0);
  if err<>0 then fillchar(ptp^, cLen, 0);
  CAM_CCM_Dec_VeriEx := err;
end;


{---------------------------------------------------------------------------}
function CAM_CCM_Dec_Veri(   ptag: pointer; tLen : word;          {Tag & length in [4,6,8,19,12,14,16]}
        {$ifdef CONST}const{$else}var{$endif}   Key; KBytes: word;{key and byte length of key}
        {$ifdef CONST}const{$else}var{$endif} nonce; nLen: word;  {nonce: address / length}
                              hdr: pointer; hLen: word;           {header: address / length}
                              ctp: pointer; cLen: longint;        {ciphertext: address / length}
                              ptp: pointer                        {plaintext: address}
                                ): integer;
  {-All-in-one CCM packet decrypt/verify. If ptag^ verification fails, ptp^ is zero-filled!}
var
  ctx: TCAMContext;
  err: integer;
begin
  err := CAM_Init(Key, KBytes*8, ctx);
  if err<>0 then CAM_CCM_Dec_Veri := err
  else CAM_CCM_Dec_Veri := CAM_CCM_Dec_VeriEX(ctx,ptag,tLen,nonce,nLen,hdr,hLen,ctp,cLen,ptp);
  fillchar(ctx, sizeof(ctx), 0);
end;



end.
