unit poly1305;

{Poly1305 one-time authenticator}

interface


{$i STD.INC}

(*************************************************************************

 DESCRIPTION     :  Poly1305 one-time authenticator

 REQUIREMENTS    :  TP5-7, D1-D7/D9-D12/D17-D18, FPC, VP, WDOSX

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODE    :  ---

 REFERENCES      :  [1] A. Moon's MIT/public domain source code from
                        https://github.com/floodyberry/poly1305-donna
                    [2] D.J. Bernstein's NACL library nacl-20110221.tar.bz2
                        file nacl-20110221\crypto_onetimeauth\poly1305\ref\auth.c
                        available from http://nacl.cr.yp.to/index.html
                    [3] Y. Nir et al, ChaCha20 and Poly1305 for IETF Protocols
                        http://tools.ietf.org/html/rfc7539

 REMARK          :  The sender **MUST NOT** use poly1305_auth to authenticate
                    more than one message under the same key. Authenticators
                    for two messages under the same key should be expected to
                    reveal enough information to allow forgeries of
                    authenticators on other messages.


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     01.08.15  W.Ehrhardt  Initial BP version from poly1305-donna-8.h
 0.11     02.08.15  we          Some fixes, complete poly1305-donna selftest
 0.12     02.08.15  we          Adjustments for compilers without const parameters
 0.13     03.08.15  we          Comments and references
 0.14     03.08.15  we          Packed arrays, some improvements
 0.15     03.08.15  we          Generic context, 8-bit types
 0.16     03.08.15  we          First 16x16 version (poly1305_init and poly1305_blocks)
 0.17     04.08.15  we          16x16 version of poly1305_finish, published bug report
 0.18     29.03.16  we          16x16 version: fixed a bug in blocks, included bug fix from polydonna in finish
 0.19     02.04.16  we          First 32x32 version (poly1305_init and poly1305_blocks)
 0.20     03.04.16  we          32x32 version of poly1305_finish
 0.21     03.04.16  we          autoselect 16x16 or 32x32 (8x8 is always slower)
 0.22     10.04.16  we          32x32 poly1305_blocks without copy to local msg block
 0.23     10.04.16  we          move poly_8x8 code to separate include file
 0.24     10.04.16  we          interfaced poly1305_update, poly1305_finish
*************************************************************************)


(*-------------------------------------------------------------------------
 Pascal source (C) Copyright 2015-2016 Wolfgang Ehrhardt

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

const
  poly1305_block_size = 16;

type
  TPoly1305Key  = packed array[0..31] of byte;
  TPoly1305Mac  = packed array[0..15] of byte;

type
  poly1305_ctx  = record
                    buffer:   array[0..poly1305_block_size-1] of byte;
                    hrpad:    packed array[0..59] of byte;
                    leftover: word;
                    final:    byte;
                  end;

procedure poly1305_init(var ctx: poly1305_ctx; {$ifdef CONST}const{$endif} key: TPoly1305Key);
  {Initialize context with key}

procedure poly1305_update(var ctx: poly1305_ctx; msg: pointer; nbytes: longint);
  {-Update context with the data of another msg}

procedure poly1305_finish(var ctx: poly1305_ctx; var mac: TPoly1305Mac);
  {-Process leftover, compute mac, clear state}

procedure poly1305_auth(var mac: TPoly1305Mac; msg: pointer; mlen: longint; {$ifdef CONST}const{$endif}key: TPoly1305Key);
  {-All-in-one computation of the Poly1305 mac of msg using key}

function  poly1305_verify({$ifdef CONST}const{$endif} mac1, mac2: TPoly1305Mac): boolean;
  {-Return true if the two macs are identical}

function  poly1305_selftest: boolean;
  {-Simple self-test of Poly1305}


implementation


uses BTypes;


{$ifdef HAS_INT64}
  {$define poly_32x32}
{$else}
  {$define poly_16x16}
{$endif}


{---------------------------------------------------------------------------}
{---------------------------------------------------------------------------}
{$ifdef poly_16x16}
type
  TPoly_vec16  = packed array[0..9] of word;  {Internal type for r,h,pad: size is multiple of 4}
  TPoly_ctx16  = record
                  buffer:   array[0..poly1305_block_size-1] of byte;
                  h,r,pad:  TPoly_vec16;
                  leftover: word;
                  final:    byte;
                end;

type
  TPoly1305LV = array[0..16] of longint;


{---------------------------------------------------------------------------}
procedure poly1305_init(var ctx: poly1305_ctx; {$ifdef CONST}const{$endif}key: TPoly1305Key);
  {Initialize context with key}
var
  t: packed array[0..15] of word;
begin
  fillchar(ctx, sizeof(ctx), 0);
  move(key, t, sizeof(key));
  with TPoly_ctx16(ctx) do begin
    {r = key and $ffffffc0ffffffc0ffffffc0fffffff}
    r[0] := ( t[0]                         ) and $1fff;
    r[1] := ((t[0] shr 13) or (t[1] shl  3)) and $1fff;
    r[2] := ((t[1] shr 10) or (t[2] shl  6)) and $1f03;
    r[3] := ((t[2] shr  7) or (t[3] shl  9)) and $1fff;
    r[4] := ((t[3] shr  4) or (t[4] shl 12)) and $00ff;
    r[5] := ((t[4] shr  1)                 ) and $1ffe;
    r[6] := ((t[4] shr 14) or (t[5] shl  2)) and $1fff;
    r[7] := ((t[5] shr 11) or (t[6] shl  5)) and $1f81;
    r[8] := ((t[6] shr  8) or (t[7] shl  8)) and $1fff;
    r[9] := ((t[7] shr  5)                 ) and $007f;
    {save pad for later}
    move(t[8],pad,16);
  end;
end;


{---------------------------------------------------------------------------}
procedure poly1305_blocks(var ctx: poly1305_ctx; msg: pointer; nbytes: longint);
  {-Process full blocks from msg}
var
  st: TPoly_ctx16 absolute ctx;
  t: packed array[0..7] of word;
  d: array[0..9] of uint32;
  c,w: uint32;
  i,j: integer;
  hibit: word;
begin
  if ctx.final<>0 then hibit:=0 else hibit := 1 shl 11;

  while (nbytes >= poly1305_block_size) do with st do begin
    {h += m}
    move(msg^,t,16);
    inc(h[0], ( t[0]                         ) and $1fff);
    inc(h[1], ((t[0] shr 13) or (t[1] shl  3)) and $1fff);
    inc(h[2], ((t[1] shr 10) or (t[2] shl  6)) and $1fff);
    inc(h[3], ((t[2] shr  7) or (t[3] shl  9)) and $1fff);
    inc(h[4], ((t[3] shr  4) or (t[4] shl 12)) and $1fff);
    inc(h[5], ((t[4] shr  1)                 ) and $1fff);
    inc(h[6], ((t[4] shr 14) or (t[5] shl  2)) and $1fff);
    inc(h[7], ((t[5] shr 11) or (t[6] shl  5)) and $1fff);
    inc(h[8], ((t[6] shr  8) or (t[7] shl  8)) and $1fff);
    inc(h[9], ((t[7] shr  5)                 ) or hibit );

    {h *= r, (partial) h %= p}
    c := 0;
    for i:=0 to 9 do begin
      d[i] := c;
      for j:=0 to 9 do begin
        if j<=i then w := r[i-j] else w := 5*r[i + 10 - j];
        inc(d[i],w*h[j]);
        if j=4 then begin
	  c := d[i] shr 13;
	  d[i] := d[i] and $1fff;
        end;
      end;
      c := c + d[i] shr 13;
      d[i] := d[i] and $1fff;
    end;

    c := ((c shl 2) + c);  {c *= 5}
    c := c + d[0];
    d[0] := c and $1fff;
    c := c shr 13;
    inc(d[1], c);

    for i:=0 to 9 do h[i] := word(d[i]);

    inc(Ptr2Inc(msg), poly1305_block_size);
    dec(nbytes, poly1305_block_size);
  end;
end;


{---------------------------------------------------------------------------}
procedure poly1305_finish(var ctx: poly1305_ctx; var mac: TPoly1305Mac);
  {-Process leftover, compute mac, clear state}
var
  st: TPoly_ctx16 absolute ctx;
  f: uint32;
  g: array[0..9] of word;
  c, mask: word;
  i: integer;
begin
  {process the remaining block}
  if st.leftover>0 then begin
    i := st.leftover;
    st.buffer[i] := 1;
    inc(i);
    while i < poly1305_block_size do begin
      st.buffer[i] := 0;
      inc(i);
    end;
    st.final := 1;
    poly1305_blocks(ctx, @st.buffer, poly1305_block_size);
  end;

  {fully carry h}
  with st do begin
    c := h[1] shr 13;
    h[1] := h[1] and $1fff;

    for i:=2 to 9 do begin
      inc(h[i], c);
      c := h[i] shr 13;
      h[i] := h[i] and $1fff;
    end;
    inc(h[0], 5*c);
    c := h[0] shr 13;
    h[0] := h[0] and $1fff;
    inc(h[1], c);
    c := h[1] shr 13;
    h[1] := h[1] and $1fff;
    inc(h[2], c);

    {compute h +- p}
    g[0] := h[0] + 5;
    c := g[0] shr 13;
    g[0] := g[0] and $1fff;
    for i:=1 to 9 do begin
      g[i] := h[i] + c;
      c := g[i] shr 13;
      g[i] := g[i] and $1fff;
    end;
    dec(g[9], 1 shl 13);

    {select h if h < p, or h + -p if h >= p}
    {Fixed code: mask = (c ^ 1) - 1;}
    mask := (c xor 1) - 1;
    for i:=0 to 9 do g[i] := g[i] and mask;

    mask := not(mask);
    for i:=0 to 9 do h[i] := (h[i] and mask) or g[i];

    {h = h % (2^128)}
    h[0] := ((h[0]       ) or (h[1] shl 13) ) and $ffff;
    h[1] := ((h[1] shr  3) or (h[2] shl 10) ) and $ffff;
    h[2] := ((h[2] shr  6) or (h[3] shl  7) ) and $ffff;
    h[3] := ((h[3] shr  9) or (h[4] shl  4) ) and $ffff;
    h[4] := ((h[4] shr 12) or (h[5] shl  1) or (h[6] shl 14)) and $ffff;
    h[5] := ((h[6] shr  2) or (h[7] shl 11) ) and $ffff;
    h[6] := ((h[7] shr  5) or (h[8] shl  8) ) and $ffff;
    h[7] := ((h[8] shr  8) or (h[9] shl  5) ) and $ffff;

    {mac = (h + pad) % (2^128)}
    f := uint32(h[0]) + pad[0];
    h[0] := word(f);
    for i:=1 to 7 do begin
      f := ((f shr 16) + h[i]) + pad[i];
      h[i] := word(f);
    end;
  end;
  move(st.h, mac, sizeof(mac));
  {zero out the state}
  fillchar(st.h, sizeof(st.h), 0);
  fillchar(st.r, sizeof(st.r), 0);
  fillchar(st.pad, sizeof(st.pad), 0);
end;
{$endif}
{---------------------------------------------------------------------------}
{---------------------------------------------------------------------------}


{---------------------------------------------------------------------------}
{---------------------------------------------------------------------------}
{$ifdef poly_32x32}

type
  TPoly_vec32  = packed array[0..4] of uint32;  {Internal type for r,h,pad: size is multiple of 4}
  TPoly_ctx32  = record
                  buffer:   array[0..poly1305_block_size-1] of byte;
                  h,r,pad:  TPoly_vec32;
                  leftover: word;
                  final:    byte;
                end;

{$ifdef VER70}
type
  int64 = longint;   {Use for development only!!, gives wrong results!!}
{$endif}

{$ifndef HAS_UINT64}
type
  uint64 = int64;    {Used for D4, D5, D6}
{$endif}


{---------------------------------------------------------------------------}
procedure poly1305_init(var ctx: poly1305_ctx; {$ifdef CONST}const{$endif}key: TPoly1305Key);
  {-Initilalize context with key}
begin
  fillchar(ctx, sizeof(ctx), 0);
  with TPoly_ctx32(ctx) do begin
    {r &= 0xffffffc0ffffffc0ffffffc0fffffff}
    r[0] :=  puint32(@key[ 0])^ and $3ffffff;
    r[1] := (puint32(@key[ 3])^ shr 2) and $3ffff03;
    r[2] := (puint32(@key[ 6])^ shr 4) and $3ffc0ff;
    r[3] := (puint32(@key[ 9])^ shr 6) and $3f03fff;
    r[4] := (puint32(@key[12])^ shr 8) and $00fffff;
    {save pad for later}
    pad[0] := puint32(@key[16])^;
    pad[1] := puint32(@key[20])^;
    pad[2] := puint32(@key[24])^;
    pad[3] := puint32(@key[28])^;
  end;
end;


{---------------------------------------------------------------------------}
procedure poly1305_blocks(var ctx: poly1305_ctx; msg: pointer; nbytes: longint);
  {-Process full blocks from msg}
var
  hibit,c: uint32;
  r0,r1,r2,r3,r4: uint32;
  s1,s2,s3,s4: uint32;
  h0,h1,h2,h3,h4: uint32;
  d0,d1,d2,d3,d4: uint64;
  st: TPoly_ctx32 absolute ctx;
  pm: puint32;
begin
  if st.final<>0 then hibit := 0 else hibit := uint32(1) shl 24;

  r0 := st.r[0];
  r1 := st.r[1];
  r2 := st.r[2];
  r3 := st.r[3];
  r4 := st.r[4];

  s1 := r1 * 5;
  s2 := r2 * 5;
  s3 := r3 * 5;
  s4 := r4 * 5;

  h0 := st.h[0];
  h1 := st.h[1];
  h2 := st.h[2];
  h3 := st.h[3];
  h4 := st.h[4];

  pm := msg;

  while (nbytes >= poly1305_block_size) do begin
    {h += m[i]}
    inc(h0, (pm^)       and $3ffffff);     inc(Ptr2Inc(pm),3);    {->msg[ 3]}
    inc(h1, (pm^ shr 2) and $3ffffff);     inc(Ptr2Inc(pm),3);    {->msg[ 6]}
    inc(h2, (pm^ shr 4) and $3ffffff);     inc(Ptr2Inc(pm),3);    {->msg[ 9]}
    inc(h3, (pm^ shr 6) and $3ffffff);     inc(Ptr2Inc(pm),3);    {->msg[12]}
    inc(h4, (pm^ shr 8) or  hibit);        inc(Ptr2Inc(pm),4);    {->msg[16]}

    {h *= r}
    d0 := (uint64(h0)*r0) + (uint64(h1)*s4) + (uint64(h2)*s3) + (uint64(h3)*s2) + (uint64(h4)*s1);
    d1 := (uint64(h0)*r1) + (uint64(h1)*r0) + (uint64(h2)*s4) + (uint64(h3)*s3) + (uint64(h4)*s2);
    d2 := (uint64(h0)*r2) + (uint64(h1)*r1) + (uint64(h2)*r0) + (uint64(h3)*s4) + (uint64(h4)*s3);
    d3 := (uint64(h0)*r3) + (uint64(h1)*r2) + (uint64(h2)*r1) + (uint64(h3)*r0) + (uint64(h4)*s4);
    d4 := (uint64(h0)*r4) + (uint64(h1)*r3) + (uint64(h2)*r2) + (uint64(h3)*r1) + (uint64(h4)*r0);

    {(partial) h %= p}
    c  := uint32(d0 shr 26);  h0 := uint32(d0 and $3ffffff);  inc(d1,c);
    c  := uint32(d1 shr 26);  h1 := uint32(d1 and $3ffffff);  inc(d2,c);
    c  := uint32(d2 shr 26);  h2 := uint32(d2 and $3ffffff);  inc(d3,c);
    c  := uint32(d3 shr 26);  h3 := uint32(d3 and $3ffffff);  inc(d4,c);
    c  := uint32(d4 shr 26);  h4 := uint32(d4 and $3ffffff);  inc(h0, c*5);
    c  := h0 shr 26;          h0 := h0 and $3ffffff;          inc(h1, c);

    dec(nbytes, poly1305_block_size);
  end;

  st.h[0] := h0;
  st.h[1] := h1;
  st.h[2] := h2;
  st.h[3] := h3;
  st.h[4] := h4;
end;


{---------------------------------------------------------------------------}
procedure poly1305_finish(var ctx: poly1305_ctx; var mac: TPoly1305Mac);
  {-Process leftover, compute mac, clear state}
var
  g0,g1,g2,g3,g4: uint32;
  h0,h1,h2,h3,h4: uint32;
  c,mask: uint32;
  f: uint64;
  i: integer;
  st:  TPoly_ctx32 absolute ctx;
begin
  {process the remaining block}
  if st.leftover>0 then begin
    i := st.leftover;
    st.buffer[i] := 1;
    inc(i);
    while i < poly1305_block_size do begin
      st.buffer[i] := 0;
      inc(i);
    end;
    st.final := 1;
    poly1305_blocks(ctx, @st.buffer, poly1305_block_size);
  end;

  {fully carry h}
  with st do begin
    h0 := st.h[0];
    h1 := st.h[1];
    h2 := st.h[2];
    h3 := st.h[3];
    h4 := st.h[4];

                  c := h1 shr 26;  h1 := h1 and $3ffffff;
    inc(h2,c);    c := h2 shr 26;  h2 := h2 and $3ffffff;
    inc(h3,c);    c := h3 shr 26;  h3 := h3 and $3ffffff;
    inc(h4,c);    c := h4 shr 26;  h4 := h4 and $3ffffff;
    inc(h0,c*5);  c := h0 shr 26;  h0 := h0 and $3ffffff;
    inc(h1,c);

    {compute h +- p}
    g0 := h0 + 5;  c := g0 shr 26;  g0 := g0 and $3ffffff;
    g1 := h1 + c;  c := g1 shr 26;  g1 := g1 and $3ffffff;
    g2 := h2 + c;  c := g2 shr 26;  g2 := g2 and $3ffffff;
    g3 := h3 + c;  c := g3 shr 26;  g3 := g3 and $3ffffff;
    g4 := h4 + c - (uint32(1) shl 26);

    {select h if h < p, or h +- p if h >= p}
    mask := (g4 shr ((sizeof(uint32) * 8) - 1)) - 1;
    g0 := g0 and mask;
    g1 := g1 and mask;
    g2 := g2 and mask;
    g3 := g3 and mask;
    g4 := g4 and mask;

    mask := not mask;
    h0 := (h0 and mask) or g0;
    h1 := (h1 and mask) or g1;
    h2 := (h2 and mask) or g2;
    h3 := (h3 and mask) or g3;
    h4 := (h4 and mask) or g4;

    {h = h % (2^128)}
    {*WE-TODO: remove and $ffffffff}
    h0 := ((h0       ) or (h1 shl 26)) and $ffffffff;
    h1 := ((h1 shr  6) or (h2 shl 20)) and $ffffffff;
    h2 := ((h2 shr 12) or (h3 shl 14)) and $ffffffff;
    h3 := ((h3 shr 18) or (h4 shl  8)) and $ffffffff;

    {mac = (h + pad) % (2^128) }
    f := uint64(h0) + pad[0]             ;  h[0] := uint32(f);
    f := uint64(h1) + pad[1] + (f shr 32);  h[1] := uint32(f);
    f := uint64(h2) + pad[2] + (f shr 32);  h[2] := uint32(f);
    f := uint64(h3) + pad[3] + (f shr 32);  h[3] := uint32(f);
  end;

  move(st.h, mac, sizeof(mac));
  {zero out the state}
  fillchar(st.h, sizeof(st.h), 0);
  fillchar(st.r, sizeof(st.r), 0);
  fillchar(st.pad, sizeof(st.pad), 0);
end;
{$endif}
{---------------------------------------------------------------------------}
{---------------------------------------------------------------------------}


{---------------------------------------------------------------------------}
procedure poly1305_update(var ctx: poly1305_ctx; msg: pointer; nbytes: longint);
  {-Update context with the data of another msg}
var
  i,want: integer;
begin
  {handle leftover}
  with ctx do begin
    if leftover > 0 then begin
      want := (poly1305_block_size - leftover);
      if want > nbytes then want := nbytes;
      for i:=0 to want-1 do begin
        buffer[leftover + i] := pbyte(msg)^;
        inc(Ptr2Inc(msg));
      end;
      dec(nbytes, want);
      inc(Ptr2Inc(msg), want);
      inc(leftover, want);
      if leftover < poly1305_block_size then exit;
      poly1305_blocks(ctx, @buffer, poly1305_block_size);
      leftover := 0;
    end;

    {process full blocks}
    if nbytes >= poly1305_block_size then begin
      want := (nbytes and not(poly1305_block_size - 1));
      poly1305_blocks(ctx, msg, want);
      inc(Ptr2Inc(msg), want);
      dec(nbytes, want);
    end;

    {store leftover}
    if nbytes>0 then begin
      for i:=0 to nbytes-1 do begin
        buffer[leftover + i] := pbyte(msg)^;
        inc(Ptr2Inc(msg));
      end;
      inc(leftover, nbytes);
    end;
  end;
end;


{---------------------------------------------------------------------------}
procedure poly1305_auth(var mac: TPoly1305Mac; msg: pointer; mlen: longint; {$ifdef CONST}const{$endif}key: TPoly1305Key);
  {-All-in-one computation of the Poly1305 mac of msg using key}
var
  ctx: poly1305_ctx;
begin
  poly1305_init(ctx, key);
  poly1305_update(ctx, msg, mlen);
  poly1305_finish(ctx, mac);
end;


{---------------------------------------------------------------------------}
function poly1305_verify({$ifdef CONST}const{$endif}mac1, mac2: TPoly1305Mac): boolean;
  {-Return true if the two macs are identical}
var
  i: integer;
  d: byte;
begin
  d := 0;
  for i:=0 to 15 do d := d or (mac1[i] xor mac2[i]);
  poly1305_verify := d=0;
end;


{---------------------------------------------------------------------------}
function poly1305_selftest: boolean;
  {-Simple self-test of Poly1305}
const
  nacl_key: TPoly1305Key = (
              $ee,$a6,$a7,$25,$1c,$1e,$72,$91,
              $6d,$11,$c2,$cb,$21,$4d,$3c,$25,
              $25,$39,$12,$1d,$8e,$23,$4e,$65,
              $2d,$65,$1f,$a4,$c8,$cf,$f8,$80);

  nacl_msg: array[0..130] of byte = (
              $8e,$99,$3b,$9f,$48,$68,$12,$73,
              $c2,$96,$50,$ba,$32,$fc,$76,$ce,
              $48,$33,$2e,$a7,$16,$4d,$96,$a4,
              $47,$6f,$b8,$c5,$31,$a1,$18,$6a,
              $c0,$df,$c1,$7c,$98,$dc,$e8,$7b,
              $4d,$a7,$f0,$11,$ec,$48,$c9,$72,
              $71,$d2,$c2,$0f,$9b,$92,$8f,$e2,
              $27,$0d,$6f,$b8,$63,$d5,$17,$38,
              $b4,$8e,$ee,$e3,$14,$a7,$cc,$8a,
              $b9,$32,$16,$45,$48,$e5,$26,$ae,
              $90,$22,$43,$68,$51,$7a,$cf,$ea,
              $bd,$6b,$b3,$73,$2b,$c0,$e9,$da,
              $99,$83,$2b,$61,$ca,$01,$b6,$de,
              $56,$24,$4a,$9e,$88,$d5,$f9,$b3,
              $79,$73,$f6,$22,$a4,$3d,$14,$a6,
              $59,$9b,$1f,$65,$4c,$b4,$5a,$74,
              $e3,$55,$a5);

  nacl_mac: TPoly1305Mac = (
              $f3,$ff,$c7,$70,$3f,$94,$00,$e5,
              $2a,$7d,$fb,$4b,$3d,$33,$05,$d9);

  {generates a final value of (2^130 - 2) == 3}
  wrap_key: TPoly1305Key = (
              $02,$00,$00,$00,$00,$00,$00,$00,
              $00,$00,$00,$00,$00,$00,$00,$00,
              $00,$00,$00,$00,$00,$00,$00,$00,
              $00,$00,$00,$00,$00,$00,$00,$00);

  wrap_msg: array[0..15] of byte = (
              $ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff,
              $ff,$ff,$ff,$ff,$ff,$ff,$ff,$ff);

  wrap_mac: TPoly1305Mac = (
              $03,$00,$00,$00,$00,$00,$00,$00,
              $00,$00,$00,$00,$00,$00,$00,$00);

  {mac of the macs of messages of length 0 to 256, where the}
  {key and messages have all their values set to the length }
  total_key : TPoly1305Key = (
                $01,$02,$03,$04,$05,$06,$07,
                $ff,$fe,$fd,$fc,$fb,$fa,$f9,
                $ff,$ff,$ff,$ff,$ff,$ff,$ff,
                $ff,$ff,$ff,$ff,$ff,$ff,$ff,
                0,0,0,0); {WE Note: these 0 are missing in original test vector}

  total_mac: TPoly1305Mac = (
                $64,$af,$e2,$e8,$d6,$ad,$7b,$bd,
                $d2,$87,$f9,$7c,$44,$62,$3d,$39);
var
  mac: TPoly1305Mac;
  all_key: TPoly1305Key;
  all_msg: array[byte] of byte;
  ctx: poly1305_ctx;
  i: integer;
  test: boolean;
begin
  test := true;
  {Test 1}
  fillchar(mac, sizeof(mac), 0);
  poly1305_auth(mac, @nacl_msg, sizeof(nacl_msg), nacl_key);
  test := test and poly1305_verify(nacl_mac, mac);

  {Test 2}
  fillchar(mac, sizeof(mac), 0);
  poly1305_init(ctx, nacl_key);
  poly1305_update(ctx, @nacl_msg[  0], 32);
  poly1305_update(ctx, @nacl_msg[ 32], 64);
  poly1305_update(ctx, @nacl_msg[ 96], 16);
  poly1305_update(ctx, @nacl_msg[112],  8);
  poly1305_update(ctx, @nacl_msg[120],  4);
  poly1305_update(ctx, @nacl_msg[124],  2);
  poly1305_update(ctx, @nacl_msg[126],  1);
  poly1305_update(ctx, @nacl_msg[127],  1);
  poly1305_update(ctx, @nacl_msg[128],  1);
  poly1305_update(ctx, @nacl_msg[129],  1);
  poly1305_update(ctx, @nacl_msg[130],  1);
  poly1305_finish(ctx, mac);
  test := test and poly1305_verify(nacl_mac, mac);

  {Test 3}
  fillchar(mac, sizeof(mac), 0);
  poly1305_auth(mac, @wrap_msg, sizeof(wrap_msg), wrap_key);
  test := test and poly1305_verify(wrap_mac, mac);

  {Test 4}
  fillchar(mac, sizeof(mac), 0);
  poly1305_init(ctx, total_key);
  for i:=0 to 255 do begin
    {set key and message to 'i,i,i..'}
    fillchar(all_key, sizeof(all_key), i);
    fillchar(all_msg, i, i);
    poly1305_auth(mac, @all_msg, i, all_key);
    poly1305_update(ctx, @mac, 16);
  end;
  poly1305_finish(ctx, mac);
  test := test and poly1305_verify(total_mac, mac);

  poly1305_selftest := test;
end;

end.
