{---------------------------------------------------------------------------}
{---------------------------------------------------------------------------}
{ poly1305 implementation using 8 x 8 -> 16 bit multiplication and 32 bit addition}


{$ifdef poly_8x8}
type
  TPoly_vec8  = packed array[0..19] of byte;  {Internal type for r,h,pad: size is multiple of 4}
  TPoly_ctx8  = record
                  buffer:   array[0..poly1305_block_size-1] of byte;
                  h,r,pad:  TPoly_vec8;
                  leftover: word;
                  final:    byte;
                end;

type
  TPoly1305LV = array[0..16] of longint;


{---------------------------------------------------------------------------}
procedure poly1305_init(var ctx: poly1305_ctx; {$ifdef CONST}const{$endif}key: TPoly1305Key);
  {-Initilalize context with key}
begin
  fillchar(ctx, sizeof(ctx), 0);
  with TPoly_ctx8(ctx) do begin
    {r = key and $ffffffc0ffffffc0ffffffc0fffffff}
    r[ 0] := key[ 0];
    r[ 1] := key[ 1];
    r[ 2] := key[ 2];
    r[ 3] := key[ 3] and $0f;
    r[ 4] := key[ 4] and $fc;
    r[ 5] := key[ 5];
    r[ 6] := key[ 6];
    r[ 7] := key[ 7] and $0f;
    r[ 8] := key[ 8] and $fc;
    r[ 9] := key[ 9];
    r[10] := key[10];
    r[11] := key[11] and $0f;
    r[12] := key[12] and $fc;
    r[13] := key[13];
    r[14] := key[14];
    r[15] := key[15] and $0f;
    {save pad for later}
    move(key[16], pad, 16);
  end;
end;


{---------------------------------------------------------------------------}
procedure poly1305_add(var h: TPoly_vec8; {$ifdef CONST}const{$else}var{$endif}c: TPoly_vec8);
  {-Add first 17 bytes of c to h}
var
  i: integer;
  u: word;
begin
  u := 0;
  for i:=0 to 16 do begin
    u := (u + h[i]) + c[i];
    h[i] := byte(u);
    u := u shr 8;
  end;
end;


{---------------------------------------------------------------------------}
procedure poly1305_squeeze(var h: TPoly_vec8; {$ifdef CONST}const{$else}var{$endif}hr: TPoly1305LV);
  {-Partial reduce h mod p}
var
  u: longint;
  i: integer;
begin
  u := 0;
  for i:=0 to 15 do begin
    u := u + hr[i];
    h[i] := byte(u);
    u := u shr 8;
  end;
  u := u + hr[16];
  h[16] := u and 3;
  u := u shr 2;
  u := u + (u shl 2);
  for i:=0 to 15 do begin
    u := u + h[i];
    h[i] := byte(u);
    u := u shr 8;
  end;
  h[16] := h[16] + byte(u);
end;


{---------------------------------------------------------------------------}
procedure poly1305_freeze(var h: TPoly_vec8);
  {-Full reduce h mod p}
const
  minusp: TPoly_vec8 = (5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,$FC,0,0,0);
  nmask : array[0..1] of byte = (0, $FF);
var
  horig: TPoly_vec8;
  i: integer;
  negative: byte;
begin
  horig := h;
  {compute h + -p}
  poly1305_add(h, minusp);
  {select h if h < p, or h + -p if h >= p }
  negative := nmask[h[16] shr 7];
  for i:=0 to 16 do h[i] := h[i] xor (negative and (horig[i] xor h[i]));
end;


{---------------------------------------------------------------------------}
procedure poly1305_blocks(var ctx: poly1305_ctx; msg: pointer; nbytes: longint);
  {-Process full blocks from msg}
var
  st:  TPoly_ctx8 absolute ctx;
  u,v: longint;
  hr:  TPoly1305LV;
  c:   TPoly_vec8;
  i,j: integer;
  hibit: byte;
begin
  hibit := st.final xor 1;
  while (nbytes >= poly1305_block_size)  do begin
    {h += m}
    move(msg^,c,16);
    c[16] := hibit;
    poly1305_add(st.h, c);
    {h *= r}
    for i:=0 to 16 do begin
      u := 0;
      for j:=0 to i do inc(u, word(st.h[j])*st.r[i-j]);
      for j:=i+1 to 16 do begin
        v := longint(st.h[j])*st.r[i + 17 - j];
        inc(u, (v shl 8) + (v shl 6));
      end;
      hr[i] := u;
    end;

    {(partial) h mod p}
    poly1305_squeeze(st.h, hr);

    inc(Ptr2Inc(msg), poly1305_block_size);
    dec(nbytes, poly1305_block_size);
  end;
end;


{---------------------------------------------------------------------------}
procedure poly1305_finish(var ctx: poly1305_ctx; var mac: TPoly1305Mac);
  {-Process leftover, compute mac, clear state}
var
  st:  TPoly_ctx8 absolute ctx;
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
  {fully reduce h}
  poly1305_freeze(st.h);
  {h = (h + pad) % (1 << 128)}
  poly1305_add(st.h, st.pad);
  move(st.h, mac, sizeof(mac));
  {zero out the state}
  fillchar(st.h, sizeof(st.h), 0);
  fillchar(st.r, sizeof(st.r), 0);
  fillchar(st.pad, sizeof(st.pad), 0);
end;
{$endif}
{---------------------------------------------------------------------------}
{---------------------------------------------------------------------------}
