{Cycle-Counter test program for ChaCha stream cipher,  (c) we Sep.2013}

program T_CHACYC;

{$i std.inc}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifndef FPC}
  {$N+}
{$endif}

uses
  {$ifdef WINCRT}
    WinCRT,
  {$endif}
  HRTimer,salsa20;

const
  LOOPS  = 100;
  BLOCKS = 9;
  BYTES  = BLOCKS*salsa_Blocklength;     {=576 Bytes}


var
  key, iv: array[0..15] of byte;
  stream,ct: array[0..BYTES-1] of byte;
  ctx: salsa_ctx;
  rounds: word;


{---------------------------------------------------------------------------}
function KeySetupCycles: longint;
var
  i: integer;
  cyc0, cyc1, cyc2: comp;
  t1,t2,c1,c2: longint;
begin
  fillchar(key, sizeof(key), 0);
  chacha_xkeysetup(ctx, @key, 128, rounds);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    ReadTSC(cyc0);
    salsa_xkeysetup(ctx, @key, 128, rounds);
    ReadTSC(cyc1);
    chacha_xkeysetup(ctx, @key, 128, rounds);
    chacha_xkeysetup(ctx, @key, 128, rounds);
    chacha_xkeysetup(ctx, @key, 128, rounds);
    chacha_xkeysetup(ctx, @key, 128, rounds);
    chacha_xkeysetup(ctx, @key, 128, rounds);
    ReadTSC(cyc2);
    t2 := round(cyc2-cyc1);
    t1 := round(cyc1-cyc0);
    if t1<c1 then c1 := t1;
    if t2<c2 then c2 := t2;
  end;
  KeySetupCycles := (c2-c1+1) shr 2;
end;


{---------------------------------------------------------------------------}
function IVSetupCycles: longint;
var
  i: integer;
  cyc0, cyc1, cyc2: comp;
  t1,t2,c1,c2: longint;
begin
  fillchar(key, sizeof(key), 0);
  fillchar(IV, sizeof(IV), 0);
  chacha_xkeysetup(ctx, @key, 128, rounds);
  chacha_ivsetup(ctx, @iv);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    ReadTSC(cyc0);
    salsa_IVsetup(ctx, @IV);
    ReadTSC(cyc1);
    chacha_IVsetup(ctx, @IV);
    chacha_IVsetup(ctx, @IV);
    chacha_IVsetup(ctx, @IV);
    chacha_IVsetup(ctx, @IV);
    chacha_IVsetup(ctx, @IV);
    ReadTSC(cyc2);
    t2 := round(cyc2-cyc1);
    t1 := round(cyc1-cyc0);
    if t1<c1 then c1 := t1;
    if t2<c2 then c2 := t2;
  end;
  IVSetupCycles := (c2-c1+1) shr 2;
end;


{---------------------------------------------------------------------------}
function StreamBlockCycles: longint;
var
  i: integer;
  cyc0, cyc1, cyc2: comp;
  t1,t2,c1,c2: longint;
begin
  fillchar(iv,sizeof(iv),0);
  fillchar(key, sizeof(key), 0);
  chacha_xkeysetup(ctx, @key, 128, rounds);
  chacha_ivsetup(ctx, @iv);
  for i:=1 to 5 do chacha_keystream_blocks(ctx, @stream, BLOCKS);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    ReadTSC(cyc0);
    chacha_keystream_blocks(ctx, @stream, BLOCKS);
    ReadTSC(cyc1);
    chacha_keystream_blocks(ctx, @stream, BLOCKS);
    chacha_keystream_blocks(ctx, @stream, BLOCKS);
    chacha_keystream_blocks(ctx, @stream, BLOCKS);
    chacha_keystream_blocks(ctx, @stream, BLOCKS);
    chacha_keystream_blocks(ctx, @stream, BLOCKS);
    ReadTSC(cyc2);
    t2 := round(cyc2-cyc1);
    t1 := round(cyc1-cyc0);
    if t1<c1 then c1 := t1;
    if t2<c2 then c2 := t2;
  end;
  StreamBlockCycles := (c2-c1+1) shr 2;
end;

{---------------------------------------------------------------------------}
function EncBlockCycles: longint;
var
  i: integer;
  cyc0, cyc1, cyc2: comp;
  t1,t2,c1,c2: longint;
begin
  fillchar(iv,sizeof(iv),0);
  fillchar(key, sizeof(key), 0);
  chacha_xkeysetup(ctx, @key, 128, rounds);
  chacha_ivsetup(ctx, @iv);
  for i:=1 to 5 do salsa_encrypt_blocks(ctx, @stream, @ct, BLOCKS);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    ReadTSC(cyc0);
    chacha_encrypt_blocks(ctx, @stream, @ct, BLOCKS);
    ReadTSC(cyc1);
    chacha_encrypt_blocks(ctx, @stream, @ct, BLOCKS);
    chacha_encrypt_blocks(ctx, @stream, @ct, BLOCKS);
    chacha_encrypt_blocks(ctx, @stream, @ct, BLOCKS);
    chacha_encrypt_blocks(ctx, @stream, @ct, BLOCKS);
    chacha_encrypt_blocks(ctx, @stream, @ct, BLOCKS);
    ReadTSC(cyc2);
    t2 := round(cyc2-cyc1);
    t1 := round(cyc1-cyc0);
    if t1<c1 then c1 := t1;
    if t2<c2 then c2 := t2;
  end;
  EncBlockCycles := (c2-c1+1) shr 2;
end;


var
  CKey, CIV, SBlk, EBlk: longint;
  FMhz: double;

const
  FW=17;
begin
  if paramstr(1)='8' then rounds := 8
  else if paramstr(1)='20' then rounds := 20
  else rounds := 12; {default for 128 bit key}

  CKey := KeySetupCycles;
  CIV  := IVSetupCycles;
  SBlK := StreamBlockCycles;
  EBlK := EncBlockCycles;
  {$ifdef FPC}
    {Avoid "Hint: use DIV instead to get an integer result"}
    {$hints off}
  {$endif}
  FMHz := CPUFrequency/1E6;
  writeln;
  writeln('T_CHACYC - Speed test program for Chacha stream cipher   (c) 2013 W.Ehrhardt');
  writeln('Selftest passed: ', chacha_selftest);
{$ifdef BIT32}
  writeln('  ChaChaBasm32 : ', ChaChaBasm32);
{$endif}
  writeln;
  writeln('GENERAL');
  writeln('CPU Frequency: ':FW, FMHz:1:1);
  writeln('Nbr of rounds: ':FW, rounds);
  writeln(' X Key setup : ':FW, Ckey);
  writeln('    IV setup : ':FW, CIV);
  writeln('KEYSTREAM');
  writeln('Cycles/Block : ':FW, SBlk/BLOCKS:1:1);
  writeln('Cycles/Byte  : ':FW, SBlk/BYTES:1:1);
  writeln('        MB/s : ':FW, BYTES*FMHz/SBlk:1:3);
  writeln('ENCRYPT');
  writeln('Cycles/Block : ':FW, EBlk/BLOCKS:1:1);
  writeln('Cycles/Byte  : ':FW, EBlk/BYTES:1:1);
  writeln('        MB/s : ':FW, BYTES*FMHz/EBlk:1:3);
end.
