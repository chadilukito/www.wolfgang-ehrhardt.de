{Cycle-Counter test program for Sosemanuk stream cipher,  (c) WE Apr.2009}

program T_SM_CYC;

{$i std.inc}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifndef FPC}
  {$N+}
{$endif}

{$ifdef X_Opt}
  {$x+}
{$endif}

uses
  {$ifdef WINCRT}
    WinCRT,
  {$endif}
  HRTimer,sosemanu;

const
  LOOPS  = 100;
  BLOCKS = 10;
  BYTES  = BLOCKS*sose_blocklength;     {=800 Bytes}


var
  key, iv: array[0..15] of byte;
  stream,ct: array[0..BYTES-1] of byte;
  ctx: sose_ctx;


{---------------------------------------------------------------------------}
function KeySetupCycles: longint;
var
  i: integer;
  {$ifndef X_Opt} j: integer; {$endif}
  cyc0, cyc1, cyc2: comp;
  t1,t2,c1,c2: longint;
begin
  fillchar(key, sizeof(key), 0);
  if sose_keysetup(ctx, @key, 128) <>0 then begin
    writeln('sose_keysetup error');
    halt;
  end;
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    ReadTSC(cyc0);
    {$ifndef X_Opt} j := {$endif} sose_keysetup(ctx, @key, 128);
    ReadTSC(cyc1);
    {$ifndef X_Opt} j := {$endif} sose_keysetup(ctx, @key, 128);
    {$ifndef X_Opt} j := {$endif} sose_keysetup(ctx, @key, 128);
    {$ifndef X_Opt} j := {$endif} sose_keysetup(ctx, @key, 128);
    {$ifndef X_Opt} j := {$endif} sose_keysetup(ctx, @key, 128);
    {$ifndef X_Opt} j := {$endif} sose_keysetup(ctx, @key, 128);
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
  if sose_keysetup(ctx, @key, 128) <>0 then begin
    writeln('sose_keysetup error');
    halt;
  end;
  sose_ivsetup(ctx, @iv);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    ReadTSC(cyc0);
    sose_ivsetup(ctx, @iv);
    ReadTSC(cyc1);
    sose_ivsetup(ctx, @iv);
    sose_ivsetup(ctx, @iv);
    sose_ivsetup(ctx, @iv);
    sose_ivsetup(ctx, @iv);
    sose_ivsetup(ctx, @iv);
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
  if sose_keysetup(ctx, @key, 128) <>0 then begin
    writeln('sose_keysetup error');
    halt;
  end;
  sose_ivsetup(ctx, @iv);
  for i:=1 to 5 do sose_keystream_blocks(ctx, @stream, BLOCKS);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    ReadTSC(cyc0);
    sose_keystream_blocks(ctx, @stream, BLOCKS);
    ReadTSC(cyc1);
    sose_keystream_blocks(ctx, @stream, BLOCKS);
    sose_keystream_blocks(ctx, @stream, BLOCKS);
    sose_keystream_blocks(ctx, @stream, BLOCKS);
    sose_keystream_blocks(ctx, @stream, BLOCKS);
    sose_keystream_blocks(ctx, @stream, BLOCKS);
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
  if sose_keysetup(ctx, @key, 128) <>0 then begin
    writeln('sose_keysetup error');
    halt;
  end;
  sose_ivsetup(ctx, @iv);
  for i:=1 to 5 do sose_encrypt_blocks(ctx, @stream, @ct, BLOCKS);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    ReadTSC(cyc0);
    sose_encrypt_blocks(ctx, @stream, @ct, BLOCKS);
    ReadTSC(cyc1);
    sose_encrypt_blocks(ctx, @stream, @ct, BLOCKS);
    sose_encrypt_blocks(ctx, @stream, @ct, BLOCKS);
    sose_encrypt_blocks(ctx, @stream, @ct, BLOCKS);
    sose_encrypt_blocks(ctx, @stream, @ct, BLOCKS);
    sose_encrypt_blocks(ctx, @stream, @ct, BLOCKS);
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
  writeln('T_SM_CYC - Speed test program for Sosemanuk stream cipher  (c) 2009 W.Ehrhardt');
  writeln('Selftest passed: ', sose_selftest);
  writeln;
  writeln('GENERAL');
  writeln('CPU Frequency: ':FW, FMHz:1:1);
  writeln('    Key setup: ':FW, Ckey);
  writeln('     IV setup: ':FW, CIV);
  writeln(' KEYSTREAM');
  writeln(' Cycles/Block: ':FW, SBlk/BLOCKS:1:1);
  writeln(' Cycles/Byte : ':FW, SBlk/BYTES:1:1);
  writeln('         MB/s: ':FW, BYTES*FMHz/SBlk:1:3);
  writeln(' ENCRYPT');
  writeln(' Cycles/Block: ':FW, EBlk/BLOCKS:1:1);
  writeln(' Cycles/Byte : ':FW, EBlk/BYTES:1:1);
  writeln('         MB/s: ':FW, BYTES*FMHz/EBlk:1:3);
end.
