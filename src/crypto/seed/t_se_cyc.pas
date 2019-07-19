{-Test prog SEED encr/decr speed, we 06.2007}

program t_se_cyc;

{$i STD.INC}

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
     wincrt,
  {$endif}
  SEA_Base, hrtimer;


const
  LOOPS   = 100;
  KeyBits = 128;
var
  ctx: TSEAContext;
  key: TSEABlock;
  ct : TSEABlock;
  pt : TSEABlock;



{---------------------------------------------------------------------------}
procedure RandFill(var block; size: word);
var
  ba: array[1..$F000] of byte absolute block;
  i: word;
begin
  for i:=1 to size do ba[i] := random(256);
end;


{---------------------------------------------------------------------------}
function EncrCycles: longint;
var
  i: integer;
  cyc0, cyc1, cyc2: comp;
  t1,t2,c1,c2: longint;
begin
  RandFill(key, sizeof(key));
  RandFill(pt, sizeof(pt));
  i := SEA_Init(Key, KeyBits, ctx);
  if i<>0 then begin
    writeln('Error SEA_Init Encr');
    halt;
  end;
  SEA_Encrypt(ctx, pt, ct);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    RandFill(pt, sizeof(pt));
    ReadTSC(cyc0);
    SEA_Encrypt(ctx, pt, ct);
    ReadTSC(cyc1);
    SEA_Encrypt(ctx, ct, ct);
    SEA_Encrypt(ctx, ct, ct);
    SEA_Encrypt(ctx, ct, ct);
    SEA_Encrypt(ctx, ct, ct);
    SEA_Encrypt(ctx, ct, ct);
    ReadTSC(cyc2);
    t2 := round(cyc2-cyc1);
    t1 := round(cyc1-cyc0);
    if t1<c1 then c1 := t1;
    if t2<c2 then c2 := t2;
  end;
  EncrCycles := (c2-c1+1) shr 2;
end;


{---------------------------------------------------------------------------}
function DecrCycles: longint;
var
  i: integer;
  cyc0, cyc1, cyc2: comp;
  t1,t2,c1,c2: longint;
begin
  RandFill(key, sizeof(key));
  RandFill(pt, sizeof(pt));
  i := SEA_Init(Key, KeyBits, ctx);
  if i<>0 then begin
    writeln('Error SEA_Init Decr');
    halt;
  end;
  SEA_Decrypt(ctx, pt, ct);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    RandFill(pt, sizeof(pt));
    ReadTSC(cyc0);
    SEA_Decrypt(ctx, pt, ct);
    ReadTSC(cyc1);
    SEA_Decrypt(ctx, ct, ct);
    SEA_Decrypt(ctx, ct, ct);
    SEA_Decrypt(ctx, ct, ct);
    SEA_Decrypt(ctx, ct, ct);
    SEA_Decrypt(ctx, ct, ct);
    ReadTSC(cyc2);
    t2 := round(cyc2-cyc1);
    t1 := round(cyc1-cyc0);
    if t1<c1 then c1 := t1;
    if t2<c2 then c2 := t2;
  end;
  DecrCycles := (c2-c1+1) shr 2;
end;


{---------------------------------------------------------------------------}
function KeyCycles: longint;
var
  i,j: integer;
  cyc0, cyc1, cyc2: comp;
  t1,t2,c1,c2: longint;
begin
  RandFill(key, sizeof(key));
  RandFill(pt, sizeof(pt));
  c1 := MaxLongint;
  c2 := MaxLongint;
  j := SEA_Init(Key, KeyBits, ctx);
  if j<>0 then begin
    writeln('Error SEA_Init Cylces');
    halt;
  end;
  for i:=1 to LOOPS do begin
    RandFill(key, sizeof(key));
    ReadTSC(cyc0);
    {$ifndef X_Opt} j := {$endif}  SEA_Init(Key, KeyBits, ctx);
    ReadTSC(cyc1);
    {$ifndef X_Opt} j := {$endif}  SEA_Init(Key, KeyBits, ctx);
    {$ifndef X_Opt} j := {$endif}  SEA_Init(Key, KeyBits, ctx);
    {$ifndef X_Opt} j := {$endif}  SEA_Init(Key, KeyBits, ctx);
    {$ifndef X_Opt} j := {$endif}  SEA_Init(Key, KeyBits, ctx);
    {$ifndef X_Opt} j := {$endif}  SEA_Init(Key, KeyBits, ctx);
    ReadTSC(cyc2);
    t2 := round(cyc2-cyc1);
    t1 := round(cyc1-cyc0);
    if t1<c1 then c1 := t1;
    if t2<c2 then c2 := t2;
  end;
  KeyCycles := (c2-c1+1) shr 2;
end;


var
  ec,dc,kc : longint;
  avg,MB,sec: double;
begin
  writeln('SEED Encr/Decr cycles   (c) W.Ehrhardt 2007');
  writeln('  EncCyc  DecCyc   InitCyc');
  ec := EncrCycles;
  dc := DecrCycles;
  kc := KeyCycles;
  avg := 0.5*(ec + dc);
  writeln(ec:8, dc:8, kc:10);
  MB  := sizeof(TSEABlock)/1E6;
  sec := avg/CPUFrequency;
  writeln('Avg Cyc: ', avg:5:0, '   MB/s: ',MB/sec:7:2);
end.
