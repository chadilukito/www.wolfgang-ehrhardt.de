{-Test prog SkipJack encr/decr speed, we May 2009}

program t_xtspd;

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
  SJ_Base, hrtimer;


const
  LOOPS = 100;

var
  ctx: TSJContext;
  key: array[0..9] of byte;
  ct : TSJBlock;
  pt : TSJBlock;


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
  i := SJ_Init(key, sizeof(key), ctx);
  if i<>0 then begin
    writeln('Error SJ_Init_Encr');
    halt;
  end;
  SJ_Encrypt(ctx, pt, ct);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    RandFill(pt, sizeof(pt));
    ReadTSC(cyc0);
    SJ_Encrypt(ctx, pt, ct);
    ReadTSC(cyc1);
    SJ_Encrypt(ctx, ct, ct);
    SJ_Encrypt(ctx, ct, ct);
    SJ_Encrypt(ctx, ct, ct);
    SJ_Encrypt(ctx, ct, ct);
    SJ_Encrypt(ctx, ct, ct);
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
  i := SJ_Init(key, sizeof(key), ctx);
  if i<>0 then begin
    writeln('Error SJ_Init_Decr');
    halt;
  end;
  SJ_Decrypt(ctx, pt, ct);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    RandFill(pt, sizeof(pt));
    ReadTSC(cyc0);
    SJ_Decrypt(ctx, pt, ct);
    ReadTSC(cyc1);
    SJ_Decrypt(ctx, ct, ct);
    SJ_Decrypt(ctx, ct, ct);
    SJ_Decrypt(ctx, ct, ct);
    SJ_Decrypt(ctx, ct, ct);
    SJ_Decrypt(ctx, ct, ct);
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
  j := SJ_Init(key, sizeof(key), ctx);
  if j<>0 then begin
    writeln('Error SJ_Init_Key');
    halt;
  end;
  for i:=1 to LOOPS do begin
    RandFill(key, sizeof(key));
    ReadTSC(cyc0);
    {$ifndef X_Opt} j := {$endif}  SJ_Init(Key, 16, ctx);
    ReadTSC(cyc1);
    {$ifndef X_Opt} j := {$endif}  SJ_Init(Key, 16, ctx);
    {$ifndef X_Opt} j := {$endif}  SJ_Init(Key, 16, ctx);
    {$ifndef X_Opt} j := {$endif}  SJ_Init(Key, 16, ctx);
    {$ifndef X_Opt} j := {$endif}  SJ_Init(Key, 16, ctx);
    {$ifndef X_Opt} j := {$endif}  SJ_Init(Key, 16, ctx);
    ReadTSC(cyc2);
    t2 := round(cyc2-cyc1);
    t1 := round(cyc1-cyc0);
    if t1<c1 then c1 := t1;
    if t2<c2 then c2 := t2;
  end;
  KeyCycles := (c2-c1+1) shr 2;
end;


var
  ec,dc,kc: longint;
  avg: longint;
  MB,sec: double;
begin
  writeln('SkipJack Encr/Decr cycles   (c) W.Ehrhardt 2009');
  writeln('CPU frequency: ', CPUFrequency/1000000:1:0, ' MHz');
  writeln('  EncCyc  DecCyc  InitCyc');
  ec := EncrCycles;
  dc := DecrCycles;
  kc := KeyCycles;
  avg := ec + dc;
  writeln(ec:8, dc:8, kc:9);
  MB  := sizeof(TSJBlock)/1E6;
  sec := avg/2/CPUFrequency;
  writeln('Avg Cyc: ', avg/2:5:0, '   MB/s: ',MB/sec:1:1);
end.
