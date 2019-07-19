{-Test prog XTEA encr/decr speed, we Jan.2005}

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
  XT_Base, hrtimer;


const
  LOOPS = 100;

var
  ctx: TXTContext;
  key: array[0..15] of byte;
  ct : TXTBlock;
  pt : TXTBlock;



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
  i := XT_Init(Key, 16, ctx);
  if i<>0 then begin
    writeln('Error XT_Init');
    halt;
  end;
  XT_Encrypt(ctx, pt, ct);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    RandFill(pt, sizeof(pt));
    ReadTSC(cyc0);
    XT_Encrypt(ctx, pt, ct);
    ReadTSC(cyc1);
    XT_Encrypt(ctx, ct, ct);
    XT_Encrypt(ctx, ct, ct);
    XT_Encrypt(ctx, ct, ct);
    XT_Encrypt(ctx, ct, ct);
    XT_Encrypt(ctx, ct, ct);
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
  i := XT_Init(Key, 16, ctx);
  if i<>0 then begin
    writeln('Error XT_Init_Decr');
    halt;
  end;
  XT_Decrypt(ctx, pt, ct);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    RandFill(pt, sizeof(pt));
    ReadTSC(cyc0);
    XT_Decrypt(ctx, pt, ct);
    ReadTSC(cyc1);
    XT_Decrypt(ctx, ct, ct);
    XT_Decrypt(ctx, ct, ct);
    XT_Decrypt(ctx, ct, ct);
    XT_Decrypt(ctx, ct, ct);
    XT_Decrypt(ctx, ct, ct);
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
  j := XT_Init(Key, 16, ctx);
  if j<>0 then begin
    writeln('Error XT_Initr');
    halt;
  end;
  for i:=1 to LOOPS do begin
    RandFill(key, sizeof(key));
    ReadTSC(cyc0);
    {$ifndef X_Opt} j := {$endif}  XT_Init(Key, 16, ctx);
    ReadTSC(cyc1);
    {$ifndef X_Opt} j := {$endif}  XT_Init(Key, 16, ctx);
    {$ifndef X_Opt} j := {$endif}  XT_Init(Key, 16, ctx);
    {$ifndef X_Opt} j := {$endif}  XT_Init(Key, 16, ctx);
    {$ifndef X_Opt} j := {$endif}  XT_Init(Key, 16, ctx);
    {$ifndef X_Opt} j := {$endif}  XT_Init(Key, 16, ctx);
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
  writeln('XTEA Encr/Decr cycles   (c) W.Ehrhardt 2005');
  writeln('EncCyc  DecCyc   InitCyc');
  ec := EncrCycles;
  dc := DecrCycles;
  kc := KeyCycles;
  avg := ec + dc;
  writeln(ec:8, dc:8, kc:10);
  MB  := sizeof(TXTBlock)/1E6;
  sec := avg/2/CPUFrequency;
  writeln('Avg Cyc: ', avg/2:5:0, '   MB/s: ',MB/sec:7:2);
end.
