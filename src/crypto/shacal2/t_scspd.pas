{-Test prog SHACAL-2 encr/decr speed, we Jan.2005}

program t_SCspd;

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
  SC_Base, hrtimer;


const
  LOOPS = 100;

var
  ctx: TSCContext;
  key: array[0..63] of byte;
  ct : TSCBlock;
  pt : TSCBlock;



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
  i := SC_Init(Key, sizeof(key), ctx);
  if i<>0 then begin
    writeln('Error SC_Init');
    halt;
  end;
  SC_Encrypt(ctx, pt, ct);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    RandFill(pt, sizeof(pt));
    ReadTSC(cyc0);
    SC_Encrypt(ctx, pt, ct);
    ReadTSC(cyc1);
    SC_Encrypt(ctx, ct, ct);
    SC_Encrypt(ctx, ct, ct);
    SC_Encrypt(ctx, ct, ct);
    SC_Encrypt(ctx, ct, ct);
    SC_Encrypt(ctx, ct, ct);
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
  i := SC_Init(Key, sizeof(key), ctx);
  if i<>0 then begin
    writeln('Error SC_Init_Decr');
    halt;
  end;
  SC_Decrypt(ctx, pt, ct);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    RandFill(pt, sizeof(pt));
    ReadTSC(cyc0);
    SC_Decrypt(ctx, pt, ct);
    ReadTSC(cyc1);
    SC_Decrypt(ctx, ct, ct);
    SC_Decrypt(ctx, ct, ct);
    SC_Decrypt(ctx, ct, ct);
    SC_Decrypt(ctx, ct, ct);
    SC_Decrypt(ctx, ct, ct);
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
  keybytes : word;
begin
  keybytes := sizeof(key);
  RandFill(key, sizeof(key));
  RandFill(pt, sizeof(pt));
  c1 := MaxLongint;
  c2 := MaxLongint;
  j := SC_Init(Key, KeyBytes, ctx);
  if j<>0 then begin
    writeln('Error SC_Initr');
    halt;
  end;
  for i:=1 to LOOPS do begin
    RandFill(key, sizeof(key));
    ReadTSC(cyc0);
    {$ifndef X_Opt} j := {$endif}  SC_Init(Key, KeyBytes, ctx);
    ReadTSC(cyc1);
    {$ifndef X_Opt} j := {$endif}  SC_Init(Key, KeyBytes, ctx);
    {$ifndef X_Opt} j := {$endif}  SC_Init(Key, KeyBytes, ctx);
    {$ifndef X_Opt} j := {$endif}  SC_Init(Key, KeyBytes, ctx);
    {$ifndef X_Opt} j := {$endif}  SC_Init(Key, KeyBytes, ctx);
    {$ifndef X_Opt} j := {$endif}  SC_Init(Key, KeyBytes, ctx);
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
  writeln('SHACAL-2 Encr/Decr cycles   (c) W.Ehrhardt 2005');
  writeln('  EncCyc  DecCyc   InitCyc');
  ec := EncrCycles;
  dc := DecrCycles;
  kc := KeyCycles;
  avg := ec + dc;
  writeln(ec:8, dc:8, kc:10);
  MB  := sizeof(TSCBlock)/1E6;
  sec := avg/2.0/CPUFrequency;
  writeln('Avg cyc/block: ', avg/2.0:5:0);
  writeln('Avg cyc/byte : ', avg/2.0/sizeof(TSCBlock):5:0);
  writeln('Avg MB/s     : ', MB/sec:5:2);
end.
