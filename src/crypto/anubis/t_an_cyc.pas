{-Test prog Anubis encr/decr speed, (c) we Aug.2008}

program t_ca_cyc;

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
  ANU_Base, hrtimer;


const
  LOOPS = 100;

var
{$ifdef BIT16}
  dummy: integer;
{$endif}
  ctx: TANUContext;
  key: array[0..31] of byte;
  ct : TANUBlock;
  pt : TANUBlock;



{---------------------------------------------------------------------------}
procedure RandFill(var block; size: word);
var
  ba: array[1..$F000] of byte absolute block;
  i: word;
begin
  for i:=1 to size do ba[i] := random(256);
end;


{---------------------------------------------------------------------------}
function EncrCycles(KeyBits: word): longint;
var
  i: integer;
  cyc0, cyc1, cyc2: comp;
  t1,t2,c1,c2: longint;
begin
  RandFill(key, sizeof(key));
  RandFill(pt, sizeof(pt));
  i := ANU_Init_Encr(Key, KeyBits, ctx);
  if i<>0 then begin
    writeln('Error ANU_Init');
    halt;
  end;
  ANU_Encrypt(ctx, pt, ct);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    RandFill(pt, sizeof(pt));
    ReadTSC(cyc0);
    ANU_Encrypt(ctx, pt, ct);
    ReadTSC(cyc1);
    ANU_Encrypt(ctx, ct, ct);
    ANU_Encrypt(ctx, ct, ct);
    ANU_Encrypt(ctx, ct, ct);
    ANU_Encrypt(ctx, ct, ct);
    ANU_Encrypt(ctx, ct, ct);
    ReadTSC(cyc2);
    t2 := round(cyc2-cyc1);
    t1 := round(cyc1-cyc0);
    if t1<c1 then c1 := t1;
    if t2<c2 then c2 := t2;
  end;
  EncrCycles := (c2-c1+1) shr 2;
end;


{---------------------------------------------------------------------------}
function DecrCycles(KeyBits: word): longint;
var
  i: integer;
  cyc0, cyc1, cyc2: comp;
  t1,t2,c1,c2: longint;
begin
  RandFill(key, sizeof(key));
  RandFill(pt, sizeof(pt));
  i := ANU_Init_Decr(Key, KeyBits, ctx);
  if i<>0 then begin
    writeln('Error ANU_Init_Decr');
    halt;
  end;
  ANU_Decrypt(ctx, pt, ct);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    RandFill(pt, sizeof(pt));
    ReadTSC(cyc0);
    ANU_Decrypt(ctx, pt, ct);
    ReadTSC(cyc1);
    ANU_Decrypt(ctx, ct, ct);
    ANU_Decrypt(ctx, ct, ct);
    ANU_Decrypt(ctx, ct, ct);
    ANU_Decrypt(ctx, ct, ct);
    ANU_Decrypt(ctx, ct, ct);
    ReadTSC(cyc2);
    t2 := round(cyc2-cyc1);
    t1 := round(cyc1-cyc0);
    if t1<c1 then c1 := t1;
    if t2<c2 then c2 := t2;
  end;
  DecrCycles := (c2-c1+1) shr 2;
end;


{---------------------------------------------------------------------------}
function KeyCycles(KeyBits: word; decr: byte): longint;
var
  i,j: integer;
  cyc0, cyc1, cyc2: comp;
  t1,t2,c1,c2: longint;
begin
  RandFill(key, sizeof(key));
  RandFill(pt, sizeof(pt));
  c1 := MaxLongint;
  c2 := MaxLongint;
  j := ANU_Init2(Key, KeyBits, ctx, decr);
  if j<>0 then begin
    writeln('Error ANU_Initr');
    halt;
  end;
  for i:=1 to LOOPS do begin
    RandFill(key, sizeof(key));
    ReadTSC(cyc0);
    {$ifndef X_Opt} j := {$endif}  ANU_Init2(Key, KeyBits, ctx, decr);
    ReadTSC(cyc1);
    {$ifndef X_Opt} j := {$endif}  ANU_Init2(Key, KeyBits, ctx, decr);
    {$ifndef X_Opt} j := {$endif}  ANU_Init2(Key, KeyBits, ctx, decr);
    {$ifndef X_Opt} j := {$endif}  ANU_Init2(Key, KeyBits, ctx, decr);
    {$ifndef X_Opt} j := {$endif}  ANU_Init2(Key, KeyBits, ctx, decr);
    {$ifndef X_Opt} j := {$endif}  ANU_Init2(Key, KeyBits, ctx, decr);
    ReadTSC(cyc2);
    t2 := round(cyc2-cyc1);
    t1 := round(cyc1-cyc0);
    if t1<c1 then c1 := t1;
    if t2<c2 then c2 := t2;
  end;
  KeyCycles := (c2-c1+1) shr 2;
end;


const
  k1=4;
  k2=10;
var
  k: word;
  ec,dc,ek,dk: array[4..10] of longint;
  avg: longint;
  MB,sec: double;
begin
  writeln('Anubis Encr/Decr cycles   (c) W.Ehrhardt 2008');
{$ifdef BASM16}
  writeln('Offset mod 15: T0=',ANU_T0ofs, ',   ctx.RK=',ofs(ctx.RK) and 15);
{$endif}
  writeln('KeyBit  EncCyc  DecCyc    EK-Cyc    DK-Cyc    MB/s');
  for k:=k2 downto k1 do begin
    ec[k] := EncrCycles(k*32);
    dc[k] := DecrCycles(k*32);
    ek[k] := KeyCycles(k*32, 0);
    dk[k] := KeyCycles(k*32, 1);
  end;
  MB  := sizeof(TANUBlock)/1E6;
  for k:=k1 to k2 do begin
    avg := ec[k] + dc[k];
    sec := avg/2.0/CPUFrequency;
    writeln(k*32:6, ec[k]:8, dc[k]:8, ek[k]:10,  dk[k]:10,  MB/sec:8:2);
  end;
end.
