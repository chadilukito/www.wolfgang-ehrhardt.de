{-Test prog Camellia encr/decr speed, we Sep.2008}

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
  {$ifdef WIN32or64}
    {$ifdef UNIT_SCOPE}
      winapi.windows,
    {$else}
      windows,
    {$endif}
  {$endif}
  CAM_Base, hrtimer;


const
  LOOPS = 100;

var
  ctx: TCAMContext;
  key: array[0..31] of byte;
  ct : TCAMBlock;
  pt : TCAMBlock;



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
  i := CAM_Init(Key, KeyBits, ctx);
  if i<>0 then begin
    writeln('Error CAM_Init');
    halt;
  end;
  CAM_Encrypt(ctx, pt, ct);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    RandFill(pt, sizeof(pt));
    ReadTSC(cyc0);
    CAM_Encrypt(ctx, pt, ct);
    ReadTSC(cyc1);
    CAM_Encrypt(ctx, ct, ct);
    CAM_Encrypt(ctx, ct, ct);
    CAM_Encrypt(ctx, ct, ct);
    CAM_Encrypt(ctx, ct, ct);
    CAM_Encrypt(ctx, ct, ct);
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
  i := CAM_Init(Key, KeyBits, ctx);
  if i<>0 then begin
    writeln('Error CAM_Init');
    halt;
  end;
  CAM_Decrypt(ctx, pt, ct);
  c1 := MaxLongint;
  c2 := MaxLongint;
  for i:=1 to LOOPS do begin
    RandFill(pt, sizeof(pt));
    ReadTSC(cyc0);
    CAM_Decrypt(ctx, pt, ct);
    ReadTSC(cyc1);
    CAM_Decrypt(ctx, ct, ct);
    CAM_Decrypt(ctx, ct, ct);
    CAM_Decrypt(ctx, ct, ct);
    CAM_Decrypt(ctx, ct, ct);
    CAM_Decrypt(ctx, ct, ct);
    ReadTSC(cyc2);
    t2 := round(cyc2-cyc1);
    t1 := round(cyc1-cyc0);
    if t1<c1 then c1 := t1;
    if t2<c2 then c2 := t2;
  end;
  DecrCycles := (c2-c1+1) shr 2;
end;


{---------------------------------------------------------------------------}
function KeyCycles(KeyBits: word): longint;
var
  i,j: integer;
  cyc0, cyc1, cyc2: comp;
  t1,t2,c1,c2: longint;
begin
  RandFill(key, sizeof(key));
  RandFill(pt, sizeof(pt));
  c1 := MaxLongint;
  c2 := MaxLongint;
  j := CAM_Init(Key, KeyBits, ctx);
  if j<>0 then begin
    writeln('Error CAM_Init');
    halt;
  end;
  for i:=1 to LOOPS do begin
    RandFill(key, sizeof(key));
    ReadTSC(cyc0);
    {$ifndef X_Opt} j := {$endif}  CAM_Init(Key, KeyBits, ctx);
    ReadTSC(cyc1);
    {$ifndef X_Opt} j := {$endif}  CAM_Init(Key, KeyBits, ctx);
    {$ifndef X_Opt} j := {$endif}  CAM_Init(Key, KeyBits, ctx);
    {$ifndef X_Opt} j := {$endif}  CAM_Init(Key, KeyBits, ctx);
    {$ifndef X_Opt} j := {$endif}  CAM_Init(Key, KeyBits, ctx);
    {$ifndef X_Opt} j := {$endif}  CAM_Init(Key, KeyBits, ctx);
    ReadTSC(cyc2);
    t2 := round(cyc2-cyc1);
    t1 := round(cyc1-cyc0);
    if t1<c1 then c1 := t1;
    if t2<c2 then c2 := t2;
  end;
  KeyCycles := (c2-c1+1) shr 2;
end;


var
  k: word;
  ec,dc,kc : array[2..4] of longint;
  avg: longint;
  MB,sec: double;
begin
  writeln('Camellia Encr/Decr cycles   (c) W.Ehrhardt 2008');
  writeln('KeyBit  EncCyc  DecCyc   InitCyc  Avg MB/s');
  {$ifdef WIN32or64}
    if Paramcount=0 then SetPriorityClass(GetCurrentProcess,HIGH_PRIORITY_CLASS);
  {$endif}
  for k:=4 downto 2 do begin
    ec[k] := EncrCycles(k*64);
    dc[k] := DecrCycles(k*64);
    kc[k] := KeyCycles(k*64);
  end;
  MB  := sizeof(TCAMBlock)/1E6;
  for k:=4 downto 2 do begin
    avg := ec[k] + dc[k];
    sec := avg/2.0/CPUFrequency;
    writeln(k*64:6, ec[k]:8, dc[k]:8, kc[k]:10, MB/sec:10:2)
  end;
end.
