{Test program for speed comparisons, (c) we May 2006}

program t_salwe;

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
  NCnt=1000000;

procedure usage;
begin
  writeln('usage: t_salwe [k8 | k12 | k20 | e8 | e12 | e20]');
  writeln(' kx: key stream with salsa20/x');
  writeln(' ex: encrypt with salsa20/x');
end;


procedure main;
const
  iv: array[1..8] of byte = (0,0,0,0,0,0,0,0);
type
  tbuf = array[1..576] of byte;
var
  ctx: salsa_ctx;
  i: longint;
  HR: THRTimer;
  sr: word;
  ks: integer;
  key: array[1..32] of byte;
  {$ifdef D12Plus}
    arg: string;
  {$else}
    arg: string[20];
  {$endif}
  pbuf: ^tbuf;
begin
  arg := paramstr(1);
  ks  := 1;
  sr  := 20;
  if arg='k8' then sr:=8
  else if arg='k12' then sr:=12
  else if arg='k20' then sr:=20
  else if arg='e8'  then begin sr:=8;  ks:=0; end
  else if arg='e12' then begin sr:=12; ks:=0; end
  else if arg='e20' then begin sr:=20; ks:=0; end
  else begin
   usage;
   halt;
  end;
  new(pbuf);
  salsa_xkeysetup(ctx, @key, 128, sr);
  salsa_ivsetup(ctx, @IV);
  StartTimer(HR);
  if ks=0 then begin
    for i:=1 to NCnt do salsa_encrypt_bytes(ctx, pbuf, pbuf, sizeof(tbuf));
  end
  else begin
    for i:=1 to NCnt do salsa_keystream_bytes(ctx, pbuf, sizeof(tbuf));
  end;
  writeln('Time in s for ',arg,' = ', ReadSeconds(HR):1:3);
  dispose(pbuf);
end;

begin
  main;
end.

