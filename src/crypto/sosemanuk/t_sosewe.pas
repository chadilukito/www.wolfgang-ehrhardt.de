{Test program for speed comparisons, (c) WE Apr.2009}

program t_sosewe;

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
  HRTimer,mem_util,sosemanu;

const
  NCnt=1000000;

procedure usage;
begin
  writeln('usage: t_salwe [k128 | k256 | e128 | e256]');
  writeln(' kx: key stream with Sosemanuk');
  writeln(' ex: encrypt with Sosemanuk');
end;

procedure main;
const
  iv: array[0..15] of byte = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
type
  tbuf = array[1..800] of byte;
var
  ctx: sose_ctx;
  i,sum: longint;
  HR: THRTimer;
  ks,es: integer;
  key: array[1..32] of byte;
  {$ifdef D12Plus}
    arg: string;
  {$else}
    arg: string[20];
  {$endif}
  pbuf: ^tbuf;
  sec,mbs: double;
begin
  arg := paramstr(1);
  es  := 0;
  ks  := 256;
  if arg='k128' then ks:=128
  else if arg='k256' then ks:=256
  else if arg='e128' then begin ks:=128; es:=1; end
  else if arg='e256' then begin ks:=256; es:=1; end
  else begin
    usage;
    halt;
  end;
  fillchar(key,sizeof(key),0);
  if sose_keysetup(ctx, @key, ks)<>0 then begin
    writeln('Error sose_keysetup');
    halt;
  end;
  new(pbuf);
  fillchar(pbuf^, sizeof(tbuf),0);
  sose_ivsetup(ctx, @IV);
  StartTimer(HR);
  if es=1 then begin
    for i:=1 to NCnt do sose_encrypt_bytes(ctx, pbuf, pbuf, sizeof(tbuf));
  end
  else begin
    for i:=1 to NCnt do sose_keystream_bytes(ctx, pbuf, sizeof(tbuf));
  end;
  sec := ReadSeconds(HR);
  mbs := 800.0E-6*NCnt/sec;
  sum := 0;
  for i:=1 to 800 do sum := sum + pbuf^[i];
  writeln('Results for ',arg, ': time in s = ',sec:6:3,
          ',   MB/s = ',mbs:5:1, ',   CS = 0x',HexLong(sum));
  {for i:=1 to 800 do begin
    write(HexByte(pbuf^[i]):3);
    if i mod 20 = 0 then writeln;
  end;}
  dispose(pbuf);
end;

begin
  main;
end.

