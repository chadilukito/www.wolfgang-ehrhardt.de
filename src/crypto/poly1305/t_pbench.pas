{-Test prog for poly1305 unit, we Apr. 2016}

program t_pbench;

{$i std.inc}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
    wincrt,
  {$endif}
  poly1305;

const
  BSIZE = $4000;
  LOOP  = 5120;       {Total 80 MB}
var
  key: TPoly1305Key;
  mac: TPoly1305Mac;
  msg: array[0..BSIZE-1] of byte;
  i: longint;
begin
  writeln('Poly1305 selftest: ',poly1305_selftest);
  fillchar(key, sizeof(key), $12);
  fillchar(msg, sizeof(msg), $AB);
  for i:=1 to LOOP do begin
    poly1305_auth(mac, @msg, sizeof(msg), key);
  end;
end.
