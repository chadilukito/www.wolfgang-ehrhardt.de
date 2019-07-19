{-Test prog for XTEA basic routines, we Jan.2005}
{ Uses extract from Botan validate.dat}

program T_XTBas2;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifndef FPC}
  {$N+}
{$endif}

{$i+}

uses
  XT_Base,BTypes,mem_util;

var
  ctx: TXTContext;

var
  key: array[0..15] of byte;
  pt:  TXTBlock;
  ct:  TXTBlock;
  tmp: TXTBlock;

var
  tf: text;


{---------------------------------------------------------------------------}
procedure abort(msg: Str255);
  {-close tf, write msg, and halt program}
begin
  close(tf);
  if msg<>'' then begin
    writeln(#7, msg);
    halt(1);
  end
  else halt;
end;


{---------------------------------------------------------------------------}
procedure NextLine(var s: Str255; var done: boolean);
  {-read next non trivial line}
begin
  done := false;
  while not eof(tf) do begin
    readln(tf,s);
    if (s<>'') and (s[1]<>';') then exit;
  end;
  done := true;
end;


{---------------------------------------------------------------------------}
procedure NextVector(var done: boolean);
  {-get next key/plain/cipher vectors}
var
  buf: array[0..128] of byte;
  len: word;
  s: Str255;
begin
  {get key}
  NextLine(s,done);
  if done then exit;
  Hex2Mem(s, @buf, sizeof(buf), len);
  if len=sizeof(key) then move(buf,key,len)
  else Abort('Invalid key');
  {get plain}
  NextLine(s,done);
  if done then Abort('Missing plain');
  Hex2Mem(s, @buf, sizeof(buf), len);
  if len=sizeof(pt) then move(buf,pt,len)
  else Abort('Invalid plain');
  {get cipher}
  NextLine(s,done);
  if done then Abort('Missing cipher');
  Hex2Mem(s, @buf, sizeof(buf), len);
  if len=sizeof(ct) then move(buf,ct,len)
  else Abort('Invalid cipher');
end;


{---------------------------------------------------------------------------}
procedure NextTest(Nbr: word; var done: boolean);
  {-perform next test}
var
  ns: string[20];
begin
  str(Nbr, ns);
  ns := ' Test '+ns;
  NextVector(done);
  if done then exit;
  if XT_Init(key, sizeof(key), ctx)<>0   then Abort('XT_Init error'+ns);
  XT_Encrypt(ctx, pt, tmp);
  if not CompMem(@ct, @tmp, sizeof(ct))  then Abort('XT_Encrypt failure'+ns);
  XT_Decrypt(ctx, ct, tmp);
  if not CompMem(@pt, @tmp, sizeof(tmp)) then Abort('XT_Encrypt failure'+ns);
end;


{---------------------------------------------------------------------------}
procedure PerformTests;
  {-Read data file and perform all tests}
var
  Nbr : word;
  done: boolean;
begin
  Nbr := 0;
  repeat
    inc(Nbr);
    NextTest(Nbr, done);
  until done;
  writeln(Nbr,' tests done.');
  Abort('');
end;


begin
  filemode := 0;
  assign(tf, 'tv_xtea.dat');
  reset(tf);
  PerformTests;
end.
