{-Test program reproducing Nessie Anubis test vectors, (c) we Aug.2008}

{ anubis-test-vectors-xxx.txt, xxx = 128, 160, 192, 224, 256, 288, 320 from}
{ http://www.larc.usp.br/~pbarreto/anubis-tweak-test-vectors.zip}
{ Note that the 'Test vectors -- set 4' is only generated if all_sets is
{ defined. To generate a text vector file for a given key size, assign
{ the key bit size to the const KeyBits and redirect stdout to a file}

program t_an_bs1;

{$i STD.INC}


{.$define all_sets}  {set 4 is VERY time consuming}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  BTypes,mem_util,anu_base;

const
  KeyBits = 320;

var
  key: array[0..79] of byte;
  ctx: TANUContext;

  plain     : TANUBlock;
  cipher    : TANUBlock;
  decrypted : TANUBlock;


{Pascal translation of Anubis submission bctestvectors.c}

{---------------------------------------------------------------------------}
procedure print_data(str: str255; pval: pointer; len: word);
begin
  writeln(str:25,'=',HexStr(pval, len));
end;


{---------------------------------------------------------------------------}
procedure DumpTV(ks: word);
  {-dump Nessie TV for key bit size ks}
var
  v,err: integer;
  i: longint;
begin
  writeln('Test vectors -- set 1');
  writeln('=====================');
  writeln;
  for v:=0 to ks-1 do begin
    fillchar(plain, sizeof(plain), 0);
    fillchar(key, sizeof(key), 0);
    key[v shr 3] := 1 shl (7-(v and 7));
    err := ANU_Init_Encr(key, ks, ctx);
    if err<>0 then begin
      writeln('** ANU_Init_Encr error: ', err);
      halt;
    end;
    ANU_Encrypt(ctx, plain, cipher);
    err := ANU_Init_Decr(key, ks, ctx);
    if err<>0 then begin
      writeln('** ANU_Init_Decr error: ', err);
      halt;
    end;
    ANU_Decrypt(ctx, cipher, decrypted);
    writeln('Set 1, vector#',v:3,':');
    print_data('key', @key, ks div 8);
    print_data('plain', @plain, ANUBLKSIZE);
    print_data('cipher', @cipher, ANUBLKSIZE);
    print_data('decrypted', @decrypted, ANUBLKSIZE);
    if not compmem(@plain, @decrypted, ANUBLKSIZE) then begin
      writeln('** Decryption error: **');
      writeln('   Decrypted ciphertext is different than the plaintext!');
    end;
    err := ANU_Init_Encr(key, ks, ctx);
    if err<>0 then begin
      writeln('** ANU_Init_Encr error: ', err);
      halt;
    end;
    for i:=2 to 100 do ANU_Encrypt(ctx, cipher, cipher);
    print_data('Iterated 100 times', @cipher, ANUBLKSIZE);
    for i:=101 to 1000 do ANU_Encrypt(ctx, cipher, cipher);
    print_data('Iterated 1000 times', @cipher, ANUBLKSIZE);
    writeln;
  end;

  writeln('Test vectors -- set 2');
  writeln('=====================');
  writeln;
  for v:=0 to pred(8*ANUBLKSIZE) do begin
    fillchar(plain, sizeof(plain), 0);
    fillchar(key, sizeof(key), 0);
    plain[v shr 3] := 1 shl (7-(v and 7));
    err := ANU_Init_Encr(key, ks, ctx);
    if err<>0 then begin
      writeln('** ANU_Init_Encr error: ', err);
      halt;
    end;
    ANU_Decrypt(ctx, plain, cipher);
    err := ANU_Init_Decr(key, ks, ctx);
    if err<>0 then begin
      writeln('** ANU_Init_Decr error: ', err);
      halt;
    end;
    ANU_Encrypt(ctx, cipher, decrypted);
    writeln('Set 2, vector#',v:3,':');
    print_data('key', @key, ks div 8);
    print_data('plain', @plain, ANUBLKSIZE);
    print_data('cipher', @cipher, ANUBLKSIZE);
    print_data('decrypted', @decrypted, ANUBLKSIZE);
    if not compmem(@plain, @decrypted, ANUBLKSIZE) then begin
      writeln('** Decryption error: **');
      writeln('   Decrypted ciphertext is different than the plaintext!');
    end;
    err := ANU_Init_Encr(key, ks, ctx);
    if err<>0 then begin
      writeln('** ANU_Init_Encr error: ', err);
      halt;
    end;
    for i:=2 to 100 do ANU_Encrypt(ctx, cipher, cipher);
    print_data('Iterated 100 times', @cipher, ANUBLKSIZE);
    for i:=101 to 1000 do ANU_Encrypt(ctx, cipher, cipher);
    print_data('Iterated 1000 times', @cipher, ANUBLKSIZE);
    writeln;
  end;

  writeln('Test vectors -- set 3');
  writeln('=====================');
  writeln;
  for v:=0 to 255 do begin
    fillchar(plain, sizeof(plain), v);
    fillchar(key, sizeof(key), v);
    err := ANU_Init_Encr(key, ks, ctx);
    if err<>0 then begin
      writeln('** ANU_Init_Encr error: ', err);
      halt;
    end;
    ANU_Encrypt(ctx, plain, cipher);
    err := ANU_Init_Decr(key, ks, ctx);
    if err<>0 then begin
      writeln('** ANU_Init_Decr error: ', err);
      halt;
    end;
    ANU_Decrypt(ctx, cipher, decrypted);
    writeln('Set 3, vector#',v:3,':');
    print_data('key', @key, ks div 8);
    print_data('plain', @plain, ANUBLKSIZE);
    print_data('cipher', @cipher, ANUBLKSIZE);
    print_data('decrypted', @decrypted, ANUBLKSIZE);
    if not compmem(@plain, @decrypted, ANUBLKSIZE) then begin
      writeln('** Decryption error: **');
      writeln('   Decrypted ciphertext is different than the plaintext!');
    end;
    err := ANU_Init_Encr(key, ks, ctx);
    if err<>0 then begin
      writeln('** ANU_Init_Encr error: ', err);
      halt;
    end;
    for i:=2 to 100 do ANU_Encrypt(ctx, cipher, cipher);
    print_data('Iterated 100 times', @cipher, ANUBLKSIZE);
    for i:=101 to 1000 do ANU_Encrypt(ctx, cipher, cipher);
    print_data('Iterated 1000 times', @cipher, ANUBLKSIZE);
    writeln;
  end;

{$ifdef all_sets}

  {WARNING!!!! This is VERY time consuming!!}
  {=========================================}

  writeln('Test vectors -- set 4');
  writeln('=====================');
  writeln;
  for v:=0 to 3 do begin
    fillchar(plain, sizeof(plain), v);
    fillchar(key, sizeof(key), v);
    if ANU_Init_Encr(key, ks, ctx)<>0 then halt;
    err := ANU_Init_Encr(key, ks, ctx);
    if err<>0 then begin
      writeln('** ANU_Init_Encr error: ', err);
      halt;
    end;
    writeln('Set 4, vector#',v:3,':');
    print_data('key', @key, ks div 8);
    print_data('plain', @plain, ANUBLKSIZE);
    for i:=1 to 99999999 do begin
      fillchar(key, sizeof(key), cipher[ANUBLKSIZE-1]);
      err := ANU_Init_Encr(key, ks, ctx);
      if err<>0 then begin
        writeln('** ANU_Init_Encr error: ', err);
        halt;
      end;
      ANU_Encrypt(ctx, cipher, cipher);
    end;
    print_data('Iterated 10^8 times', @cipher, ANUBLKSIZE);
    writeln;
  end;
  writeln;
{$endif}

  writeln;
  writeln('End of test vectors');
end;

begin
  HexUpper := true;
  DumpTV(320);
end.

