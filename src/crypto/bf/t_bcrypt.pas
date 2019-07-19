{-Test prog for bcrypt routines, we 10.2013}
program t_bcrypt;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  BTypes,mem_util,bcrypt;

{$ifdef BIT16}
  {$ifdef BASM16}
    const level=2;
  {$else}
    const level=1;
  {$endif}
{$else}
  const level=3;
{$endif}

var
  HStr: BString;
  HDig: TBCDigest;
  err : integer;
  salt: TBCSalt;
const
  PWD0 = 'Wrdblbrnft+42';
  PWD1 = 'Wrdblbrmft-42';
  cost = 8;
begin

  writeln('Test program for bcrypt password hashing   (C) 2013  W.Ehrhardt');

  write('BFC_Selftest (cost <= ',2*level + 6,'): ');
  err := BFC_Selftest(true, level);
  if err=0 then writeln(' passed.')
  else writeln(' test ', err, ' failed!');
  writeln;

  Randseed := 42;
  RandMemXL(@salt[0], sizeof(salt));

  writeln('Test BFC_MakeDigest/BFC_FormatHash');
  err := BFC_MakeDigest(PWD0, salt, cost, HDig);
  if err<>0 then writeln('Error from BFC_MakeDigest: ', err)
  else begin
    writeln('Digest for <',PWD0, '>: 0x', HexStr(@HDig, sizeof(HDig)));
    HStr := BFC_FormatHash(cost, salt, HDig);
    writeln('bcrypt hash = ', HStr);
  end;
  writeln;

  writeln('Test BFC_HashPassword');
  err := BFC_HashPassword(PWD0, salt, cost, HStr);
  if err<>0 then writeln('Error from BFC_HashPassword: ', err)
  else begin
    writeln('bcrypt hash: ', HStr);
  end;
  writeln;

  write('Verify with <', PWD0,'>: ');
  err := BFC_VerifyPassword(PWD0, HStr);
  if err=0 then writeln('passed')
  else writeln('failed, err=',err);
  writeln;

  {Wrong password: err=0 is failure}
  write('Verify with <', PWD1,'>: ');
  err := BFC_VerifyPassword(PWD1, HStr);
  if err=0 then writeln('failed, err=0 with wrong password')
  else if err=BF_Err_Verify_failed then writeln('passed, return value = BF_Err_Verify_failed')
  else writeln('failed, err=',err);
  writeln;
  writeln;

end.

