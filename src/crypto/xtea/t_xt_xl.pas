{-Test prog for XTEA modes, ILen > $FFFF for 32 bit, we July 2010}

program T_XT_XL;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifndef FPC}
  {$N+}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  {$ifdef USEDLL}
    {$ifdef VirtualPascal}
      XT_Intv,
    {$else}
      XT_Intf,
    {$endif}
  {$else}
    XT_Base, XT_CTR, XT_CFB, XT_OFB, XT_CBC, XT_ECB,
  {$endif}
  BTypes, mem_util;

const
  key128 : array[0..15] of byte = ($78,$56,$34,$12,$f0,$cd,$cb,$9a,
                                   $48,$37,$26,$15,$c0,$bf,$ae,$9d);

      IV : array[0..07] of byte = ($00,$01,$02,$03,$04,$05,$06,$07);

     CTR : array[0..07] of byte = ($f0,$f1,$f2,$f3,$f4,$f5,$f6,$f7);

{$ifndef BIT16}
const BSIZE=400000;
{$else}
const BSIZE=10000;
{$endif}

const
  BS1 = XTBLKSIZE*(BSIZE div (2*XTBLKSIZE));

type
  TBuf = array[0..BSIZE-1] of byte;

var
  pt, ct, dt: Tbuf;

var
  Context: TXTContext;


{---------------------------------------------------------------------------}
function test(px,py: pointer): Str255;
begin
  if compmemxl(px,py,sizeof(TBuf)) then test := 'OK' else test := 'Error';
end;


{---------------------------------------------------------------------------}
procedure TestCFB;
begin
  fillchar(dt,sizeof(dt),0);
  if XT_CFB_Init(key128, sizeof(key128), TXTBlock(IV), context)<>0 then begin
    writeln('*** Error CFB_Init');
    exit;
  end;
  if XT_CFB_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error CFB_Encrypt 1');
    exit;
  end;
  if XT_CFB_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error CFB_Encrypt 2');
    exit;
  end;
  if XT_CFB_Init(key128, sizeof(key128), TXTBlock(IV), context)<>0 then begin
    writeln('*** Error CFB_Init');
    exit;
  end;
  if XT_CFB_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error CFB_Decrypt');
    exit;
  end;
  writeln('CFB  test: ', test(@pt,@dt));
end;


{---------------------------------------------------------------------------}
procedure TestCBC;
begin
  fillchar(dt,sizeof(dt),0);
  if XT_CBC_Init(key128, sizeof(key128), TXTBlock(IV), context)<>0 then begin
    writeln('*** Error CBC_Init');
    exit;
  end;
  if XT_CBC_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error CBC_Encrypt 1');
    exit;
  end;
  if XT_CBC_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error CBC_Encrypt 2');
    exit;
  end;
  if XT_CBC_Init(key128, sizeof(key128), TXTBlock(IV), context)<>0 then begin
    writeln('*** Error CBC_Init');
    exit;
  end;
  if XT_CBC_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error CBC_Decrypt');
    exit;
  end;
  writeln('CBC  test: ', test(@pt,@dt));
end;


{---------------------------------------------------------------------------}
procedure TestECB;
begin
  fillchar(dt,sizeof(dt),0);
  if XT_ECB_Init(key128, sizeof(key128), context)<>0 then begin
    writeln('*** Error ECB_Init');
    exit;
  end;
  if XT_ECB_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error ECB_Encrypt 1');
    exit;
  end;
  if XT_ECB_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error ECB_Encrypt 2');
    exit;
  end;
  if XT_ECB_Init(key128, sizeof(key128), context)<>0 then begin
    writeln('*** Error ECB_Init');
    exit;
  end;
  if XT_ECB_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error ECB_Decrypt');
    exit;
  end;
  writeln('ECB  test: ', test(@pt,@dt));
end;


{---------------------------------------------------------------------------}
procedure TestCTR;
begin
  fillchar(dt,sizeof(dt),0);
  if XT_CTR_Init(key128, sizeof(key128), TXTBlock(CTR), context)<>0 then begin
    writeln('*** Error CTR_Init');
    exit;
  end;
  if XT_CTR_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error CTR_Encrypt 1');
    exit;
  end;
  if XT_CTR_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error CTR_Encrypt 2');
    exit;
  end;
  if XT_CTR_Init(key128, sizeof(key128), TXTBlock(CTR), context)<>0 then begin
    writeln('*** Error CTR_Init');
    exit;
  end;
  if XT_CTR_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error CTR_Decrypt');
    exit;
  end;
  writeln('CTR  test: ', test(@pt,@dt));
end;


{---------------------------------------------------------------------------}
procedure TestOFB;
begin
  fillchar(dt,sizeof(dt),0);
  if XT_OFB_Init(key128, sizeof(key128), TXTBlock(IV), context)<>0 then begin
    writeln('*** Error OFB_Init');
    exit;
  end;
  if XT_OFB_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error OFB_Encrypt 1');
    exit;
  end;
  if XT_OFB_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error OFB_Encrypt 2');
    exit;
  end;
  if XT_OFB_Init(key128, sizeof(key128), TXTBlock(IV), context)<>0 then begin
    writeln('*** Error OFB_Init');
    exit;
  end;
  if XT_OFB_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error OFB_Decrypt');
    exit;
  end;
  writeln('OFB  test: ', test(@pt,@dt));
end;


begin
  {$ifdef USEDLL}
    writeln('Test program for XT_DLL V',XT_DLL_Version,'   (C) 2010  W.Ehrhardt');
  {$else}
    writeln('Test program for XTEA  modes    (C) 2010  W.Ehrhardt');
  {$endif}
  writeln('Test of encrypt/decrypt routines using single calls with ',BS1,'/',BSize, ' bytes.');
  RandMemXL(@pt, sizeof(TBuf));
  TestCBC;
  TestCFB;
  TestCTR;
  TestECB;
  TestOFB;
  writeln;
end.
