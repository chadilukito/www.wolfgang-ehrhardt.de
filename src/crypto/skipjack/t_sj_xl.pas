{-Test prog for SkipJack modes, ILen > $FFFF for 32 bit, we July 2010}

program T_SJ_XL;

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
      SJ_Intv,
    {$else}
      SJ_Intf,
    {$endif}
  {$else}
    SJ_Base, SJ_CTR, SJ_CFB, SJ_OFB, SJ_CBC, SJ_ECB,
  {$endif}
  BTypes, mem_util;

const
     key : array[0..09] of byte = ($11,$22,$33,$44,$55,$66,$77,$88,$99,$00);

      IV : array[0..07] of byte = ($00,$01,$02,$03,$04,$05,$06,$07);

     CTR : array[0..07] of byte = ($f0,$f1,$f2,$f3,$f4,$f5,$f6,$f7);

{$ifndef BIT16}
const BSIZE=400000;
{$else}
const BSIZE=10000;
{$endif}

const
  BS1 = SJBLKSIZE*(BSIZE div (2*SJBLKSIZE));

type
  TBuf = array[0..BSIZE-1] of byte;

var
  pt, ct, dt: Tbuf;

var
  Context: TSJContext;


{---------------------------------------------------------------------------}
function test(px,py: pointer): Str255;
begin
  if compmemxl(px,py,sizeof(TBuf)) then test := 'OK' else test := 'Error';
end;


{---------------------------------------------------------------------------}
procedure TestCFB;
begin
  fillchar(dt,sizeof(dt),0);
  if SJ_CFB_Init(key, sizeof(key), TSJBlock(IV), context)<>0 then begin
    writeln('*** Error CFB_Init');
    exit;
  end;
  if SJ_CFB_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error CFB_Encrypt 1');
    exit;
  end;
  if SJ_CFB_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error CFB_Encrypt 2');
    exit;
  end;
  if SJ_CFB_Init(key, sizeof(key), TSJBlock(IV), context)<>0 then begin
    writeln('*** Error CFB_Init');
    exit;
  end;
  if SJ_CFB_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error CFB_Decrypt');
    exit;
  end;
  writeln('CFB  test: ', test(@pt,@dt));
end;


{---------------------------------------------------------------------------}
procedure TestCBC;
begin
  fillchar(dt,sizeof(dt),0);
  if SJ_CBC_Init(key, sizeof(key), TSJBlock(IV), context)<>0 then begin
    writeln('*** Error CBC_Init');
    exit;
  end;
  if SJ_CBC_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error CBC_Encrypt 1');
    exit;
  end;
  if SJ_CBC_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error CBC_Encrypt 2');
    exit;
  end;
  if SJ_CBC_Init(key, sizeof(key), TSJBlock(IV), context)<>0 then begin
    writeln('*** Error CBC_Init');
    exit;
  end;
  if SJ_CBC_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error CBC_Decrypt');
    exit;
  end;
  writeln('CBC  test: ', test(@pt,@dt));
end;


{---------------------------------------------------------------------------}
procedure TestECB;
begin
  fillchar(dt,sizeof(dt),0);
  if SJ_ECB_Init(key, sizeof(key), context)<>0 then begin
    writeln('*** Error ECB_Init');
    exit;
  end;
  if SJ_ECB_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error ECB_Encrypt 1');
    exit;
  end;
  if SJ_ECB_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error ECB_Encrypt 2');
    exit;
  end;
  if SJ_ECB_Init(key, sizeof(key), context)<>0 then begin
    writeln('*** Error ECB_Init');
    exit;
  end;
  if SJ_ECB_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error ECB_Decrypt');
    exit;
  end;
  writeln('ECB  test: ', test(@pt,@dt));
end;


{---------------------------------------------------------------------------}
procedure TestCTR;
begin
  fillchar(dt,sizeof(dt),0);
  if SJ_CTR_Init(key, sizeof(key), TSJBlock(CTR), context)<>0 then begin
    writeln('*** Error CTR_Init');
    exit;
  end;
  if SJ_CTR_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error CTR_Encrypt 1');
    exit;
  end;
  if SJ_CTR_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error CTR_Encrypt 2');
    exit;
  end;
  if SJ_CTR_Init(key, sizeof(key), TSJBlock(CTR), context)<>0 then begin
    writeln('*** Error CTR_Init');
    exit;
  end;
  if SJ_CTR_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error CTR_Decrypt');
    exit;
  end;
  writeln('CTR  test: ', test(@pt,@dt));
end;


{---------------------------------------------------------------------------}
procedure TestOFB;
begin
  fillchar(dt,sizeof(dt),0);
  if SJ_OFB_Init(key, sizeof(key), TSJBlock(IV), context)<>0 then begin
    writeln('*** Error OFB_Init');
    exit;
  end;
  if SJ_OFB_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error OFB_Encrypt 1');
    exit;
  end;
  if SJ_OFB_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error OFB_Encrypt 2');
    exit;
  end;
  if SJ_OFB_Init(key, sizeof(key), TSJBlock(IV), context)<>0 then begin
    writeln('*** Error OFB_Init');
    exit;
  end;
  if SJ_OFB_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error OFB_Decrypt');
    exit;
  end;
  writeln('OFB  test: ', test(@pt,@dt));
end;



begin
  {$ifdef USEDLL}
    writeln('Test program for SJ_DLL V',SJ_DLL_Version,'   (C) 2010  W.Ehrhardt');
  {$else}
    writeln('Test program for SkipJack  modes    (C) 2010  W.Ehrhardt');
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
