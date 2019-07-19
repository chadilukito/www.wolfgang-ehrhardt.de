{-Test prog for Shacal-2 modes, ILen > $FFFF for 32 bit, we Aug. 2010}

program T_SC_XL;

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
      SC_Intv,
    {$else}
      SC_Intf,
    {$endif}
  {$else}
    SC_Base, SC_CTR, SC_CFB, SC_OFB, SC_CBC, SC_ECB,
  {$endif}
  BTypes, mem_util;

const
  key   : array[0.. 63] of byte = ($32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32,
                                   $32,$32,$32,$32,$32,$32,$32,$32);
  IV    : array[0.. 31] of byte = ($42,$42,$42,$42,$42,$42,$42,$42,
                                   $42,$42,$42,$42,$42,$42,$42,$42,
                                   $42,$42,$42,$42,$42,$42,$42,$42,
                                   $42,$42,$42,$42,$42,$42,$42,$42);


{$ifndef BIT16}
const BSIZE=400000;
{$else}
const BSIZE=10000;
{$endif}

const
  BS1 = SCBLKSIZE*(BSIZE div (2*SCBLKSIZE));

type
  TBuf = array[0..BSIZE-1] of byte;

var
  pt, ct, dt: Tbuf;

var
  Context: TSCContext;


{---------------------------------------------------------------------------}
function test(px,py: pointer): Str255;
begin
  if compmemxl(px,py,sizeof(TBuf)) then test := 'OK' else test := 'Error';
end;


{---------------------------------------------------------------------------}
procedure TestCFB;
begin
  fillchar(dt,sizeof(dt),0);
  if SC_CFB_Init(key, sizeof(key), TSCBlock(IV), context)<>0 then begin
    writeln('*** Error CFB_Init');
    exit;
  end;
  if SC_CFB_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error CFB_Encrypt 1');
    exit;
  end;
  if SC_CFB_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error CFB_Encrypt 2');
    exit;
  end;
  if SC_CFB_Init(key, sizeof(key), TSCBlock(IV), context)<>0 then begin
    writeln('*** Error CFB_Init');
    exit;
  end;
  if SC_CFB_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error CFB_Decrypt');
    exit;
  end;
  writeln('CFB  test: ', test(@pt,@dt));
end;



{---------------------------------------------------------------------------}
procedure TestCBC;
begin
  fillchar(dt,sizeof(dt),0);
  if SC_CBC_Init(key, sizeof(key), TSCBlock(IV), context)<>0 then begin
    writeln('*** Error CBC_Init');
    exit;
  end;
  if SC_CBC_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error CBC_Encrypt 1');
    exit;
  end;
  if SC_CBC_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error CBC_Encrypt 2');
    exit;
  end;
  if SC_CBC_Init(key, sizeof(key), TSCBlock(IV), context)<>0 then begin
    writeln('*** Error CBC_Init');
    exit;
  end;
  if SC_CBC_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error CBC_Decrypt');
    exit;
  end;
  writeln('CBC  test: ', test(@pt,@dt));
end;


{---------------------------------------------------------------------------}
procedure TestECB;
begin
  fillchar(dt,sizeof(dt),0);
  if SC_ECB_Init(key, sizeof(key), context)<>0 then begin
    writeln('*** Error ECB_Init');
    exit;
  end;
  if SC_ECB_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error ECB_Encrypt 1');
    exit;
  end;
  if SC_ECB_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error ECB_Encrypt 2');
    exit;
  end;
  if SC_ECB_Init(key, sizeof(key), context)<>0 then begin
    writeln('*** Error ECB_Init');
    exit;
  end;
  if SC_ECB_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error ECB_Decrypt');
    exit;
  end;
  writeln('ECB  test: ', test(@pt,@dt));
end;


{---------------------------------------------------------------------------}
procedure TestCTR;
begin
  fillchar(dt,sizeof(dt),0);
  if SC_CTR_Init(key, sizeof(key), TSCBlock(IV), context)<>0 then begin
    writeln('*** Error CTR_Init');
    exit;
  end;
  if SC_CTR_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error CTR_Encrypt 1');
    exit;
  end;
  if SC_CTR_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error CTR_Encrypt 2');
    exit;
  end;
  if SC_CTR_Init(key, sizeof(key), TSCBlock(IV), context)<>0 then begin
    writeln('*** Error CTR_Init');
    exit;
  end;
  if SC_CTR_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error CTR_Decrypt');
    exit;
  end;
  writeln('CTR  test: ', test(@pt,@dt));
end;


{---------------------------------------------------------------------------}
procedure TestOFB;
begin
  fillchar(dt,sizeof(dt),0);
  if SC_OFB_Init(key, sizeof(key), TSCBlock(IV), context)<>0 then begin
    writeln('*** Error OFB_Init');
    exit;
  end;
  if SC_OFB_Encrypt(@pt, @ct, BS1, context)<>0 then begin
    writeln('*** Error OFB_Encrypt 1');
    exit;
  end;
  if SC_OFB_Encrypt(@pt[BS1], @ct[BS1], sizeof(TBuf)-BS1, context)<>0 then begin
    writeln('*** Error OFB_Encrypt 2');
    exit;
  end;
  if SC_OFB_Init(key, sizeof(key), TSCBlock(IV), context)<>0 then begin
    writeln('*** Error OFB_Init');
    exit;
  end;
  if SC_OFB_Decrypt(@ct, @dt, sizeof(TBuf), context)<>0 then begin
    writeln('*** Error OFB_Decrypt');
    exit;
  end;
  writeln('OFB  test: ', test(@pt,@dt));
end;


begin
  {$ifdef USEDLL}
    writeln('Test program for SC_DLL V',SC_DLL_Version,'   (C) 2010  W.Ehrhardt');
  {$else}
    writeln('Test program for Shacal-2 modes    (C) 2010  W.Ehrhardt');
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
