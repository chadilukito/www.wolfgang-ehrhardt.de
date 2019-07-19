{Twofish 'Monte Carlo Tests',  we 06.2006}

program t_mcst;

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
  tf_base, tf_cbc, tf_ecb, BTypes, mem_util;

const
  IMAX = 399;
  JMAX = 9999;


{---------------------------------------------------------------------------}
procedure ECBEncr;
  {-Reproduce ecb_e_m.txt}

  procedure TestBits(kbits: word; ts: BString);
    {-generate part for keysize kbits}
  var
    i,j,Err: Integer;
    PT, CT: TTFBlock;
    Key: array[0..31] of byte;
    ctx: TTFContext;
  begin
    write(kbits, ' bits ');
    fillchar(Key, sizeof(Key), 0);
    fillchar(PT, sizeof(PT), 0);
    CT := PT;
    for i:=0 to IMAX do begin
      if i and 7 = 0 then write('.');
      Err := TF_ECB_Init(Key, kbits, ctx);
      if Err<>0 then begin
        writeln('TF_ECB_Init error: ',Err);
        halt;
      end;
      for j:=0 to JMAX do begin
        PT := CT;
        Err := TF_ECB_Encrypt(@CT, @CT, 16, ctx);
        if Err<>0 then begin
          writeln('TF_ECB_Encrypt error: ', Err);
          halt;
        end;
      end;
      case kbits of
        128: for j:=0 to 15 do Key[j] := Key[j] xor CT[j];
        192: begin
               for j:=0 to  7 do Key[j]   := Key[j]   xor PT[8+j];
               for j:=0 to 15 do Key[j+8] := Key[j+8] xor CT[j];
             end;
        256: begin
               for j:=0 to 15 do Key[j]    := Key[j]    xor PT[j];
               for j:=0 to 15 do Key[j+16] := Key[j+16] xor CT[j];
             end;
      end;
    end;
    writeln(' ',ts=HexStr(@CT,16));
  end;

const
  CT128='B732DF6CC184B01F9974DB17289FB41D';
  CT192='3AF5C4EF729D702C5C50A0A773793CB8';
  CT256='002CB6685B2651AD49DA77A3AD1D2067';
begin
  writeln('ecb_e_m');
  TestBits(128, CT128);
  TestBits(192, CT192);
  TestBits(256, CT256);
end;

{---------------------------------------------------------------------------}
procedure ECBDecr;
  {-Reproduce ecb_d_m.txt}

  procedure TestBits(kbits: word; ts: BString);
    {-generate part for keysize kbits}
  var
    i,j,Err: Integer;
    PT, CT: TTFBlock;
    Key: array[0..31] of byte;
    ctx: TTFContext;
  begin
    write(kbits, ' bits ');
    fillchar(Key, sizeof(Key), 0);
    fillchar(PT, sizeof(PT), 0);
    CT := PT;
    for i:=0 to IMAX do begin
      if i and 7 = 0 then write('.');
      Err := TF_ECB_Init(Key, kbits, ctx);
      if Err<>0 then begin
        writeln('TF_ECB_Init error: ', Err);
        halt;
      end;
      for j:=0 to JMAX do begin
        PT := CT;
        Err := TF_ECB_Decrypt(@CT, @CT, 16, ctx);
        if Err<>0 then begin
          writeln('TF_ECB_Decrypt error: ', Err);
          halt;
        end;
      end;
      case kbits of
        128: for j:=0 to 15 do Key[j] := Key[j] xor CT[j];
        192: begin
               for j:=0 to  7 do Key[j]   := Key[j]   xor PT[8+j];
               for j:=0 to 15 do Key[j+8] := Key[j+8] xor CT[j];
             end;
        256: begin
               for j:=0 to 15 do Key[j]    := Key[j]    xor PT[j];
               for j:=0 to 15 do Key[j+16] := Key[j+16] xor CT[j];
             end;
      end;
    end;
    writeln(' ',ts=HexStr(@CT,16));
  end;

const
  PT128='A86CEEE664902053FCD3575C3CBBC876';
  PT192='3A372A2C050DA35D08802C203AF398A0';
  PT256='E036ACCDD45E0EF4A619BB707FF4F287';

begin
  writeln('ecb_d_m');
  TestBits(128, PT128);
  TestBits(192, PT192);
  TestBits(256, PT256);
end;


{---------------------------------------------------------------------------}
procedure CBCEncr;
  {-Reproduce cbc_e_m.txt}

  procedure TestBits(kbits: word; ts: BString);
    {-generate part for keysize kbits}
  var
    i,j,Err: Integer;
    IV, PT, CT: TTFBlock;
    Key: array[0..31] of byte;
    ctx: TTFContext;
  begin
    write(kbits, ' bits ');
    fillchar(Key, sizeof(Key), 0);
    fillchar(PT, sizeof(PT), 0);
    fillchar(IV, sizeof(IV), 0);
    CT := PT;
    for i:=0 to IMAX do begin
      if i and 7 = 0 then write('.');
      Err := TF_CBC_Init(Key, kbits, IV, ctx);
      if Err<>0 then begin
        writeln('TF_CBC_Init error: ', Err);
        halt;
      end;
      for j:=0 to JMAX do begin
        CT := PT;
        PT := ctx.IV;
        Err := TF_CBC_Encrypt(@CT, @CT, 16, ctx);
        if Err<>0 then begin
          writeln('TF_CBC_Encrypt error: ', Err);
          halt;
        end;
      end;
      IV := CT;
      case kbits of
        128: for j:=0 to 15 do Key[j] := Key[j] xor CT[j];
        192: begin
               for j:=0 to  7 do Key[j]   := Key[j]   xor PT[8+j];
               for j:=0 to 15 do Key[j+8] := Key[j+8] xor CT[j];
             end;
        256: begin
               for j:=0 to 15 do Key[j]    := Key[j]    xor PT[j];
               for j:=0 to 15 do Key[j+16] := Key[j+16] xor CT[j];
             end;
      end;
    end;
    writeln(' ',ts=HexStr(@CT,16));
  end;

const
  CT128='28FDC8977E692AB60F1DBD40CDB8B23F';
  CT192='B34A31F100565375C3C943CC6000C84D';
  CT256='08E526F57736D82AB41B3B1DF05AF3A3';

begin
  writeln('cbc_e_m');
  TestBits(128,CT128);
  TestBits(192,CT192);
  TestBits(256,CT256);
end;


{---------------------------------------------------------------------------}
procedure CBCDecr;
  {-Reproduce cbc_d_m.txt}

  procedure TestBits(kbits: word; ts: BString);
    {-generate part for keysize kbits}
  var
    i,j,Err: Integer;
    IV, PT, CT: TTFBlock;
    Key: array[0..31] of byte;
    ctx: TTFContext;
  begin
    write(kbits, ' bits ');
    fillchar(Key, sizeof(Key), 0);
    fillchar(PT, sizeof(PT), 0);
    fillchar(IV, sizeof(IV), 0);
    for i:=0 to IMAX do begin
      if i and 7 = 0 then write('.');
      CT := PT;
      Err := TF_CBC_Init(Key, kbits, IV, ctx);
      if Err<>0 then begin
        writeln('TF_CBC_Init error: ', Err);
        halt;
      end;
      PT := CT;
      for j:=0 to JMAX do begin
        CT := PT;
        Err := TF_CBC_Decrypt(@PT, @PT, 16, ctx);
        if Err<>0 then begin
          writeln('TF_CBC_Decrypt error: ', Err);
          halt;
        end;
      end;
      IV := ctx.IV;
      case kbits of
        128: for j:=0 to 15 do Key[j] := Key[j] xor PT[j];
        192: begin
               for j:=0 to  7 do Key[j]   := Key[j]   xor CT[8+j];
               for j:=0 to 15 do Key[j+8] := Key[j+8] xor PT[j];
             end;
        256: begin
               for j:=0 to 15 do Key[j]    := Key[j]    xor CT[j];
               for j:=0 to 15 do Key[j+16] := Key[j+16] xor PT[j];
             end;
      end;
    end;
    writeln(' ',ts=HexStr(@PT,16));
  end;
const
  PT128='9AAF16457300750022E65F4A91E366BE';
  PT192='17F1A6B67DA5A95053A25A1B6232304C';
  PT256='84265D9B4541486B9CE3D53B9C3C253C';

begin
  writeln('cbc_d_m');
  TestBits(128,PT128);
  TestBits(192,PT192);
  TestBits(256,PT256);
end;



begin
  writeln('T_MCST - Twofish Monte Carlo Self Tests     (c) 2006-2008 W.Ehrhardt');
  HexUpper := true;
  ECBEncr;
  ECBDecr;
  CBCEncr;
  CBCDecr;
end.

