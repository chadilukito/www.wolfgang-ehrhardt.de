{-Test prog for Blowfish chaining modes, we 11.2004}

program t_bmodes;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}


uses
  {$ifdef WINCRT}
    wincrt,
  {$endif}
  mem_util, bf_base, bf_cbc, bf_cfb, bf_ofb, bf_ecb, bf_ctr;

var
  ctx: TBFContext;

{Test vectors by Eric Young from http://www.schneier.com/code/vectors.txt}

{WE Note: For CBC test PT is padded with 00 because BF_CBC}
{         would use cipher text stealing with 29 bytes PT }

const
  key : array[1..16] of byte = ($01,$23,$45,$67,$89,$AB,$CD,$EF,$F0,$E1,$D2,$C3,$B4,$A5,$96,$87);

  IV  : array[1.. 8] of byte = ($FE,$DC,$BA,$98,$76,$54,$32,$10);

  PT  : array[1..32] of byte = ($37,$36,$35,$34,$33,$32,$31,$20,$4E,$6F,$77,$20,$69,$73,$20,$74,
                                $68,$65,$20,$74,$69,$6D,$65,$20,$66,$6F,$72,$20,$00,$00,$00,$00);

  CBC : array[1..32] of byte = ($6B,$77,$B4,$D6,$30,$06,$DE,$E6,$05,$B1,$56,$E2,$74,$03,$97,$93,
                                $58,$DE,$B9,$E7,$15,$46,$16,$D9,$59,$F1,$65,$2B,$D5,$FF,$92,$CC);

  CFB : array[1..29] of byte = ($E7,$32,$14,$A2,$82,$21,$39,$CA,$F2,$6E,$CF,$6D,$2E,$B9,$E7,$6E,
                                $3D,$A3,$DE,$04,$D1,$51,$72,$00,$51,$9D,$57,$A6,$C3);

  OFB : array[1..29] of byte = ($E7,$32,$14,$A2,$82,$21,$39,$CA,$62,$B3,$43,$CC,$5B,$65,$58,$73,
                                $10,$DD,$90,$8D,$0C,$24,$1B,$22,$63,$C2,$CF,$80,$DA);


 kecb : array[1.. 8] of byte = ($01,$23,$45,$67,$89,$AB,$CD,$EF);

 pecb : array[1..16] of byte = ($11,$11,$11,$11,$11,$11,$11,$11,$00,$00,$00,$00,$00,$00,$00,$00);

 cecb : array[1..16] of byte = ($61,$F9,$C3,$80,$22,$81,$B0,$96,$24,$59,$46,$88,$57,$54,$36,$9A);

 {CTR cipher text computed with StrSecII from above key,IV, PT (28 bytes)}
 cctr : array[1..28] of byte = ($19,$7C,$05,$54,$87,$CD,$4A,$DE,$E9,$54,$C2,$3D,$C4,$B1,$BB,$ED,
                                $4A,$B2,$AE,$56,$67,$5F,$CA,$AD,$8F,$24,$0C,$92);

var
  ct: array[1..64] of byte;


{---------------------------------------------------------------------------}
procedure CBC_test;
  {-Test CBC routines}
begin
  {CBC Encrypt}
  if BF_CBC_Init(key, sizeof(key), TBFBlock(IV), ctx)<>0 then begin
    writeln('BF_Init error');
    halt;
  end;
  if BF_CBC_Encrypt(@PT, @CT, sizeof(CBC), ctx)<>0 then begin
    writeln('BF_CBC_Encrypt');
    halt;
  end;
  writeln('CBC Enc: ', CompMem(@ct, @CBC, sizeof(CBC)));
  {CBC Decrypt}
  BF_CBC_Reset(TBFBlock(IV), ctx);
  if BF_CBC_Decrypt(@CBC, @CT, sizeof(CBC), ctx)<>0 then begin
    writeln('BF_CBC_Decrypt');
    halt;
  end;
  writeln('CBC Dec: ', CompMem(@ct, @PT, sizeof(PT)));
end;


{---------------------------------------------------------------------------}
procedure CFB_test;
  {-Test CFB routines}
begin
  {CFB Encrypt}
  if BF_CFB_Init(key, sizeof(key), TBFBlock(IV), ctx)<>0 then begin
    writeln('BF_Init error');
    halt;
  end;
  if BF_CFB_Encrypt(@PT, @CT, sizeof(CFB), ctx)<>0 then begin
    writeln('BF_CFB_Encrypt');
    halt;
  end;
  writeln('CFB Enc: ', CompMem(@ct, @CFB, sizeof(CFB)));
  {CFB Decrypt}
  BF_CFB_Reset(TBFBlock(IV), ctx);
  if BF_CFB_Decrypt(@CFB, @CT, sizeof(CFB), ctx)<>0 then begin
    writeln('BF_CFB_Decrypt');
    halt;
  end;
  writeln('CFB Dec: ', CompMem(@ct, @PT, sizeof(PT)));
end;


{---------------------------------------------------------------------------}
procedure OFB_test;
  {-Test OFB routines}
begin
  {OFB Encrypt}
  if BF_OFB_Init(key, sizeof(key), TBFBlock(IV), ctx)<>0 then begin
    writeln('BF_Init error');
    halt;
  end;
  if BF_OFB_Encrypt(@PT, @CT, sizeof(OFB), ctx)<>0 then begin
    writeln('BF_OFB_Encrypt');
    halt;
  end;
  writeln('OFB Enc: ', CompMem(@ct, @OFB, sizeof(OFB)));
  {OFB Dncrypt}
  BF_OFB_Reset(TBFBlock(IV), ctx);
  if BF_OFB_Decrypt(@OFB, @CT, sizeof(OFB), ctx)<>0 then begin
    writeln('BF_OFB_Decrypt');
    halt;
  end;
  writeln('OFB Dec: ', CompMem(@ct, @PT, sizeof(PT)));
end;


{---------------------------------------------------------------------------}
procedure ECB_Test;
  {-Test OFB routines, enc/dec two blocks from vectors.tst}
begin
  {ECB Encrypt}
  if BF_ECB_Init(kecb, sizeof(kecb), ctx)<>0 then begin
    writeln('BF_Init error');
    halt;
  end;
  if BF_ECB_Encrypt(@pecb, @ct, sizeof(pecb), ctx)<>0 then begin
    writeln('BF_ECB_Encrypt');
    halt;
  end;
  writeln('ECB Enc: ', CompMem(@ct, @cecb, sizeof(cecb)));
  {ECB Decrypt}
  BF_ECB_Reset(ctx);
  if BF_ECB_Decrypt(@cecb, @ct, sizeof(cecb), ctx)<>0 then begin
    writeln('BF_ECB_Decrypt');
    halt;
  end;
  writeln('ECB Dec: ', CompMem(@ct, @pecb, sizeof(pecb)));
end;


{---------------------------------------------------------------------------}
procedure CTR_test;
  {-Test CTR routines}
var
  ictr: TBFBlock;
begin

  {Note: StrSecII increments counter before first use!!}
  ictr := TBFBlock(IV);
  BF_IncMSBFull(ictr);

  {CTR Encrypt}
  if BF_CTR_Init(key, sizeof(key), TBFBlock(ictr), ctx)<>0 then begin
    writeln('BF_Init error');
    halt;
  end;
  if BF_CTR_Encrypt(@PT, @ct, sizeof(cctr), ctx)<>0 then begin
    writeln('BF_CTR_Encrypt');
    halt;
  end;
  writeln('CTR Enc: ', CompMem(@ct, @cctr, sizeof(cctr)));

  {CTR Decrypt}
  BF_CTR_Reset(ictr, ctx);
  if BF_CTR_Decrypt(@cctr, @ct, sizeof(cctr), ctx)<>0 then begin
    writeln('BF_CTR_Decrypt');
    halt;
  end;
  writeln('CTR Dec: ', CompMem(@ct, @pt, sizeof(cctr)));
end;



begin
  writeln('Test program for Blowfish chaining modes    (C) 2004  W.Ehrhardt');
  CBC_test;
  CFB_test;
  OFB_test;
  ECB_test;
  CTR_test;
end.
