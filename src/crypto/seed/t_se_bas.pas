{Test program for basic SEED functions, (c) we Jun.2007}
program t_se_bas;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  mem_util,SEA_base;


{$ifdef StrictLong}
  {$warnings off}
  {$R-} {avoid D9+ errors!}
{$endif}


{Test vectors from RFC4269 Appendix B}

{RKx: Intermediate Values Ki0,Ki1}
const
  Key1: TSEABlock = ($00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00);
   PT1: TSEABlock = ($00,$01,$02,$03,$04,$05,$06,$07,$08,$09,$0A,$0B,$0C,$0D,$0E,$0F);
   CT1: TSEABlock = ($5E,$BA,$C6,$E0,$05,$4E,$16,$68,$19,$AF,$F1,$CC,$6D,$34,$6C,$DB);

  Key2: TSEABlock = ($00,$01,$02,$03,$04,$05,$06,$07,$08,$09,$0A,$0B,$0C,$0D,$0E,$0F);
   PT2: TSEABlock = ($00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00);
   CT2: TSEABlock = ($C1,$1F,$22,$F2,$01,$40,$50,$50,$84,$48,$35,$97,$E4,$37,$0F,$43);


  Key3: TSEABlock = ($47,$06,$48,$08,$51,$E6,$1B,$E8,$5D,$74,$BF,$B3,$FD,$95,$61,$85);
   PT3: TSEABlock = ($83,$A2,$F8,$A2,$88,$64,$1F,$B9,$A4,$E9,$A5,$CC,$2F,$13,$1C,$7D);
   CT3: TSEABlock = ($EE,$54,$D1,$3E,$BC,$AE,$70,$6D,$22,$6B,$C3,$14,$2C,$D4,$0D,$4A);


  Key4: TSEABlock = ($28,$DB,$C3,$BC,$49,$FF,$D8,$7D,$CF,$A5,$09,$B1,$1D,$42,$2B,$E7);
   PT4: TSEABlock = ($B4,$1E,$6B,$E2,$EB,$A8,$4A,$14,$8E,$2E,$ED,$84,$59,$3C,$5E,$C7);
   CT4: TSEABlock = ($9B,$9B,$7B,$FC,$D1,$81,$3C,$B9,$5D,$0B,$36,$18,$F4,$0F,$51,$22);

const
   RK1: TSEARndKey = ($7C8F8C7E,$C737A22C,$FF276CDB,$A7CA684A,
                       $2F9D01A1,$70049E41,$AE59B3C4,$4245E90C,
                       $A1D6400F,$DBC1394E,$85963508,$0C5F1FCB,
                       $B684BDA7,$61A4AEAE,$D17E0741,$FEE90AA1,
                       $76CC05D5,$E97A7394,$50AC6F92,$1B2666E5,
                       $65B7904A,$8EC3A7B3,$2F7E2E22,$A2B121B9,
                       $4D0BFDE4,$4E888D9B,$631C8DDC,$4378A6C4,
                       $216AF65F,$7878C031,$71891150,$98B255B0);

   RK2: TSEARndKey = ($C119F584,$5AE033A0,$62947390,$A600AD14,
                       $F6F6544E,$596C4B49,$C1A3DE02,$CE483C49,
                       $5E742E6D,$7E25163D,$8299D2B4,$790A46CE,
                       $EA67D836,$55F354F2,$C47329FB,$F50DB634,
                       $2BD30235,$51679CE6,$FA8D6B76,$A9F37E02,
                       $8B99CC60,$0F6092D4,$BDAEFCFA,$489C2242,
                       $F6357C14,$CFCCB126,$A0AA6D85,$F8C10774,
                       $47F4FEC5,$353AE1BA,$FECCEA48,$A4EF9F9B);

   RK3: TSEARndKey = ($56BE4A0F,$E9F62877,$68BCB66C,$078911DD,
                       $5B82740B,$FD24D09B,$8D608015,$A120E0BE,
                       $810A75AE,$1BF223E5,$F9C0D2D0,$0F676C02,
                       $8F9B5C84,$8A7C8DDD,$D4AB4896,$18E93447,
                       $CF090F51,$5A4C8202,$4EC3196F,$61B1A0DC,
                       $244E07C1,$D0D10B12,$69917C6C,$7FF94FB3,
                       $9A7EB482,$723B5738,$B97522C5,$39CC6349,
                       $FFC2AFD5,$1412E731,$A9AF7241,$A3E67359);

   RK4: TSEARndKey = ($B2B11B63,$2EE9E2D1,$11967260,$71A62F24,
                       $2E017A5A,$35DAD7A7,$1B2AB5FF,$A3ADA69F,
                       $519C9903,$DA90AAEE,$29FD95AD,$B94C3F13,
                       $6F629D19,$8ACE692F,$30A26E73,$2F22338E,
                       $9721073A,$98EE8DAE,$C597A8A9,$27DCDC97,
                       $F5163A00,$5FFD0003,$5CBE65DA,$A73403E4,
                       $7D5CF070,$1D3B8092,$388C702B,$1BAA4945,
                       $87D1AB5A,$FA13FB5C,$C97D7EED,$90724A6E);

{$ifdef StrictLong}
  {$warnings on}
  {$ifdef RangeChecks_on}
    {$R+}
  {$endif}
{$endif}

{---------------------------------------------------------------------------}
procedure TestKeySetup(k: integer; Key: TSEABlock; TRK: TSEARndKey);
var
  i: integer;
  ctx: TSEAContext;
begin
  write(' Test B.',k,': ');
  if SEA_Init(Key, 8*sizeof(key), ctx)<>0 then begin
    writeln('init error');
    exit;
  end;
  for i:=0 to 31 do begin
    if TRK[i]<>ctx.RK[i] then begin
      writeln('first diff at index ',i);
      exit;
    end;
  end;
  writeln('OK');
end;

procedure TestEncDec(k: integer; Key, PT, CT: TSEABlock);
var
  ctx: TSEAContext;
  tmp: TSEABlock;
begin
  write(' Test B.',k,': ');
  if SEA_Init(Key, 8*sizeof(key), ctx)<>0 then begin
    writeln('init error');
    exit;
  end;
  SEA_Encrypt(ctx, PT, tmp);
  write('enc - ', CompMem(@tmp, @CT, sizeof(CT)));
  SEA_Decrypt(ctx, CT, tmp);
  write(',  dec - ', CompMem(@tmp, @PT, sizeof(PT)));
  writeln;
end;

begin
  writeln('Test program SEED Encryption Algorithm , (c) we Jun.2007');
  writeln('Test SEED key setup');
  TestKeySetup(1,Key1,RK1);
  TestKeySetup(2,Key2,RK2);
  TestKeySetup(3,Key3,RK3);
  TestKeySetup(4,Key4,RK4);
  writeln('Test SEED block encrypt/decrypt');
  TestEncDec(1,Key1,PT1,CT1);
  TestEncDec(2,Key2,PT2,CT2);
  TestEncDec(3,Key3,PT3,CT3);
  TestEncDec(4,Key4,PT4,CT4);
end.
