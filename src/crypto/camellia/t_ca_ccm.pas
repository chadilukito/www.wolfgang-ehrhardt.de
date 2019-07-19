{-Test program for CCM, (c) we 05.2009}

program T_CCM;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
    wincrt,
  {$endif}
  {$ifdef USEDLL}
    {$ifdef VirtualPascal}
      CAM_Intv,
    {$else}
      CAM_Intf,
    {$endif}
  {$else}
    CAM_Base, CAM_CCM,
  {$endif}
  mem_util;



{---------------------------------------------------------------------------}
procedure Simple_Tests;
  {-Two tests from RFC}
const
  key1: array[0..15] of byte = ($C0,$C1,$C2,$C3,$C4,$C5,$C6,$C7,$C8,$C9,$CA,$CB,$CC,$CD,$CE,$CF);
  iv1 : array[0..12] of byte = ($00,$00,$00,$03,$02,$01,$00,$A0,$A1,$A2,$A3,$A4,$A5);
  hdr1: array[0..07] of byte = ($00,$01,$02,$03,$04,$05,$06,$07);
  pt1 : array[0..22] of byte = ($08,$09,$0A,$0B,$0C,$0D,$0E,$0F,
                                $10,$11,$12,$13,$14,$15,$16,$17,
                                $18,$19,$1A,$1B,$1C,$1D,$1E);
  ct1 : array[0..22] of byte = ($ba,$73,$71,$85,$e7,$19,$31,$04,
                                $92,$f3,$8a,$5f,$12,$51,$da,$55,
                                $fa,$fb,$c9,$49,$84,$8a,$0d);
  tag1: array[0..07] of byte = ($fc,$ae,$ce,$74,$6b,$3d,$b9,$ad);

const
  key2: array[0..15] of byte = ($C0,$C1,$C2,$C3,$C4,$C5,$C6,$C7,$C8,$C9,$CA,$CB,$CC,$CD,$CE,$CF);
  iv2 : array[0..12] of byte = ($00,$00,$00,$06,$05,$04,$03,$A0,$A1,$A2,$A3,$A4,$A5);
  hdr2: array[0..11] of byte = ($00,$01,$02,$03,$04,$05,$06,$07,$08,$09,$0A,$0B);
  pt2 : array[0..18] of byte = ($0C,$0D,$0E,$0F,$10,$11,$12,$13,
                                $14,$15,$16,$17,$18,$19,$1A,$1B,
                                $1C,$1D,$1E);
  ct2 : array[0..18] of byte = ($ca,$ef,$1e,$82,$72,$11,$b0,$8f,
                                $7b,$d9,$0f,$08,$c7,$72,$88,$c0,
                                $70,$a4,$a0);
  tag2: array[0..07] of byte = ($8b,$3a,$93,$3a,$63,$e4,$97,$a0);


var
  ccm_ctx: TCAMContext;

var
  tag: TCAMBlock;
  buf: array[0..63] of byte;
  err: integer;
begin

  {-----------------------------------------------------------------}
  writeln('Test 1: Ex functions');
  err := CAM_Init(Key1, 8*sizeof(key1), ccm_ctx);
  if err=0 then err := CAM_CCM_Enc_AuthEx(ccm_ctx, tag, sizeof(tag1),
                                          iv1, sizeof(iv1), @hdr1, sizeof(hdr1),
                                          @pt1, sizeof(pt1), @buf);
  if err<>0 then writeln('Err1: ', err)
  else begin
    writeln(' CT1: ', compmem(@buf, @ct1, sizeof(ct1)));
    writeln('Tag1: ', compmem(@tag, @tag1, sizeof(tag1)));
  end;
  err := CAM_CCM_Dec_VeriEx(ccm_ctx, @tag1, sizeof(tag1),
                            iv1, sizeof(iv1), @hdr1, sizeof(hdr1),
                            @ct1, sizeof(ct1), @buf);
  if err<>0 then writeln('Err1: ', err)
  else begin
    writeln(' PT1: ', compmem(@buf, @pt1, sizeof(pt1)));
  end;

  writeln('Test 1: simple functions');
  err := CAM_CCM_Enc_Auth(tag, sizeof(tag1), key1, sizeof(key1),
                          iv1, sizeof(iv1), @hdr1, sizeof(hdr1),
                          @pt1, sizeof(pt1), @buf);
  if err<>0 then writeln('Err1: ', err)
  else begin
    writeln(' CT1: ', compmem(@buf, @ct1, sizeof(ct1)));
    writeln('Tag1: ', compmem(@tag, @tag1, sizeof(tag1)));
  end;
  err := CAM_CCM_Dec_Veri(@tag1, sizeof(tag1), key1, sizeof(key1),
                          iv1, sizeof(iv1), @hdr1, sizeof(hdr1),
                          @ct1, sizeof(ct1), @buf);
  if err<>0 then writeln('Err1: ', err)
  else begin
    writeln(' PT1: ', compmem(@buf, @pt1, sizeof(pt1)));
  end;

  {-----------------------------------------------------------------}
  writeln('Test 2: Ex functions');
  err := CAM_Init(Key2, 8*sizeof(key2), ccm_ctx);
  if err=0 then err := CAM_CCM_Enc_AuthEx(ccm_ctx, tag, sizeof(tag2),
                                          iv2, sizeof(iv2), @hdr2, sizeof(hdr2),
                                          @pt2, sizeof(pt2), @buf);
  if err<>0 then writeln('Err2: ', err)
  else begin
    writeln(' CT2: ', compmem(@buf, @ct2, sizeof(ct2)));
    writeln('Tag2: ', compmem(@tag, @tag2, sizeof(tag2)));
  end;
  err := CAM_CCM_Dec_VeriEx(ccm_ctx, @tag2, sizeof(tag2),
                            iv2, sizeof(iv2), @hdr2, sizeof(hdr2),
                            @ct2, sizeof(ct2), @buf);
  if err<>0 then writeln('Err2: ', err)
  else begin
    writeln(' PT2: ', compmem(@buf, @pt2, sizeof(pt2)));
  end;

  writeln('Test 2: simple functions');
  err := CAM_CCM_Enc_Auth(tag, sizeof(tag2), key2, sizeof(key2),
                          iv2, sizeof(iv2), @hdr2, sizeof(hdr2),
                          @pt2, sizeof(pt2), @buf);
  if err<>0 then writeln('Err2: ', err)
  else begin
    writeln(' CT2: ', compmem(@buf, @ct2, sizeof(ct2)));
    writeln('Tag2: ', compmem(@tag, @tag2, sizeof(tag2)));
  end;
  err := CAM_CCM_Dec_Veri(@tag2, sizeof(tag2), key2, sizeof(key2),
                          iv2, sizeof(iv2), @hdr2, sizeof(hdr2),
                          @ct2, sizeof(ct2), @buf);
  if err<>0 then writeln('Err2: ', err)
  else begin
    writeln(' PT2: ', compmem(@buf, @pt2, sizeof(pt2)));
  end;

end;


{---------------------------------------------------------------------------}
procedure LTC_Test(print: boolean);
  {-reproduce LTC CCM-CAM test vectors}
var
  key, nonce, tag: TCAMBlock;
  buf: array[0..63] of byte;
  i,k,err: integer;
const
  final: TCAMBlock = ($0f,$5a,$69,$f5,$2a,$a8,$d8,$50,$8d,$09,$e6,$42,$51,$1e,$54,$e5);
begin
  writeln('LibTomCrypt CCM-CAM test');
  HexUpper := true;
  for i:=0 to 15 do key[i] := i and $FF;
  nonce := key;
  for k:=0 to 32 do begin
    for i:=0 to k-1 do buf[i] := i and $FF;
    err := CAM_CCM_Enc_Auth(tag, sizeof(tag), key, sizeof(key), nonce, 13,  @buf, k, @buf, k, @buf);
    if err<>0 then begin
      writeln('CAM_CCM_Enc_Auth error code ',err, ' at k=',k);
      exit;
    end;
    if print then writeln(k:2,': ',HexStr(@buf,k),', ',HexStr(@tag,sizeof(tag)));
    key := tag;
  end;
  writeln('Final tag OK: ', compmem(@tag, @final, sizeof(final)));
end;




{---------------------------------------------------------------------------}
procedure RFC_Packets;
  {-Check (non-random) CCM packets from RFC 3610}
type
  ta25 = array[0..24] of byte;
  ta10 = array[0..09] of byte;
const
  ctest: array[1..12] of ta25 = (
           ($ba,$73,$71,$85,$e7,$19,$31,$04,$92,$f3,$8a,$5f,$12,$51,$da,$55,$fa,$fb,$c9,$49,$84,$8a,$0d,$00,$00),
           ($5d,$25,$64,$bf,$8e,$af,$e1,$d9,$95,$26,$ec,$01,$6d,$1b,$f0,$42,$4c,$fb,$d2,$cd,$62,$84,$8f,$33,$00),
           ($81,$f6,$63,$d6,$c7,$78,$78,$17,$f9,$20,$36,$08,$b9,$82,$ad,$15,$dc,$2b,$bd,$87,$d7,$56,$f7,$92,$04),
           ($ca,$ef,$1e,$82,$72,$11,$b0,$8f,$7b,$d9,$0f,$08,$c7,$72,$88,$c0,$70,$a4,$a0,$00,$00,$00,$00,$00,$00),
           ($2a,$d3,$ba,$d9,$4f,$c5,$2e,$92,$be,$43,$8e,$82,$7c,$10,$23,$b9,$6a,$8a,$77,$25,$00,$00,$00,$00,$00),
           ($fe,$a5,$48,$0b,$a5,$3f,$a8,$d3,$c3,$44,$22,$aa,$ce,$4d,$e6,$7f,$fa,$3b,$b7,$3b,$ab,$00,$00,$00,$00),
           ($54,$53,$20,$26,$e5,$4c,$11,$9a,$8d,$36,$d9,$ec,$6e,$1e,$d9,$74,$16,$c8,$70,$8c,$4b,$5c,$2c,$00,$00),
           ($8a,$d1,$9b,$00,$1a,$87,$d1,$48,$f4,$d9,$2b,$ef,$34,$52,$5c,$cc,$e3,$a6,$3c,$65,$12,$a6,$f5,$75,$00),
           ($5d,$b0,$8d,$62,$40,$7e,$6e,$31,$d6,$0f,$9c,$a2,$c6,$04,$74,$21,$9a,$c0,$be,$50,$c0,$d4,$a5,$77,$87),
           ($db,$11,$8c,$ce,$c1,$b8,$76,$1c,$87,$7c,$d8,$96,$3a,$67,$d6,$f3,$bb,$bc,$5c,$00,$00,$00,$00,$00,$00),
           ($7c,$c8,$3d,$8d,$c4,$91,$03,$52,$5b,$48,$3d,$c5,$ca,$7e,$a9,$ab,$81,$2b,$70,$56,$00,$00,$00,$00,$00),
           ($2c,$d3,$5b,$88,$20,$d2,$3e,$7a,$a3,$51,$b0,$e9,$2f,$c7,$93,$67,$23,$8b,$2c,$c7,$48,$00,$00,$00,$00));
  ttest: array[1..12] of ta10 = (
           ($fc,$ae,$ce,$74,$6b,$3d,$b9,$ad,$00,$00),
           ($60,$b2,$29,$5d,$f2,$42,$83,$e8,$00,$00),
           ($f5,$51,$d6,$68,$2f,$23,$aa,$46,$00,$00),
           ($8b,$3a,$93,$3a,$63,$e4,$97,$a0,$00,$00),
           ($8f,$a1,$7b,$a7,$f3,$31,$db,$09,$00,$00),
           ($ab,$36,$a1,$ee,$4f,$e0,$fe,$28,$00,$00),
           ($ac,$af,$a3,$bc,$cf,$7a,$4e,$bf,$95,$73),
           ($73,$88,$e4,$91,$3e,$f1,$47,$01,$f4,$41),
           ($94,$d6,$e2,$30,$cd,$25,$c9,$fe,$bf,$87),
           ($d0,$92,$99,$eb,$11,$f3,$12,$f2,$32,$37),
           ($07,$9d,$af,$fa,$da,$16,$cc,$cf,$2c,$4e),
           ($cb,$b9,$4c,$29,$47,$79,$3d,$64,$af,$75));
var
  pn: integer;
  key, nonce, tag, hdr: TCAMBlock;
  buf: array[0..63] of byte;
  i,ih,it,k,err: integer;
  plen,tlen,hlen: word;
  x: longint;
  b: byte;
begin
  writeln('Test packet vectors 1 .. 12 from RFC 5528');
  nonce[00] := 0;
  nonce[01] := 0;
  nonce[02] := 0;
  nonce[07] := $A0;
  nonce[08] := $A1;
  nonce[09] := $A2;
  nonce[10] := $A3;
  nonce[11] := $A4;
  nonce[12] := $A5;
  pn := 0;
  for i:=0 to 15 do key[i] := $C0+i;
  for it:=0 to 1 do begin
    tlen := 8 + 2*it;
    for ih:=0 to 1 do begin
      hlen := 8 + 4*ih;
      for k := 31 to 33 do begin
        pLen := k-hlen;
        x := pn*$01010101+$03020100;
        inc(pn);
        nonce[03] := (x shr 24) and $ff;
        nonce[04] := (x shr 16) and $ff;
        nonce[05] := (x shr 08) and $ff;
        nonce[06] :=  x and $ff;
        b := 0;
        for i:=0 to pred(hlen) do begin
          hdr[i] := b;
          inc(b);
        end;
        for i:=0 to pred(pLen) do begin
          buf[i] := b;
          inc(b);
        end;
        err := CAM_CCM_Enc_Auth(tag,tlen,key,16,nonce,13,@hdr,hlen,@buf,plen,@buf);
        write('Packet ',pn:2);
        if err<>0 then writeln(': CAM_CCM_Enc_Auth error code ',err)
        else begin
          writeln(':  CT ',compmem(@buf,@ctest[pn],plen), ',  Tag ',compmem(@tag,@ttest[pn],tlen));
          err := CAM_CCM_Dec_Veri(@tag,tlen,key,16,nonce,13,@hdr,hlen,@ctest[pn],plen,@buf);
          if err<>0 then writeln(' - CAM_CCM_Dec_Veri error code ',err);
        end;
      end;
    end;
  end;
end;

begin
  writeln('Test program CAM-CCM mode    (c) 2009 W.Ehrhardt');
  {$ifdef USEDLL}
    writeln('DLL Version: ',CAM_DLL_Version);
  {$endif}
  Simple_Tests;
  RFC_Packets;
end.
