{-Test prog for SkipJack basic routines, we Jun.2009}

program t_xtbas1;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifndef FPC}
  {$N+}
{$endif}


uses SJ_base,mem_util;

var
  ctx: TSJContext;


{First vector set from clarification.pdf}

const
  p1: TSJBlock = ($aa,$bb,$cc,$dd,$00,$11,$22,$33);
  c1: TSJBlock = ($00,$d3,$12,$7a,$e2,$ca,$87,$25);
  k1: array[0..9] of byte = ($11,$22,$33,$44,$55,$66,$77,$88,$99,$00);

{Test vectors from Botan library http://botan.randombit.net/}
const
  ts: array[1..30] of string[54] = (
       'AABBCCDD00112233:00D3127AE2CA8725:11223344556677889900',
       'CE365D5D21C1A4CB:C00891C551C5E168:9C5F3F996E59C9543249',
       'CB758E2851482982:6C09A2825D32B67E:21A07C1CED3C2C0C1576',
       '7B402EA5E4B7A7C3:C6E32EA485F38324:F62D87056348C5D64071',
       '3AE159B52AE3FD1B:8AD85F68B89DFAD6:0E2B3B9AEEF001392C3C',
       '3828786C48F705D2:9352B87091483003:51BAA0E8AADF4B8B6A60',
       'E060FCC7F7F16FD9:8C70B2C901339B1F:CE70B79AE70F7AA44778',
       '8F5FA719DE4B1D24:958816FE7FC5862B:91A8919EC9360CABB973',
       '0B55FD902BFECC99:CA7F517B383DA760:FB9F7F8B62E4996E49E7',
       'CA7F517B383DA760:278B665DB00CC924:FB9F7F8B62E4996E49E7',
       '6527AF09D0B01CB7:628A8AE67A87F464:90DDF1550EC7DCF4CAE5',
       '628A8AE67A87F464:CD01A638A878E7FE:90DDF1550EC7DCF4CAE5',
       'E7951155B748D347:EAEB4A1470307BF1:3516DABCD760F2BEE4CD',
       'AD14EBC6D0261D94:8DAE0E5E2CD055A0:C9C5DAF7DFD17D902270',
       '9B0C81EDA6853253:DC354CB74F2FC2B4:EEEE6892DCD1ED868F56',
       'C76443A5B0652306:160DF886878D6908:03604B2D0D06A9AA9D68',
       '37F1C930714AA1CF:39DDEC7C8B84DBD6:6E8494476C89110F166C',
       '1E71CDF5AB39DF1D:AE316B4C32222DC9:DF3A10F722776402DAF8',
       '9EE6838FCE6C6CDD:FF7F52D9C17728E3:E4EE21889437C10A7682',
       '111AA47F17CFAABE:1A86B8753F784547:C3C55FCACDD387163C84',
       '0AC61B6C219FC0C4:727AA5B83616105C:E5F795A933FFD70C87AE',
       '56582400B014F8D3:918F72548E0FFCB4:9163BD738BEA13D9CB5C',
       '9C323238D9C76E35:F801578F6050B793:C70CA4689C59CD745EF6',
       '6CD57A531CCF9E20:619E091055D423D8:DC934E7C08D7466E10AA',
       '667DE1649DEA2E89:5FD975B231E25909:EA4FC33C0CA289973FA9',
       '1BC90F76FD901399:AE676788090270E7:9988881616D6CB63B188',
       '9E9CCADD47C9EBDA:22A3D66BA549CCE7:10DF61754870FFD16CFB',
       '2E8FCDE2EFDD1964:FD42E226CF058AE4:2C005FEFE7C4C01ADC5E',
       '128106BDEC982932:C1F24DB137E5C062:6A49942FA39AC190308E',
       'CC93DA20EE2AAE3A:714D626B8AE5D154:92903F26A46FD43F6EB9');
var
  pt,ct,tb: TSJBlock;
  i: integer;
  L: word;
  key: array[0..9] of byte;

begin
  if SJ_Init(k1, sizeof(k1), ctx)<>0 then begin
    writeln('SJ_Init error');
    halt;
  end;
  writeln('Spec/Clarification test vector:');
  SJ_Encrypt(ctx, p1, ct);
  write('Encrypt: ', CompMem(@ct, @c1, sizeof(ct)));
  SJ_Decrypt(ctx, c1, ct);
  writeln(',   Decrypt: ', CompMem(@ct, @p1, sizeof(ct)));

  writeln('Botan test vectors:');
  for i:=1 to 30 do begin
    Hex2Mem(copy(ts[i],1,16),@pt,sizeof(pt),L);
    if sizeof(pt)<>L then begin
       writeln('i=',i:2, '  sizeof(pt)<>L');
       halt;
    end;
    Hex2Mem(copy(ts[i],18,16),@ct,sizeof(ct),L);
    if sizeof(ct)<>L then begin
       writeln('i=',i:2, '  sizeof(ct)<>L');
       halt;
    end;
    Hex2Mem(copy(ts[i],35,20),@key,sizeof(key),L);
    if sizeof(key)<>L then begin
       writeln('i=',i:2, '  sizeof(ct)<>L');
       halt;
    end;
    if SJ_Init(key, sizeof(key), ctx)<>0 then begin
      writeln('i=',i:2, '  SJ_Init error');
      halt;
    end;
    SJ_Encrypt(ctx, pt, tb);
    write('i=',i:2, '  Encrypt:', CompMem(@ct, @tb, sizeof(ct)):5);
    SJ_Decrypt(ctx, ct, tb);
    writeln(',    Decrypt:', CompMem(@pt, @tb, sizeof(pt)):5);
  end;
end.
