program t_kecc4;

{Testing NIST API for Keccak-512 with ShortMsgKAT_512.txt}

{$i std.inc}

{$ifdef APPCONS}
  {$apptype console}
{$endif}


uses
  {$ifdef WINCRT} WinCRT, {$endif}
  BTypes, Base2n, Mem_Util, keccak_n;

var
  bitlen: longint;
  state: thashState;
  msg: array[0..1023] of byte;
  dig: array[0..63] of byte;
  buf: array[0..128] of byte;
  LM, LD: word;
  tf: text;

{$ifdef BIT16}
var
  i: integer;
  s: string;
const
  BITMAX = 990;
{$else}
var
  i: longint;
  {$ifdef UNICODE}
    s: string;
  {$else}
    s: ansistring;
  {$endif}
const
  BITMAX = 2047;
{$endif}

label
  done;

begin
  writeln('Testing NIST API for Keccak-512 with ShortMsgKAT_512.txt');
  {$ifdef BIT16}
    assign(tf,'smkat512.txt'); {Rename to DOS 8.3 format!}
  {$else}
    assign(tf,'ShortMsgKAT_512.txt');
  {$endif}
  reset(tf);
  bitlen := 0;
  repeat
    repeat
      if eof(tf) then begin
        writeln('No (more) test case found');
        goto done;
      end;
      readln(tf,s);
    until pos('Len = ',s)=1;
    {$ifdef debug}
      write(s,#13);
    {$endif}

    s := copy(s,7,length(s));
    val(s,bitlen,i);
    if i<>0 then begin
      writeln('Error bitlength for ',s);
      halt;
    end;

    readln(tf,s);
    if pos('Msg = ',s)<>1 then begin
      writeln('Expected "Msg = " not found');
      halt;
    end;

    s := copy(s,7,length(s));
    {$ifdef BIT16}
      DecodeBase16Str(s,@msg,sizeof(msg),LM);
    {$else}
      DecodeBase16AStr({$ifdef UNICODE}ansistring{$endif}(s),@msg,sizeof(msg),LM);
    {$endif}
    if (bitlen>0) and (LM <> (bitlen+7) div 8) then begin
      writeln('Msg length conflict with Len = ', bitlen);
      writeln('Read=',s);
      halt;
    end;

    readln(tf,s);
    if pos('MD = ',s)<>1 then begin
      writeln('Expected "MD = " not found');
      halt;
    end;

    s := copy(s,6,length(s));
    {$ifdef BIT16}
      DecodeBase16Str(s,@dig,sizeof(dig),LD);
    {$else}
      DecodeBase16AStr({$ifdef UNICODE}ansistring{$endif}(s),@dig,sizeof(dig),LD);
    {$endif}
    if LD<>64 then begin
      writeln('Digist length <> 64');
      halt;
    end;

    i := Init(state,512);
    if i=0 then i := Update(state, @msg, bitlen);
    if i=0 then i := Final(state,@buf);
    if i=0 then begin
      if not compmem(@buf, @dig, sizeof(dig)) then writeln('Failed for Len = ',bitlen);
    end
    else writeln('Error ',i,' for Len = ',bitlen);
  until bitlen>=BITMAX;

done:
  {$ifdef debug}
    writeln;
  {$endif}
  writeln('Done. Max. bit length = ', bitlen);
  close(tf);
end.

