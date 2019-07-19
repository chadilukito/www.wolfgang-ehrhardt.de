program t_kecc5;

{Testing NIST API for Keccak-512 with LongMsgKAT_512.txt)}
{Only 32+ bits supported because ansistrings are used, no}
{real need to rewrite the code with pchars for 16 bit.   }

{$i std.inc}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  BTypes, Base2n, Mem_Util, keccak_n;

{$ifdef BIT16}
error('********  Not for 16 bit compilers  ***********');
{$endif}

var
  bitlen: longint;
  state: thashState;
  msg: array[0..5000] of byte;
  dig: array[0..63] of byte;
  buf: array[0..128] of byte;
  LM, LD: word;
  tf: text;
var
  i: longint;
{$ifdef UNICODE}
  s: string;
{$else}
  s: ansistring;
{$endif}
const
  BITMAX = 34304;

begin
  writeln('Testing NIST API for Keccak-512 with LongMsgKAT_512.txt');
  assign(tf,'LongMsgKAT_512.txt');
  reset(tf);
  bitlen := 0;
  repeat
    repeat
      if eof(tf) then begin
        writeln('No (more) test case found');
        break;
      end;
      readln(tf,s);
    until pos('Len = ',s)=1;
    if eof(tf) then break;
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
    DecodeBase16AStr({$ifdef UNICODE}ansistring{$endif}(s),@msg,sizeof(msg),LM);
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
    DecodeBase16AStr({$ifdef UNICODE}ansistring{$endif}(s),@dig,sizeof(dig),LD);
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

  {$ifdef debug}
    writeln;
  {$endif}
  writeln('Done. Max. bit length = ', bitlen);
  close(tf);
end.

