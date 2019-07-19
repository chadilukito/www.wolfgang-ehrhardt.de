{test program for zpipe unit}

program t_zpipe;

{$ifdef win32}
  {$ifndef VirtualPascal}
    {$apptype console}
  {$endif}
{$endif}


uses zlibh, zpipe;


{---------------------------------------------------------------------------}
procedure abort(const msg: str255);
  {-write message and halt}
begin
  writeln(msg);
  halt;
end;


var
  fi, fo: file;
  ok: boolean;
  oc: char8;
  ret: int;
  os: string[3];
begin
  ok := paramcount>2;
  oc := #0;
  if ok then begin
    os := {$ifdef unicode} str255 {$endif}(paramstr(1));
    ok := (length(os)=2) and (os[1]='-');
    if ok then begin
      oc := upcase(os[2]);
      ok := (oc='C') or (oc='D');
    end;
  end;

  if not ok then abort('Usage: t_zpipe [-c|-d] <infile> <outfile>');

  {allow read only infile}
  filemode := 0;
  assign(fi, paramstr(2));
  reset(fi,1);
  if IOResult<>0 then Abort('Reset error: '+{$ifdef unicode} str255 {$endif}(paramstr(2)));

  assign(fo,paramstr(3));
  rewrite(fo,1);
  if IOResult<>0 then Abort('Rewrite error: '+{$ifdef unicode} str255 {$endif}(paramstr(2)));

  if oc='C' then ret := def(fi,fo,Z_DEFAULT_COMPRESSION)
  else ret := inf(fi,fo);

  if ret=Z_OK then writeln('OK') else writeln('zlib error: ', ret);
end.
