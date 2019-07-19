{Simple test for x/salsa20 stream cipher unit, WE 2009}

program T_S20_ST;

{$i std.inc}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifndef FPC}
  {$N+}
{$endif}

uses
  {$ifdef WINCRT}
    WinCRT,
  {$endif}
  salsa20;

begin
  writeln('Simple test for Salsa20 stream cipher unit    (c) 2010 W.Ehrhardt');
  writeln(' Salsa20 stream cipher selftest: ', salsa_selftest);
  writeln('XSalsa20 stream cipher selftest: ', xsalsa_selftest);
  writeln('  ChaCha stream cipher selftest: ', chacha_selftest);
end.
