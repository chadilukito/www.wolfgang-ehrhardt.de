{-Test program for cam_cprf, (c) we 06.2008}

program T_CPRF;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
     wincrt,
  {$endif}
  cam_cprf;

begin
  writeln('Selftest Camellia CMAC PRF-128: ', CAM_CPRF128_selftest);
end.
