program t_sm_st;

{$i STD.INC}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

uses
  {$ifdef WINCRT}
    wincrt,
  {$endif}
  sosemanu;

begin
  writeln('Self test: ', sose_selftest);
end.
