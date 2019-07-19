{GUI demo for crcmodel/crcm_cat, (c) 2008 W.Ehrhardt}

program lazcrc32;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

uses
{$IFnDEF FPC}
{$ELSE}
  Interfaces,
{$ENDIF}
  Forms,
  tcrc32u_l in 'tcrc32u_l.pas' {Form1};

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
