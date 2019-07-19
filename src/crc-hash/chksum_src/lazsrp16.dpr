program lazsrp16;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

uses
{$IFnDEF FPC}
{$ELSE}
  Interfaces,
{$ENDIF}
  Forms,
  srp16u_l in 'srp16u_l.pas' {Form1};

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
