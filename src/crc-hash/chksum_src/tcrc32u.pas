(*************************************************************************

 DESCRIPTION     :  GUI demo for crcmodel/crcm_cat

 REQUIREMENTS    :  D3-D7/D9-D10/D12/D25S

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODUS   :  ---

 REFERENCES      :  [1] Ross Williams' public domain C sources crcmodel.c, crcmodel.h
                        in "A Painless Guide to CRC Error Detection Algorithms"
                        http://www.ross.net/crc/download/crc_v3.txt
                    [2] Greg Cook's Catalogue of Parameterised CRC Algorithms
                        http://reveng.sourceforge.net/crc-catalogue/

 REMARK          :  - For Delphi2 ignore/remove all unsupported properties
                    - D25 tested with Tokyo Starter/Win32

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     01.09.09  W.Ehrhardt  Initial version from tcrc16
 0.11     13.03.10  we          Changed groupbox caption to CRC-32
 0.12     13.03.10  we          Fix for InvHex display
 0.13     17.05.17  we          CRC32_AUTOSAR
  **************************************************************************)

(*-------------------------------------------------------------------------
 (C) Copyright 2009-2017 Wolfgang Ehrhardt

 This software is provided 'as-is', without any express or implied warranty.
 In no event will the authors be held liable for any damages arising from
 the use of this software.

 Permission is granted to anyone to use this software for any purpose,
 including commercial applications, and to alter it and redistribute it
 freely, subject to the following restrictions:

 1. The origin of this software must not be misrepresented; you must not
    claim that you wrote the original software. If you use this software in
    a product, an acknowledgment in the product documentation would be
    appreciated but is not required.

 2. Altered source versions must be plainly marked as such, and must not be
    misrepresented as being the original software.

 3. This notice may not be removed or altered from any source distribution.
----------------------------------------------------------------------------*)

unit tcrc32u;

interface

{$i std.inc}

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls, Buttons;

type
  TForm1 = class(TForm)
    Edit1: TEdit;         {HEX/string input control}
    CB_Format: TComboBox; {HEX/string input format control}
    GroupBox1: TGroupBox;
    LN1: TLabel;          {LNx: labels for parax.name}
    LN2: TLabel;          {LVx: labels for crc value with parax}
    LN3: TLabel;
    LN4: TLabel;
    LN5: TLabel;
    LN6: TLabel;
    LN7: TLabel;
    LN8: TLabel;
    LN9: TLabel;
    LV1: TLabel;
    LV2: TLabel;
    LV3: TLabel;
    LV4: TLabel;
    LV5: TLabel;
    LV6: TLabel;
    LV7: TLabel;
    LV8: TLabel;
    LV9: TLabel;
    LN10: TLabel;
    LV10: TLabel;
    Lab_InvHex: TLabel;
    Lab_Hdr: TLabel;
    Lab_Foot: TLabel;

    procedure FormCreate(Sender: TObject);
      {-One-time initialization}
    procedure FormShow(Sender: TObject);
      {-(Re)calculate and display CRCs if form is shown}
    procedure Edit1Change(Sender: TObject);
      {-(Re)calculate and display CRCs if input changed}
    procedure CB_FormatChange(Sender: TObject);
      {-(Re)calculate and display CRCs if input format changed}
  private
    { Private declarations }
    buf  : array[0..4095] of byte;
    blen : word;
  public
    { Public declarations }
    procedure RecalcAll;
      {-Calculate and display CRCs for all crcm_cat 16 bit algorithms}
    procedure CheckAndCalc;
      {-Check input, display warning if inv. Hex, calculate and display all CRCs}
  end;

var
  Form1: TForm1;

implementation

uses
  Base2N, crcmodel, crcm_cat;

{$R *.DFM}


{---------------------------------------------------------------------------}
procedure Recalc1(const para: TCRCParam; const TN, TV: TLabel);
  {-Calculate of blen bytes of buf with CRC defined by parameter set para}
  { Display para.name on at label TN and CRC at label TV}
var
  CRC: longint;
  ctx: TCRC_ctx;
begin
  cm_Create(para,nil,ctx);
  cm_Full(ctx,CRC,@Form1.buf,Form1.blen);
  TN.Caption := {$ifdef D12Plus} string {$endif}(para.name);
  TV.Caption := '$'+IntToHex(CRC,8);
end;


{---------------------------------------------------------------------------}
procedure TForm1.RecalcAll;
  {-Calculate and display CRCs for all crcm_cat 32 bit algorithms}
begin
  Recalc1(    CRC32_Zip , LN1  , LV1  );
  Recalc1(  CRC32_BZIP2 , LN2  , LV2  );
  Recalc1(      CRC32_C , LN3  , LV3  );
  Recalc1(      CRC32_D , LN4  , LV4  );
  Recalc1( CRC32_JAMCRC , LN5  , LV5  );
  Recalc1(  CRC32_MPEG2 , LN6  , LV6  );
  Recalc1(  CRC32_POSIX , LN7  , LV7  );
  Recalc1(      CRC32_Q , LN8  , LV8  );
  Recalc1(   CRC32_XFER , LN9  , LV9  );
  Recalc1(CRC32_AUTOSAR , LN10 , LV10 );
end;

{---------------------------------------------------------------------------}
procedure TForm1.CheckAndCalc;
  {-Check input, display warning if inv. Hex, calculate and display all CRCs}
var
  s: ansistring;
  i: integer;
  HOK: boolean;
const
  HexC: array[0..15] of ansichar = '0123456789ABCDEF';
begin
  s := {$ifdef D12Plus} ansistring {$endif}(Edit1.Text);
  if length(s)>sizeof(buf) then SetLength(s,sizeof(buf));
  blen := length(s);
  if CB_Format.Itemindex=1 then begin
    {string input, copy char to buf bytes}
    Lab_InvHex.Visible := false;
    Lab_InvHex.Caption := '';
    for i:=1 to blen do buf[i-1] := byte(s[i]);
  end
  else begin
    {Hex input, first check for invalid chars}
    HOK := true;
    for i:=1 to blen do begin
      if pos(upcase(s[i]),HexC)=0 then begin
        HOK := false;
        break;
      end;
    end;
    if HOK then begin
      Lab_InvHex.Visible := false;
      Lab_InvHex.Caption := '';
    end
    else begin
      Lab_InvHex.Visible := true;
      Lab_InvHex.Caption := 'Invalid HEX char(s)';
    end;
    {Convert hex string to memory at buf, stops at first invalid}
    DecodeBase16AStr(s, @buf, sizeof(buf),blen);
  end;
  {Calculate and display all CRCs of buf}
  RecalcAll;
end;

{---------------------------------------------------------------------------}
procedure TForm1.FormCreate(Sender: TObject);
  {-One-time initialization}
begin
  CB_Format.Itemindex := 0;
  Lab_InvHex.Caption  := '';
end;

{---------------------------------------------------------------------------}
procedure TForm1.FormShow(Sender: TObject);
  {-(Re)calculate and display CRCs if form is shown}
begin
  RecalcAll;
end;

{---------------------------------------------------------------------------}
procedure TForm1.Edit1Change(Sender: TObject);
  {-(Re)calculate and display CRCs if input changed}
begin
  if Edit1.Modified then CheckAndCalc;
end;

{---------------------------------------------------------------------------}
procedure TForm1.CB_FormatChange(Sender: TObject);
  {-(Re)calculate and display CRCs if input format changed}
begin
  CheckAndCalc;
end;

end.
