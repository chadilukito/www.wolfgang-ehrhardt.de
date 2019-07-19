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
 0.10     18.08.08  W.Ehrhardt  Initial version
 0.11     20.08.08  we          Clear Lab_InvHex for empty HEX input, add comments
 0.12     06.09.08  we          Version display, finalize for web upload
 0.13     24.09.08  we          Max input length 1000, ansistring
 0.14     01.12.08  we          8 new parameter records from [2]
 0.15     25.04.09  we          2 new parameter records from [2]
 0.16     02.06.09  we          Fixed name display position of CRC16_EN_13757
 0.17     04.06.09  we          Removed reserved from slots 18/19
 0.18     12.07.09  we          Max hex length increased to 4096
 0.19     21.07.09  we          D12 fixes
 0.20     01.10.09  we          CRC-16/MAXIM, CRC-16/T10-DIF
 0.21     13.03.10  we          CRC16_DDS110, CRC16_TELEDISK
 0.22     16.12.10  we          CRC-16/Sick
 0.23     03.01.14  we          CRC16_CDMA2000, CRC16_DECTX, CRC16_TMS37157
 0.24     17.05.17  we          8 new algrithms
 0.24.1   12.06.18  we          Lazarus adjustments
  **************************************************************************)

(*-------------------------------------------------------------------------
 (C) Copyright 2008-2018 Wolfgang Ehrhardt

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

unit tcrc16u_l;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

{$i std.inc}

uses
{$IFnDEF FPC}
  Windows,
{$ELSE}
  LCLIntf, LCLType, LMessages,
{$ENDIF}
  Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
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
    LN11: TLabel;
    LN12: TLabel;
    LN13: TLabel;
    LN14: TLabel;
    LN15: TLabel;
    LN16: TLabel;
    LN17: TLabel;
    LN18: TLabel;
    LN19: TLabel;
    LV10: TLabel;
    LN20: TLabel;
    LN21: TLabel;
    LN22: TLabel;
    LN23: TLabel;
    LN24: TLabel;
    LN25: TLabel;
    LN26: TLabel;
    LN27: TLabel;
    LN28: TLabel;
    LV11: TLabel;
    LV12: TLabel;
    LV13: TLabel;
    LV14: TLabel;
    LV15: TLabel;
    LV16: TLabel;
    LV17: TLabel;
    LV18: TLabel;
    LV19: TLabel;
    LV20: TLabel;
    LV21: TLabel;
    LV22: TLabel;
    LV23: TLabel;
    LV24: TLabel;
    LV25: TLabel;
    LV26: TLabel;
    LV27: TLabel;
    LV28: TLabel;
    Lab_InvHex: TLabel;
    Lab_Hdr: TLabel;
    Lab_Foot: TLabel;
    LN29: TLabel;
    LN30: TLabel;
    LN31: TLabel;
    LN32: TLabel;
    LN33: TLabel;
    LN34: TLabel;
    LN35: TLabel;
    LN36: TLabel;
    LV29: TLabel;
    LV30: TLabel;
    LV31: TLabel;
    LV32: TLabel;
    LV33: TLabel;
    LV34: TLabel;
    LV35: TLabel;
    LV36: TLabel;

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
  Base2N, CRC_Sick, crcmodel, crcm_cat;

{$IFnDEF FPC}
  {$R *.dfm}
{$ELSE}
  {$R *.lfm}
{$ENDIF}


{---------------------------------------------------------------------------}
procedure RecalcSick(const TN, TV: TLabel);
var
  CRC: word;
begin
  CRC_Sick_Full(CRC,@Form1.buf,Form1.blen);
  TN.Caption := 'CRC-16/Sick';
  TV.Caption := '$'+IntToHex(CRC,4);
end;


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
  TV.Caption := '$'+IntToHex(CRC,4);
end;


{---------------------------------------------------------------------------}
procedure TForm1.RecalcAll;
  {-Calculate and display CRCs for all crcm_cat 16 bit algorithms}
begin
  Recalc1(         CRC16_ARC , LN1  , LV1  );
  Recalc1(        CRC16_ATOM , LN2  , LV2  );
  Recalc1(   CRC16_AUG2_CITT , LN3  , LV3  );
  Recalc1(    CRC16_AUG_CITT , LN4  , LV4  );
  Recalc1(     CRC16_BT_CHIP , LN5  , LV5  );
  Recalc1(     CRC16_BUYPASS , LN6  , LV6  );
  Recalc1(        CRC16_CITT , LN7  , LV7  );
  Recalc1(         CRC16_DNP , LN8  , LV8  );
  Recalc1(       CRC16_ICODE , LN9  , LV9  );
  Recalc1(     CRC16_MCRF4XX , LN10 , LV10 );
  Recalc1(         CRC16_USB , LN11 , LV11 );
  Recalc1(      CRC16_KERMIT , LN12 , LV12 );
  Recalc1(      CRC16_MODBUS , LN13 , LV13 );
  Recalc1(           CRC16_R , LN14 , LV14 );
  Recalc1(      CRC16_RIELLO , LN15 , LV15 );
  Recalc1(         CRC16_X25 , LN16 , LV16 );
  Recalc1(     CRC16_XKERMIT , LN17 , LV17 );
  Recalc1(      CRC16_ZMODEM , LN18 , LV18 );
  Recalc1(    CRC16_EN_13757 , LN19 , LV19 );
  Recalc1(       CRC16_MAXIM , LN20 , LV20 );
  Recalc1(     CRC16_T10_DIF , LN21 , LV21 );
  Recalc1(      CRC16_DDS110 , LN22 , LV22 );
  Recalc1(    CRC16_TELEDISK , LN23 , LV23 );
  Recalc1(    CRC16_CDMA2000 , LN24 , LV24 );
  Recalc1(       CRC16_DECTX , LN25 , LV25 );
  Recalc1(    CRC16_TMS37157 , LN26 , LV26 );
  Recalc1(           CRC16_A , LN27 , LV27 );
  Recalc1(         CRC16_CMS , LN28 , LV28 );
  Recalc1(     CRC16_GENIBUS , LN29 , LV29 );
  Recalc1(         CRC16_GSM , LN30 , LV30 );
  Recalc1(      CRC16_LJ1200 , LN31 , LV31 );
  Recalc1(    CRC16_PROFIBUS , LN32 , LV32 );
  Recalc1(CRC16_OPENSAFETY_A , LN33 , LV33 );
  Recalc1(CRC16_OPENSAFETY_B , LN34 , LV34 );

  RecalcSick(LN36 , LV36);
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
    for i:=1 to blen do buf[i-1] := byte(s[i]);
    Lab_InvHex.Visible := false;
    Lab_InvHex.Caption  := '';
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
