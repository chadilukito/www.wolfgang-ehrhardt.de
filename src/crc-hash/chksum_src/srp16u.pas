{***************************************************************

 DESCRIPTION     :  Search and display CRC-16 Rocksoft Parameters

 REQUIREMENTS    :  D3-D7/D9-D10/D12/D255

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  ---

 DISPLAY MODUS   :  Graphic

 REFERENCES      :  [1] Ross Williams' public domain C sources crcmodel.c, crcmodel.h
                        in "A Painless Guide to CRC Error Detection Algorithms"
                        http://www.ross.net/crc/download/crc_v3.txt
                    [2] Greg Cook's Catalogue of Parameterised CRC Algorithms
                        http://reveng.sourceforge.net/crc-catalogue/

 REMARK          :  - For Delphi2 ignore/remove all unsupported properties
                    - D25 tested with Tokyo Starter/Win32


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 1.00     21.08.08  W.Ehrhardt  Initial version
 1.01     21.08.08  we          Added ResMemo
 1.02     21.08.08  we          Reordered loops, bailout/running
 1.03     21.08.08  we          Fix logic for second data stet
 1.04     21.08.08  we          Stop button
 1.05     09.09.08  we          Clear/Load/Save buttons and actions
 1.06     10.09.08  we          Checkbox "List only verified"
 1.07     10.09.08  we          Test CRC1/CRC2 swap logic
 1.08     10.09.08  we          Check known algorithms
 1.09     12.09.08  we          Display checked data sets in memo
 1.10     25.04.09  we          Clear speed button
 1.11     11.09.09  we          Three data sets
 1.12     01.10.09  we          CRC-16/MAXIM, CRC-16/T10-DIF
 1.13     01.10.09  we          Swap 1/2 entries
 1.14     04.10.09  we          Full xorout loop if (polymin=polymax) and (initmin=initmax)
 1.15     10.10.09  we          Renamed to SRP16, info button, impoved initial directories logic
 1.16     11.10.09  we          Code clean up, D12 compatibility
 1.17     11.10.09  we          Bugfix "clear parameters": remove error color
 1.18     13.03.10  we          Added CRC16_DDS110, CRC16_TELEDISK to known algorithms
 1.20     03.01.14  we          CRC16_CDMA2000, CRC16_DECTX, CRC16_TMS37157
 1.21     17.05.17  we          8 more known algorithms
 ****************************************************************}

(*-------------------------------------------------------------------------
 (C) Copyright 2008-2017 Wolfgang Ehrhardt

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

unit srp16u;

interface

{$i std.inc}

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls, ComCtrls, Buttons,
  inifiles, mem_util, base2n, crc_sick, crcmodel, crcm_cat, ExtCtrls, Menus;

const
  TB_Version = 'SRP16 V1.21';

type
  TForm1 = class(TForm)
    Button_Start: TBitBtn;
    Button_Stop: TBitBtn;
    CB_Format1: TComboBox;
    CB_Format2: TComboBox;
    CB_Format3: TComboBox;
    CB_Poly: TComboBox;
    CB_Verified: TCheckBox;
    ECRC1: TEdit;
    ECRC2: TEdit;
    ECRC3: TEdit;
    ECStr1: TEdit;
    ECStr2: TEdit;
    ECStr3: TEdit;
    EInitMax: TEdit;
    EInitMin: TEdit;
    EPolyMax: TEdit;
    EPolyMin: TEdit;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Lab_Hdr: TLabel;
    Lab_maxinit: TLabel;
    Lab_maxpoly: TLabel;
    Lab_mininit: TLabel;
    Lab_minpoly: TLabel;
    OpenDialog1: TOpenDialog;
    Panel1: TPanel;
    PopupMenu1: TPopupMenu;
    ResMemo: TRichEdit;
    RE_Clear: TMenuItem;
    RE_Insert: TMenuItem;
    SaveDialog1: TSaveDialog;
    SB_CheckKnown: TSpeedButton;
    SB_Info: TSpeedButton;
    SB_Load: TSpeedButton;
    SB_New: TSpeedButton;
    SB_RemSpaces: TSpeedButton;
    SB_Save: TSpeedButton;
    SB_Swap: TSpeedButton;

    procedure FormCreate(Sender: TObject);
      {-One-time initialization}
    procedure ECStr1Change(Sender: TObject);
      {-(Re)calculate and display CRCs if input changed}
    procedure ECStr2Change(Sender: TObject);
      {-(Re)calculate and display CRCs if input changed}
    procedure ECStr3Change(Sender: TObject);
      {-(Re)calculate and display CRCs if input changed}
    procedure CB_Format1Change(Sender: TObject);
      {-(Re)calculate and display CRCs if input format changed}
    procedure CB_Format2Change(Sender: TObject);
      {-(Re)calculate and display CRCs if input format changed}
    procedure CB_Format3Change(Sender: TObject);
      {-(Re)calculate and display CRCs if input format changed}
    procedure Button_StartClick(Sender: TObject);
      {-Prepare data/parameters and start search loop}
    procedure Button_StopClick(Sender: TObject);
      {-Setup bailout and indicate search loop exit}
    procedure SB_NewClick(Sender: TObject);
      {-Clear search parameters/data}
    procedure SB_LoadClick(Sender: TObject);
      {-Load parameters from file}
    procedure SB_SaveClick(Sender: TObject);
      {-Save parameters to file}
    procedure SB_CheckKnownClick(Sender: TObject);
      {-Prepare data and check known algortithms}
    procedure RE_InsertClick(Sender: TObject);
      {-Insert data/CRC sets into text}
    procedure RE_ClearClick(Sender: TObject);
      {-Clear richedit result text}
    procedure SB_RemSpacesClick(Sender: TObject);
      {-Remove spaces from Hex data, add $ to Hex CRC}
    procedure CB_PolyChange(Sender: TObject);
      {-Fill min/max Poly from Poly combo box change}
    procedure SB_SwapClick(Sender: TObject);
      {-Swap sets 1 and 2}
    procedure SB_InfoClick(Sender: TObject);
      {-Show info}

  private
    { Private declarations }
    buf1,buf2,buf3: array[0..1023] of byte;
    blen1,blen2,blen3: word;
    initmin, initmax: word;
    polymin, polymax: word;
    tcrc1, tcrc1s: word;
    tcrc2, tcrc2s: word;
    tcrc3, tcrc3s: word;
    bailout, running: boolean;

  public
    { Public declarations }
    procedure Check1;
      {-Check input1, color warning if inv. Hex}
    procedure Check2;
      {-Check input2, color warning if inv. Hex}
    procedure Check3;
      {-Check input3, color warning if inv. Hex}
    procedure SearchPara;
      {-Main routine: search Rocksoft parameters for data/CRC sets}
    procedure LoadBSF(const FName: string);
      {-Load parameters from file}
    procedure SaveBSF(const FName: string);
      {-Save parameters to file}
    procedure Chk1Known(const para: TCRCParam);
      {-Check a single known algo given by TCRCParam}
    procedure CheckSick;
      {-Check CRC-16/Sick}
    procedure CheckAllKnown;
      {-Calculate and display CRCs for all crcm_cat 16 bit algorithms}
    procedure DisplayData;
     {-Insert data/CRC sets into text}
  end;

var
  Form1: TForm1;

implementation

{$R *.DFM}

var
  CRCPara: TCRCParam = (poly  : $0;
                        init  : $ffff;
                        xorout: $ffff;
                        check : $0;
                        width : 16;
                        refin : true;
                        refout: true;
                        name  : 'TEST');

{---------------------------------------------------------------------------}
function bool2str(b: boolean): string;
  {-boolean to 'true'/'false'}
begin
  if b then result:='true ' else result:='false';
end;


{---------------------------------------------------------------------------}
procedure TForm1.DisplayData;
  {-Insert data/CRC sets into text}
var
  l1,l2,l3: integer;
begin
  l1 := length(ECStr1.Text);
  l2 := length(ECStr2.Text);
  l3 := length(ECStr3.Text);
  if l1 or l2 or l3 > 0 then ResMemo.Lines.Append('Checked data sets');
  if l1>0 then ResMemo.Lines.Append('CRC1: '+ECRC1.Text+',   Data1: '+ECStr1.Text);
  if l2>0 then ResMemo.Lines.Append('CRC2: '+ECRC2.Text+',   Data2: '+ECStr2.Text);
  if l3>0 then ResMemo.Lines.Append('CRC3: '+ECRC3.Text+',   Data3: '+ECStr3.Text);
end;


{---------------------------------------------------------------------------}
procedure TForm1.Chk1Known(const para: TCRCParam);
  {-Check a single known algo given by TCRCParam}
var
  CRC1, CRC2, CRC3: longint;
  ctx: TCRC_ctx;
  s: string;
  found: boolean;
begin
  cm_Create(para,nil,ctx);
  cm_Full(ctx, CRC1, @buf1, blen1);
  found := false;
  if (CRC1=tcrc1) or (CRC1=tcrc1s) then begin
    ResMemo.Lines.Append('Found known algorithm: '+string(para.Name));
    s := 'CRC=$'+string(HexWord(CRC1))+
         '  Poly=$'+string(HexWord(para.poly))+
         '  init=$'+string(HexWord(para.init))+
         '  xorout=$'+string(HexWord(para.xorout))+
         '  refin='+bool2str(para.refin)+
         '  refout='+bool2str(para.refout);
    if (blen2>0) or (blen3>0) then begin
       cm_Full(ctx, CRC2, @buf2, blen2);
       cm_Full(ctx, CRC3, @buf3, blen3);
       if ((CRC1=tcrc1) and (CRC2=tcrc2)) or ((CRC1=tcrc1s) and (CRC2=tcrc2s)) then begin
         ResMemo.Lines.Append(s);
         ResMemo.Lines.Append(' *** Second data set verified');
         ResMemo.Update;
         found := true;
       end;
       if (blen3>0) and (((CRC1=tcrc1) and (CRC3=tcrc3)) or ((CRC1=tcrc1s) and (CRC3=tcrc3s))) then begin
         if not found then ResMemo.Lines.Append(s);
         found := true;
         ResMemo.Lines.Append(' *** Third  data set verified');
         ResMemo.Update;
       end;
       if (not CB_Verified.Checked) and (not found) then begin
         ResMemo.Lines.Append(s);
         ResMemo.Update;
       end;
    end
    else begin
      ResMemo.Lines.Append(s);
      ResMemo.Update;
    end;
    Application.ProcessMessages;
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.CheckSick;
  {-Check CRC-16/Sick}
var
  CRC1, CRC2, CRC3: word;
  s: string;
  found: boolean;
begin
  CRC_Sick_Full(CRC1, @buf1, blen1);
  found := false;
  if (CRC1=tcrc1) or (CRC1=tcrc1s) then begin
    s := 'Found known algorithm: CRC-16/Sick. CRC=$'+string(HexWord(CRC1));
    if (blen2>0) or (blen3>0) then begin
       CRC_Sick_Full(CRC2, @buf2, blen2);
       CRC_Sick_Full(CRC3, @buf3, blen3);
       if ((CRC1=tcrc1) and (CRC2=tcrc2)) or ((CRC1=tcrc1s) and (CRC2=tcrc2s)) then begin
         ResMemo.Lines.Append(s);
         ResMemo.Lines.Append(' *** Second data set verified');
         ResMemo.Update;
         found := true;
       end;
       if (blen3>0) and (((CRC1=tcrc1) and (CRC3=tcrc3)) or ((CRC1=tcrc1s) and (CRC3=tcrc3s))) then begin
         if not found then ResMemo.Lines.Append(s);
         found := true;
         ResMemo.Lines.Append(' *** Third  data set verified');
         ResMemo.Update;
       end;
       if (not CB_Verified.Checked) and (not found) then begin
         ResMemo.Lines.Append(s);
         ResMemo.Update;
       end;
    end
    else begin
      ResMemo.Lines.Append(s);
      ResMemo.Update;
    end;
    Application.ProcessMessages;
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.CheckAllKnown;
  {-Calculate and display CRCs for all crcm_cat 16 bit algorithms}
begin
  ResMemo.Lines.Append('===== Checking for known algorithms =====');
  DisplayData;
  Chk1Known(CRC16_ARC);
  Chk1Known(CRC16_ATOM);
  Chk1Known(CRC16_AUG2_CITT);
  Chk1Known(CRC16_AUG_CITT);
  Chk1Known(CRC16_BT_CHIP);
  Chk1Known(CRC16_BUYPASS);
  Chk1Known(CRC16_CITT);
  Chk1Known(CRC16_DNP);
  Chk1Known(CRC16_EN_13757);
  Chk1Known(CRC16_RIELLO);
  Chk1Known(CRC16_ICODE);
  Chk1Known(CRC16_KERMIT);
  Chk1Known(CRC16_MCRF4XX);
  Chk1Known(CRC16_MODBUS);
  Chk1Known(CRC16_R);
  Chk1Known(CRC16_USB);
  Chk1Known(CRC16_X25);
  Chk1Known(CRC16_XKERMIT);
  Chk1Known(CRC16_ZMODEM);
  Chk1Known(CRC16_MAXIM);
  Chk1Known(CRC16_T10_DIF);
  Chk1Known(CRC16_DDS110);
  Chk1Known(CRC16_TELEDISK);
  Chk1Known(CRC16_CDMA2000);
  Chk1Known(CRC16_DECTX);
  Chk1Known(CRC16_TMS37157);

  Chk1Known(CRC16_A);
  Chk1Known(CRC16_CMS);
  Chk1Known(CRC16_GENIBUS);
  Chk1Known(CRC16_GSM);
  Chk1Known(CRC16_LJ1200);
  Chk1Known(CRC16_OPENSAFETY_A);
  Chk1Known(CRC16_OPENSAFETY_B);
  Chk1Known(CRC16_PROFIBUS);

  CheckSick;
  ResMemo.Lines.Append('===== done =====');
  ResMemo.Lines.Append('');
  ResMemo.Update;
  ResMemo.SetFocus;
  ResMemo.SelStart := length(ResMemo.text);
end;


{---------------------------------------------------------------------------}
procedure TForm1.SearchPara;
  {-Main routine: search Rocksoft parameters for data/CRC sets}
var
  CRC1, CRC2, CRC3: longint;
  p: word;
  listall, found: boolean;
  ref, tinit, txout, txmax: word;
  s: string;
var
  ctx: TCRC_ctx;
begin
  ResMemo.Clear;
  ResMemo.Lines.Add('===== Result parameter sets =====');
  ResMemo.Update;
  listall := not CB_Verified.Checked;
  if (polymin=polymax) and (initmin=initmax) then txmax:=$FFFF else txmax:=1;
  //TestKnown;
  try
    for p:=polymin to polymax do begin
      CRCpara.poly := p;
      for tinit:=initmin to initmax do begin
        CRCpara.init := tinit;
        for ref:=0 to 3 do begin
          case ref of
            0: begin CRCpara.refin := false; CRCpara.refout := false; end;
            1: begin CRCpara.refin := true;  CRCpara.refout := true;  end;
            2: begin CRCpara.refin := false; CRCpara.refout := true;  end;
            3: begin CRCpara.refin := true;  CRCpara.refout := false; end;
          end;
          for txout:=0 to txmax do begin
            if bailout then exit;
            if txmax=1 then CRCpara.xorout := txout*$FFFF
            else CRCpara.xorout := txout;
            cm_Create(CRCPara,nil,ctx);
            cm_Full(ctx, CRC1, @buf1, blen1);
            found := false;
            if (CRC1=tcrc1) or (CRC1=tcrc1s) then begin
              s := 'CRC=$'+string(HexWord(CRC1))+
                   '  Poly=$'+string(HexWord(CRCpara.poly))+
                   '  init=$'+string(HexWord(CRCpara.init))+
                   '  xorout=$'+string(HexWord(CRCpara.xorout))+
                   '  refin='+bool2str(CRCpara.refin)+
                   '  refout='+bool2str(CRCpara.refout);
              if (blen2>0) or (blen3>0) then begin
                 cm_Full(ctx, CRC2, @buf2, blen2);
                 cm_Full(ctx, CRC3, @buf3, blen3);
                 if (blen2>0) and (((CRC1=tcrc1) and (CRC2=tcrc2)) or ((CRC1=tcrc1s) and (CRC2=tcrc2s))) then begin
                   found := true;
                   ResMemo.Lines.Append(s);
                   ResMemo.Lines.Append(' *** Second data set verified');
                   ResMemo.Update;
                 end;
                 if (blen3>0) and (((CRC1=tcrc1) and (CRC3=tcrc3)) or ((CRC1=tcrc1s) and (CRC3=tcrc3s))) then begin
                   if not found then ResMemo.Lines.Append(s);
                   found := true;
                   ResMemo.Lines.Append(' *** Third  data set verified');
                   ResMemo.Update;
                 end;
                 if listall and (not found) then begin
                   ResMemo.Lines.Append(s);
                   ResMemo.Update;
                 end;
              end
              else begin
                ResMemo.Lines.Append(s);
                ResMemo.Update;
              end;
              Application.ProcessMessages;
            end;
          end; {for txout}
        end; {for ref}
      end; {for tinit}
    end;  {for poly}
  finally
    ResMemo.Lines.Append('===== done =====');
    ResMemo.Lines.Append('');
    ResMemo.Update;
    ResMemo.SetFocus;
    ResMemo.SelStart := length(ResMemo.text);
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.Check1;
  {-Check input1, color warning if inv. Hex}
var
  s: string;
  i: integer;
  HOK: boolean;
begin
  s := ECStr1.Text;
  if length(s)>sizeof(buf1) then SetLength(s,sizeof(buf1));
  blen1 := length(s);
  if CB_Format1.Itemindex=1 then begin
    {string input, copy char to buf bytes}
    for i:=1 to blen1 do buf1[i-1] := byte(s[i]);
    ECstr1.Color := clWindow;
  end
  else begin
    {Hex input, first check for invalid chars}
    HOK := true;
    for i:=1 to blen1 do begin
      if pos(upcase(s[i]),'0123456789ABCDEF')=0 then begin
        HOK := false;
        break;
      end;
    end;
    if HOK then begin
      ECstr1.Color := clWindow;
    end
    else begin
      ECstr1.Color := clYellow;
    end;
    {Convert hex string to memory at buf, stops at first invalid}
    DecodeBase16AStr({$ifdef D12Plus} ansistring {$endif}(s), @buf1, sizeof(buf1),blen1);
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.Check2;
  {-Check input2, color warning if inv. Hex}
var
  s: string;
  i: integer;
  HOK: boolean;
begin
  s := ECStr2.Text;
  if length(s)>sizeof(buf2) then SetLength(s,sizeof(buf2));
  blen2 := length(s);
  if CB_Format2.Itemindex=1 then begin
    {string input, copy char to buf bytes}
    for i:=1 to blen2 do buf2[i-1] := byte(s[i]);
    ECstr2.Color := clWindow;
  end
  else begin
    {Hex input, first check for invalid chars}
    HOK := true;
    for i:=1 to blen2 do begin
      if pos(upcase(s[i]),'0123456789ABCDEF')=0 then begin
        HOK := false;
        break;
      end;
    end;
    if HOK then begin
      ECstr2.Color := clWindow;
    end
    else begin
      ECstr2.Color := clYellow;
    end;
    {Convert hex string to memory at buf, stops at first invalid}
    DecodeBase16AStr({$ifdef D12Plus} ansistring {$endif}(s), @buf2, sizeof(buf2),blen2);
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.Check3;
  {-Check input3, color warning if inv. Hex}
var
  s: string;
  i: integer;
  HOK: boolean;
begin
  s := ECStr3.Text;
  if length(s)>sizeof(buf3) then SetLength(s,sizeof(buf3));
  blen3 := length(s);
  if CB_Format3.Itemindex=1 then begin
    {string input, copy char to buf bytes}
    for i:=1 to blen3 do buf3[i-1] := byte(s[i]);
    ECstr3.Color := clWindow;
  end
  else begin
    {Hex input, first check for invalid chars}
    HOK := true;
    for i:=1 to blen3 do begin
      if pos(upcase(s[i]),'0123456789ABCDEF')=0 then begin
        HOK := false;
        break;
      end;
    end;
    if HOK then begin
      ECstr3.Color := clWindow;
    end
    else begin
      ECstr3.Color := clYellow;
    end;
    {Convert hex string to memory at buf, stops at first invalid}
    DecodeBase16AStr({$ifdef D12Plus} ansistring {$endif}(s), @buf3, sizeof(buf3),blen3);
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.LoadBSF(const FName: string);
  {-Load parameters from file}
var
  IniFile: TIniFile;
  i1,i2,i3: integer;
begin
  IniFile := TIniFile.Create(Fname);
  try
    ECRC1.Text  := IniFile.ReadString('SRP-Para','CRC1_Value','');
    ECRC2.Text  := IniFile.ReadString('SRP-Para','CRC2_Value','');
    ECRC3.Text  := IniFile.ReadString('SRP-Para','CRC3_Value','');
    ECStr1.Text := IniFile.ReadString('SRP-Para','CRC1_String','');
    ECStr2.Text := IniFile.ReadString('SRP-Para','CRC2_String','');
    ECStr3.Text := IniFile.ReadString('SRP-Para','CRC3_String','');
    i1 := IniFile.ReadInteger('SRP-Para','CRC1_Format',0);
    i2 := IniFile.ReadInteger('SRP-Para','CRC2_Format',0);
    i3 := IniFile.ReadInteger('SRP-Para','CRC3_Format',0);
    if i1 in [0,1] then  CB_Format1.Itemindex := i1;
    if i2 in [0,1] then  CB_Format2.Itemindex := i2;
    if i3 in [0,1] then  CB_Format3.Itemindex := i2;
    CB_Poly.Text  := IniFile.ReadString('SRP-Para','Poly','');
    EPolyMin.Text := IniFile.ReadString('SRP-Para','PolyMin','');
    EPolyMax.Text := IniFile.ReadString('SRP-Para','PolyMax','');
    EInitMin.Text := IniFile.ReadString('SRP-Para','InitMin','');
    EInitMax.Text := IniFile.ReadString('SRP-Para','InitMax','');
    Check1;
    Check2;
    Check3;
  finally
    IniFile.Free;
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.SaveBSF(const FName: string);
  {-Save parameters to file}
var
  IniFile: TIniFile;
begin
  IniFile := TIniFile.Create(Fname);
  try
    IniFile.EraseSection('SRP-Para');
    IniFile.WriteString ('SRP-Para','CRC1_Value',ECRC1.Text);
    IniFile.WriteString ('SRP-Para','CRC2_Value',ECRC2.Text);
    IniFile.WriteString ('SRP-Para','CRC3_Value',ECRC3.Text);
    IniFile.WriteInteger('SRP-Para','CRC1_Format',CB_Format1.Itemindex);
    IniFile.WriteInteger('SRP-Para','CRC2_Format',CB_Format2.Itemindex);
    IniFile.WriteInteger('SRP-Para','CRC3_Format',CB_Format3.Itemindex);
    IniFile.WriteString ('SRP-Para','CRC1_String',ECStr1.Text);
    IniFile.WriteString ('SRP-Para','CRC2_String',ECStr2.Text);
    IniFile.WriteString ('SRP-Para','CRC3_String',ECStr3.Text);
    IniFile.WriteString ('SRP-Para','Poly',   CB_Poly.Text);
    IniFile.WriteString ('SRP-Para','PolyMin',EPolyMin.Text);
    IniFile.WriteString ('SRP-Para','PolyMax',EPolyMax.Text);
    IniFile.WriteString ('SRP-Para','InitMin',EInitMin.Text);
    IniFile.WriteString ('SRP-Para','InitMax',EInitMax.Text);
  finally
    IniFile.Free;
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.FormCreate(Sender: TObject);
  {-One-time initialization}
begin
  CB_Format1.Itemindex := 0;
  CB_Format2.Itemindex := 0;
  CB_Format3.Itemindex := 0;
  CB_Poly.Itemindex := 0;
  Lab_Hdr.Caption := TB_Version + '  |  Search and display CRC16 Rocksoft parameters';
end;


{---------------------------------------------------------------------------}
procedure TForm1.ECStr1Change(Sender: TObject);
  {-(Re)calculate and display CRCs if input changed}
begin
  if ECStr1.Modified then Check1;
end;


{---------------------------------------------------------------------------}
procedure TForm1.ECStr2Change(Sender: TObject);
  {-(Re)calculate and display CRCs if input changed}
begin
  if ECStr2.Modified then Check2;
end;


{---------------------------------------------------------------------------}
procedure TForm1.ECStr3Change(Sender: TObject);
  {-(Re)calculate and display CRCs if input changed}
begin
  if ECStr3.Modified then Check3;
end;


{---------------------------------------------------------------------------}
procedure TForm1.CB_Format1Change(Sender: TObject);
  {-(Re)calculate and display CRCs if input format changed}
begin
  Check1;
end;


{---------------------------------------------------------------------------}
procedure TForm1.CB_Format2Change(Sender: TObject);
  {-(Re)calculate and display CRCs if input format changed}
begin
  Check2;
end;


{---------------------------------------------------------------------------}
procedure TForm1.CB_Format3Change(Sender: TObject);
  {-(Re)calculate and display CRCs if input format changed}
begin
  Check2;
end;


{---------------------------------------------------------------------------}
procedure TForm1.Button_StartClick(Sender: TObject);
  {-Prepare data/parameters and start search loop}
begin
  Check1;
  Check2;
  Check3;
  if blen1 > 0 then begin
    tcrc1  := StrToInt(ECRC1.Text);
    tcrc1s := swap(tcrc1);
    if blen2>0 then begin
      tcrc2  := StrToInt(ECRC2.Text);
      tcrc2s := swap(tcrc2);
    end;
    if blen3>0 then begin
      tcrc3  := StrToInt(ECRC3.Text);
      tcrc3s := swap(tcrc3);
    end;
    initmin := StrToIntDef(EInitMin.Text,0);
    initmax := StrToIntDef(EInitMax.Text,$FFFF);
    polymin := StrToIntDef(EPolyMin.Text,1);
    polymax := StrToIntDef(EPolyMax.Text,$FFFF);
    Button_Start.Enabled := false;
    Button_Stop.Enabled  := true;
    bailout := false;
    running := true;
    SearchPara;
    running := false;
    Button_Stop.Enabled  := false;
    Button_Start.Enabled := true;
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.Button_StopClick(Sender: TObject);
  {-Setup bailout and indicate search loop exit}
begin
  bailout  := true;
end;


{---------------------------------------------------------------------------}
procedure TForm1.SB_NewClick(Sender: TObject);
  {-Clear search parameters/data}
begin
  if MessageDlg('Clear parameters?', mtConfirmation, [mbYes, mbNo], 0)=mrYes then begin
    ECRC1.Text := '';
    ECRC2.Text := '';
    ECRC3.Text := '';
    ECStr1.Text := '';
    ECStr2.Text := '';
    ECStr3.Text := '';
    CB_Format1.Itemindex := 0;
    CB_Format2.Itemindex := 0;
    CB_Format3.Itemindex := 0;
    CB_Poly.Itemindex := 0;
    EPolyMin.Text := '';
    EPolyMax.Text := '';
    EInitMin.Text := '';
    EInitMax.Text := '';
    ECstr1.Color := clWindow;
    ECstr2.Color := clWindow;
    ECstr3.Color := clWindow;
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.SB_LoadClick(Sender: TObject);
  {-Load parameters from file}
begin
  if Opendialog1.InitialDir='' then Opendialog1.InitialDir := Savedialog1.InitialDir;
  if Opendialog1.InitialDir='' then Opendialog1.InitialDir := ExtractFilePath(Application.ExeName);
  if Opendialog1.Execute then begin
    LoadBSF(Opendialog1.Filename);
    Opendialog1.InitialDir := ExtractFilePath(Opendialog1.Filename);
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.SB_SaveClick(Sender: TObject);
  {-Save parameters to file}
begin
  if Savedialog1.InitialDir='' then Savedialog1.InitialDir := Opendialog1.InitialDir;
  if Savedialog1.InitialDir='' then Savedialog1.InitialDir := ExtractFilePath(Application.ExeName);
  if Savedialog1.Execute then begin
    SaveBSF(Savedialog1.Filename);
    Savedialog1.InitialDir := ExtractFilePath(Savedialog1.Filename);
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.SB_CheckKnownClick(Sender: TObject);
  {-Prepare data and check known algortithms}
begin
  Check1;
  Check2;
  Check3;
  if blen1 > 0 then begin
    tcrc1  := StrToInt(ECRC1.Text);
    tcrc1s := swap(tcrc1);
    if blen2>0 then begin
      tcrc2  := StrToInt(ECRC2.Text);
      tcrc2s := swap(tcrc2);
    end;
    if blen3>0 then begin
      tcrc3  := StrToInt(ECRC3.Text);
      tcrc3s := swap(tcrc3);
    end;
    CheckAllKnown;
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.RE_InsertClick(Sender: TObject);
  {-Insert data/CRC sets into text}
begin
  DisplayData;
end;


{---------------------------------------------------------------------------}
procedure TForm1.RE_ClearClick(Sender: TObject);
  {-Clear richedit result text}
begin
  ResMemo.Clear;
end;


{---------------------------------------------------------------------------}
procedure TForm1.SB_RemSpacesClick(Sender: TObject);
  {-Remove spaces from Hex data, add $ to Hex CRC}
var
  s: string;
  i: integer;
begin
  {Remove spaces if HEX format}
  if CB_Format1.Itemindex=0 then begin
    s := ECStr1.Text;
    i := pos(' ',s);
    while i>0 do begin
      delete(s,i,1);
      i := pos(' ',s);
    end;
    ECStr1.Text := s;
  end;
  {Remove spaces if HEX format}
  if CB_Format2.Itemindex=0 then begin
    s := ECStr2.Text;
    i := pos(' ',s);
    while i>0 do begin
      delete(s,i,1);
      i := pos(' ',s);
    end;
    ECStr2.Text := s;
  end;
  {Remove spaces if HEX format}
  if CB_Format3.Itemindex=0 then begin
    s := ECStr3.Text;
    i := pos(' ',s);
    while i>0 do begin
      delete(s,i,1);
      i := pos(' ',s);
    end;
    ECStr3.Text := s;
  end;

  Check1;
  Check2;
  Check3;

  {Insert $ if CRC contains HEX char}
  s := ECRC1.text;
  i := pos(' ',s);
  while i>0 do begin
    delete(s,i,1);
    i := pos(' ',s);
  end;
  if (s<>'') and (s[1]<>'$') then begin
    for i:=1 to length(s) do begin
      if pos(upcase(s[i]),'ABCDEF')>0 then begin
         s := '$'+s;
         ECRC1.text := s;
         break;
      end;
    end;
  end;

  {Insert $ if CRC contains HEX char}
  s := ECRC2.text;
  i := pos(' ',s);
  while i>0 do begin
    delete(s,i,1);
    i := pos(' ',s);
  end;
  if (s<>'') and (s[1]<>'$') then begin
    for i:=1 to length(s) do begin
      if pos(upcase(s[i]),'ABCDEF')>0 then begin
         s := '$'+s;
         ECRC2.text := s;
         break;
      end;
    end;
  end;

  {Insert $ if CRC contains HEX char}
  s := ECRC3.text;
  i := pos(' ',s);
  while i>0 do begin
    delete(s,i,1);
    i := pos(' ',s);
  end;
  if (s<>'') and (s[1]<>'$') then begin
    for i:=1 to length(s) do begin
      if pos(upcase(s[i]),'ABCDEF')>0 then begin
         s := '$'+s;
         ECRC3.text := s;
         break;
      end;
    end;
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.CB_PolyChange(Sender: TObject);
  {-Fill min/max Poly from Poly combo box change}
begin
  EPolyMin.Text := CB_Poly.Text;
  EPolyMax.Text := CB_Poly.Text;
end;


{---------------------------------------------------------------------------}
procedure TForm1.SB_SwapClick(Sender: TObject);
  {-Swap sets 1 and 2}
var
  t: string;
  i : integer;
begin
  if (ECRC2.Text<>'') and (ECStr2.Text<>'') then begin
    t := ECRC2.Text;
    ECRC2.Text := ECRC1.Text;
    ECRC1.Text := t;
    t := ECStr2.Text;
    ECStr2.Text := ECStr1.Text;
    ECStr1.Text := t;
    i := CB_Format2.Itemindex;
    CB_Format2.Itemindex :=  CB_Format1.Itemindex;
    CB_Format1.Itemindex := i;
    Check1;
    Check2;
  end;
end;


{---------------------------------------------------------------------------}
procedure TForm1.SB_InfoClick(Sender: TObject);
  {-Show info}
begin
   MessageDlg( TB_Version+'  (c) 2008-2017 W.Ehrhardt'+#13+#10
              +'Open source freeware demo for searching CRC16 Rocksoft parameters'+#13+#10
              +''+#13+#10
              +'Search and display logic:'+#13+#10
              +''+#13+#10
              +'1.  Enter up to three CRC/Data pairs'+#13+#10
              +'2a. If you know the poly, enter it into Min.poly and Max.poly'+#13+#10
              +'2b. If you know the init value, enter it into Min.init and Max.init'+#13+#10
              +'2c. If only verified parameters shall be listed, check "List if double match"'+#13+#10
              +'3.  Click Search! button'+#13+#10
              +''+#13+#10
              +'SRP16 searches the ranges Min.poly .. Max.poly and Min.init .. Max.init, with all'+#13+#10
              +'additional combinations of refin/refout and xorout=$0000/$FFFF and swapped'+#13+#10
              +'CRC bytes. Normally one of the Poly or Init range is set to just one fixed value;'+#13+#10
              +'if Min.poly=Max.poly and Min.init=Max.init, a special xorout search routine is used.'+#13+#10
              +''+#13+#10
              +'This software is provided "as-is", without any express or implied'+#13+#10
              +'warranty. In no event will the authors be held liable for any'+#13+#10
              +'damages arising from the use of this software.',
              mtInformation, [mbOK], 0);
end;

end.
