(*************************************************************************

 DESCRIPTION     :  GUI demo for CRC/HASH

 REQUIREMENTS    :  D2-D7/D9-D10/D12/D17-D18/D25S

 MEMORY USAGE    :  ---

 DISPLAY MODUS   :  ---

 REFERENCES      :  ---

 REMARK          :  For Delphi2 ignore/remove all unsupported properties

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     18.03.02  W.Ehrhardt  Initial version
 0.20     06.05.03  we          with hints, Info button, icon, version info
 0.30     13.09.03  we          with Adler32, CRC64
 0.50     03.11.03  we          Speedups (V0.5 as CCH)
 0.60     24.11.03  we          SHA384/512, TMemo -> TRichEdit
 0.61     24.11.03  we          INI file
 0.62     02.01.04  we          SHA224
 0.63     04.01.04  we          Base64 display format
 0.64     12.04.04  we          with mem_util.hexstr
 0.65     04.01.05  we          recompiled to fix SHA512/384 bug
 0.66     02.12.05  we          Hex Upcase checkbox
 0.67     11.12.05  we          Whirlpool
 0.68     22.01.06  we          New hash unit
 0.69     01.02.06  we          RIPEMD-160
 0.69a    12.02.06  we          Output sequence: RIPEMD-160 then SHA1
 0.70.0   28.02.06  we          try blocks for load/save ini
 0.71.0   14.03.06  we          New layout, print button, URL label
 0.71.1   15.03.06  we          Self test button, un/check all
 0.71.2   05.04.06  we          CRC24
 0.71.3   05.04.06  we          Process command line files on start
 0.71.4   22.01.07  we          New release with fixed Whirlpool unit
 0.71.5   10.02.07  we          Without filesize

 0.72.0   17.02.07  we          Stop button, status bar
 0.72.1   21.02.07  we          MD4, eDonkey
 0.72.2   21.02.07  we          Export as text
 0.72.3   21.02.07  we          blkcnt: helper count to display update
 0.72.4   23.02.07  we          eDonkey AND eMule
 0.72.5   30.09.07  we          Bug fix SHA512/384 for file sizes above 512MB
 0.72.6   15.11.07  we          Replaced string with ansistring

 0.73     21.07.09  we          D12 fixes
 0.74     11.03.12  we          SHA512/224, SHA512/256, new homepage
 0.75     11.08.15  we          SHA3-224 .. SHA3-512, D17+D18
 0.76     18.05.17  we          Blake2s changes
 0.77     07.19.17  we          Blake2b if HAS_INT64
 0.78     12.11.17  we          Blake2b for all
 **************************************************************************)

(*-------------------------------------------------------------------------
 (C) Copyright 2002-2017 Wolfgang Ehrhardt

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

unit chksum_u;

interface

{$i std.inc}

{$i-,j+}

uses
  {$ifndef UNIT_SCOPE}
    Windows, Messages, SysUtils, Classes, Forms, Dialogs, shellapi,
    StdCtrls, Buttons, ExtCtrls, ComCtrls, IniFiles, clipbrd, Controls;
  {$else}
    winapi.Windows, winapi.Messages, system.SysUtils, System.UITypes,
    system.Classes, vcl.Graphics, vcl.Controls, vcl.Forms, vcl.Dialogs,
    vcl.StdCtrls, vcl.Buttons, vcl.ExtCtrls,
    winapi.shellapi, vcl.ComCtrls, system.IniFiles, vcl.clipbrd;
  {$endif}
const
  Version  = '';
  XVersion = '0.78';
  HomePage = 'http://wolfgang-ehrhardt.de/';

type
  TCS_Main = class(TForm)
    OpenDialog1: TOpenDialog;
    Panel1: TPanel;
    SB_OpenFile: TSpeedButton;
    SB_Clear: TSpeedButton;
    SB_Info: TSpeedButton;
    CB_CRC16: TCheckBox;
    CB_CRC32: TCheckBox;
    CB_MD5: TCheckBox;
    CB_SHA1: TCheckBox;
    CB_SHA224: TCheckBox;
    CB_SHA256: TCheckBox;
    CB_Adler32: TCheckBox;
    CB_CRC64: TCheckBox;
    CB_SHA384: TCheckBox;
    CB_SHA512: TCheckBox;
    Memo1: TRichEdit;
    RG_Format: TRadioGroup;
    CB_Upcase: TCheckBox;
    CB_Whirl: TCheckBox;
    CB_RMD160: TCheckBox;
    Panel2: TPanel;
    SB_Print: TSpeedButton;
    SB_UncheckAll: TSpeedButton;
    PrintDialog: TPrintDialog;
    GCH_Label: TLabel;
    SB_Test: TSpeedButton;
    SB_CheckAll: TSpeedButton;
    CB_CRC24: TCheckBox;
    SB_Stop: TSpeedButton;
    StatusBar: TStatusBar;
    CB_ED2K: TCheckBox;
    CB_MD4: TCheckBox;
    SB_Export: TSpeedButton;
    SaveDialog1: TSaveDialog;
    CB_SHA5_224: TCheckBox;
    CB_SHA5_256: TCheckBox;
    CB_SHA3_224: TCheckBox;
    CB_SHA3_256: TCheckBox;
    CB_SHA3_384: TCheckBox;
    CB_SHA3_512: TCheckBox;
    CB_Blaks224: TCheckBox;
    CB_Blaks256: TCheckBox;
    CB_Blakb384: TCheckBox;
    CB_Blakb512: TCheckBox;

    procedure SB_OpenFileClick(Sender: TObject);
      {-Select and process files}
    procedure SB_ClearClick(Sender: TObject);
      {-Clear memo}
    procedure SB_InfoClick(Sender: TObject);
      {-Show info}
    procedure MLAppend(const s: ansistring);
      {-Append a line to file data result string}
    procedure LoadIni;
      {-read INI file}
    procedure SaveIni;
      {-write INI file}
    procedure FormShow(Sender: TObject);
      {-Load INI, set version label ...}
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
      {-Save INI on exit}
    procedure RG_FormatExit(Sender: TObject);
      {-Update Base64 flag}
    procedure SB_UncheckAllClick(Sender: TObject);
      {-Uncheck all algorithm check boxes}
    procedure SB_PrintClick(Sender: TObject);
      {-Print calculated check sums}
    procedure GCH_LabelClick(Sender: TObject);
      {-Browse WE home page}
    procedure SB_TestClick(Sender: TObject);
      {-Self test of all check sum algorithms}
    procedure SB_CheckAllClick(Sender: TObject);
      {-Check all algorithm check boxes}
    procedure SB_StopClick(Sender: TObject);
      {-Stop a running calculation}
    procedure SB_ExportClick(Sender: TObject);
      {-Export as text file}

  private
    buf: array[1..$F000] of byte;   {File read buffer}
    FData: string;                  {Check sums of a file as string}
    Base64: boolean;                {use base64}
    bailout: boolean;
    Hashing: boolean;
  public
    procedure ProcessFiles(const FName: string; var blkcnt: longint);
      {-Process one file}
    procedure SB_SetAll(value: boolean);
      {-Set all algorithm check boxes}
  end;

var
  CS_Main: TCS_Main;

implementation

uses
  Mem_util,
  CRC16, CRC24, CRC32, CRC64, ADLER32, ED2K, MD4,
  Hash, MD5, RMD160, SHA1, SHA224, SHA256,
  SHA384, SHA512, SHA5_224, SHA5_256, Whirl512,
  SHA3_224, SHA3_256, SHA3_384, SHA3_512,
  Blakb384, Blakb512,
  Blaks224, Blaks256;

{$R *.DFM}

{---------------------------------------------------------------------------}
function HexString(const x: array of byte): ansistring;
  {-HEX string from memory}
begin
  Result := HexStr(@x, sizeof(x));
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.MLAppend(const s: ansistring);
  {-Append a line to file data result string}
begin
  FData := FData+{$ifdef D12Plus} string {$endif}(s)+#13#10;
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.ProcessFiles(const FName: string; var blkcnt: longint);
  {-Process one file}
var
  n: integer;
  SHA1Context  : THashContext;  SHA1Digest   : TSHA1Digest;
  RMD160Context: THashContext;  RMD160Digest : TRMD160Digest;
  SHA224Context: THashContext;  SHA256Context: THashContext;
  SHA384Context: THashContext;  SHA512Context: THashContext;
  WhirlContext : THashContext;  SHA256Digest : TSHA256Digest;
  SHA224Digest : TSHA224Digest; SHA384Digest : TSHA384Digest;
  SHA512Digest : TSHA512Digest; WhirlDigest  : TWhirlDigest;
  MD5Context   : THashContext;  MD5Digest    : TMD5Digest;
  MD4Context   : THashContext;  MD4Digest    : TMD4Digest;
  ED2KContext  : TED2KContext;  ED2KResults  : TED2KResult;
  SHA5_224Context: THashContext;  SHA5_224Digest: TSHA5_224Digest;
  SHA5_256Context: THashContext;  SHA5_256Digest: TSHA5_256Digest;
  SHA3_224Context: THashContext;  SHA3_224Digest: TSHA3_224Digest;
  SHA3_256Context: THashContext;  SHA3_256Digest: TSHA3_256Digest;
  SHA3_384Context: THashContext;  SHA3_384Digest: TSHA3_384Digest;
  SHA3_512Context: THashContext;  SHA3_512Digest: TSHA3_512Digest;
  Blaks_224Context: THashContext;  Blaks_224Digest: TBlake2S_224Digest;
  Blaks_256Context: THashContext;  Blaks_256Digest: TBlake2S_256Digest;
  Blakb_384Context: THashContext;  Blakb_384Digest: TBlake2B_384Digest;
  Blakb_512Context: THashContext;  Blakb_512Digest: TBlake2B_512Digest;
  CRC16: word;
  CRC24: longint;  pgpsig: TPGPDigest;
  CRC32: longint;
  CRC64: TCRC64;
  Adler: longint;
  f: file;

  procedure Mwriteln(const s: ansistring);
    {-Writeln a line to richedit}
  begin
    MLAppend(s);
    MLAppend('');
    Memo1.Text := Memo1.Text+#10+{$ifdef D12Plus} string {$endif}(s);
  end;

  function RB(A: longint): longint;
    {-rotate byte of longint}
  begin
    RB := (A shr 24) or ((A shr 8) and $FF00) or ((A shl 8) and $FF0000) or (A shl 24);
  end;

begin
  StatusBar.SimpleText := Fname;
  MLAppend({$ifdef D12Plus} ansistring {$endif}(FName));
  filemode := 0;
  blkcnt := 0;
  if not FileExists(FName) then begin
    Mwriteln('*** file not found');
    exit;
  end;
  assignfile(f,FName);
  system.reset(f,1);
  if IOresult<>0 then begin
    Mwriteln('***  could not be opened');
    exit;
  end;
  SHA1Init(SHA1Context);
  RMD160Init(RMD160Context);
  SHA224Init(SHA224Context);
  SHA256Init(SHA256Context);
  SHA384Init(SHA384Context);
  SHA512Init(SHA512Context);
  Whirl_Init(WhirlContext);
  SHA5_224Init(SHA5_224Context);
  SHA5_256Init(SHA5_256Context);
  SHA3_224Init(SHA3_224Context);
  SHA3_256Init(SHA3_256Context);
  SHA3_384Init(SHA3_384Context);
  SHA3_512Init(SHA3_512Context);
  Blaks224Init(Blaks_224Context);
  Blaks256Init(Blaks_256Context);
  Blakb384Init(Blakb_384Context);
  Blakb512Init(Blakb_512Context);
  ED2K_Init(ED2KContext);
  MD4Init(MD4Context);
  MD5Init(MD5Context);
  Adler32Init(adler);
  CRC16Init(CRC16);
  CRC24Init(CRC24);
  CRC32Init(CRC32);
  CRC64Init(CRC64);
  repeat
    if bailout then exit;
    blockread(f,buf,sizeof(buf),n);
    if IOResult<>0 then begin
      Mwriteln('*** read error');
      break;
    end;
    if n<>0 then begin
      Application.ProcessMessages;
      inc(blkcnt);
      if CB_SHA1.Checked     then SHA1Update(SHA1Context,@buf,n);
      if CB_RMD160.Checked   then RMD160Update(RMD160Context,@buf,n);
      if CB_SHA224.Checked   then SHA224Update(SHA224Context,@buf,n);
      if CB_SHA256.Checked   then SHA256Update(SHA256Context,@buf,n);
      if CB_SHA384.Checked   then SHA384Update(SHA384Context,@buf,n);
      if CB_SHA512.Checked   then SHA512Update(SHA512Context,@buf,n);
      if CB_SHA5_224.Checked then SHA5_224Update(SHA5_224Context,@buf,n);
      if CB_SHA5_256.Checked then SHA5_256Update(SHA5_256Context,@buf,n);
      if CB_SHA3_224.Checked then SHA3_224Update(SHA3_224Context,@buf,n);
      if CB_SHA3_256.Checked then SHA3_256Update(SHA3_256Context,@buf,n);
      if CB_SHA3_384.Checked then SHA3_384Update(SHA3_384Context,@buf,n);
      if CB_SHA3_512.Checked then SHA3_512Update(SHA3_512Context,@buf,n);
      if CB_Blaks224.Checked then Blaks224Update(Blaks_224Context,@buf,n);
      if CB_Blaks256.Checked then Blaks256Update(Blaks_256Context,@buf,n);
      if CB_Blakb384.Checked then Blakb384Update(Blakb_384Context,@buf,n);
      if CB_Blakb512.Checked then Blakb512Update(Blakb_512Context,@buf,n);
      if CB_Whirl.Checked    then Whirl_Update(WhirlContext,@buf,n);
      if CB_ED2K.Checked     then ED2K_Update(ED2KContext,@buf,n);
      if CB_MD4.Checked      then MD4Update(MD4Context,@buf,n);
      if CB_MD5.Checked      then MD5Update(MD5Context,@buf,n);
      if CB_Adler32.Checked  then Adler32Update(adler,@buf,n);
      if CB_CRC16.Checked    then CRC16Update(CRC16,@buf,n);
      if CB_CRC24.Checked    then CRC24Update(CRC24,@buf,n);
      if CB_CRC32.Checked    then CRC32Update(CRC32,@buf,n);
      if CB_CRC64.Checked    then CRC64Update(CRC64,@buf,n);
    end;
  until n<>sizeof(buf);
  closefile(f);
  IOResult;
  SHA1Final(SHA1Context,SHA1Digest);
  RMD160Final(RMD160Context,RMD160Digest);
  SHA224Final(SHA224Context,SHA224Digest);
  SHA256Final(SHA256Context,SHA256Digest);
  SHA384Final(SHA384Context,SHA384Digest);
  SHA512Final(SHA512Context,SHA512Digest);
  SHA5_224Final(SHA5_224Context,SHA5_224Digest);
  SHA5_256Final(SHA5_256Context,SHA5_256Digest);
  SHA3_224Final(SHA3_224Context,SHA3_224Digest);
  SHA3_256Final(SHA3_256Context,SHA3_256Digest);
  SHA3_384Final(SHA3_384Context,SHA3_384Digest);
  SHA3_512Final(SHA3_512Context,SHA3_512Digest);
  Blaks224Final(Blaks_224Context,Blaks_224Digest);
  Blaks256Final(Blaks_256Context,Blaks_256Digest);
  Blakb384Final(Blakb_384Context,Blakb_384Digest);
  Blakb512Final(Blakb_512Context,Blakb_512Digest);
  Whirl_Final(WhirlContext,WhirlDigest);
  ED2K_Final(ED2KContext,ED2KResults);
  MD4Final(MD4Context,MD4Digest);
  MD5Final(MD5Context,MD5Digest);
  Adler32Final(adler);
  CRC16Final(CRC16);
  CRC24Final(CRC24); Long2PGP(CRC24, pgpsig);
  CRC32Final(CRC32);
  CRC64Final(CRC64);
  if Base64 then begin
    if CB_CRC16.Checked    then MLAppend('      CRC16: '+Base64Str(@CRC16       , sizeof(CRC16       )));
    if CB_CRC24.Checked    then MLAppend('      CRC24: '+Base64Str(@pgpsig      , sizeof(pgpsig      )));
    if CB_CRC32.Checked    then MLAppend('      CRC32: '+Base64Str(@CRC32       , sizeof(CRC32       )));
    if CB_Adler32.Checked  then MLAppend('    Adler32: '+Base64Str(@adler       , sizeof(adler       )));
    if CB_CRC64.Checked    then MLAppend('      CRC64: '+Base64Str(@CRC64       , sizeof(CRC64       )));
    if CB_ED2K.Checked then begin
                                MLAppend('    eDonkey: '+Base64Str(@ED2KResults.eDonkey, sizeof(ED2KResults.eDonkey)));
     if ED2KResults.differ then MLAppend('      eMule: '+Base64Str(@ED2KResults.eMule, sizeof(ED2KResults.eMule)));
    end;
    if CB_MD4.Checked      then MLAppend('        MD4: '+Base64Str(@MD4Digest   , sizeof(MD4Digest   )));
    if CB_MD5.Checked      then MLAppend('        MD5: '+Base64Str(@MD5Digest   , sizeof(MD5Digest   )));
    if CB_RMD160.Checked   then MLAppend('  RIPEMD160: '+Base64Str(@RMD160Digest, sizeof(RMD160Digest)));
    if CB_SHA1.Checked     then MLAppend('       SHA1: '+Base64Str(@SHA1Digest  , sizeof(SHA1Digest  )));
    if CB_SHA224.Checked   then MLAppend('     SHA224: '+Base64Str(@SHA224Digest, sizeof(SHA224Digest)));
    if CB_SHA256.Checked   then MLAppend('     SHA256: '+Base64Str(@SHA256Digest, sizeof(SHA256Digest)));
    if CB_SHA384.Checked   then MLAppend('     SHA384: '+Base64Str(@SHA384Digest, sizeof(SHA384Digest)));
    if CB_SHA512.Checked   then MLAppend('     SHA512: '+Base64Str(@SHA512Digest, sizeof(SHA512Digest)));
    if CB_SHA5_224.Checked then MLAppend(' SHA512/224: '+Base64Str(@SHA5_224Digest, sizeof(SHA5_224Digest)));
    if CB_SHA5_256.Checked then MLAppend(' SHA512/256: '+Base64Str(@SHA5_256Digest, sizeof(SHA5_256Digest)));
    if CB_Whirl.Checked    then MLAppend('  Whirlpool: '+Base64Str(@WhirlDigest, sizeof(WhirlDigest)));
    if CB_SHA3_224.Checked then MLAppend('   SHA3-224: '+Base64Str(@SHA3_224Digest, sizeof(SHA3_224Digest)));
    if CB_SHA3_256.Checked then MLAppend('   SHA3-256: '+Base64Str(@SHA3_256Digest, sizeof(SHA3_256Digest)));
    if CB_SHA3_384.Checked then MLAppend('   SHA3-384: '+Base64Str(@SHA3_384Digest, sizeof(SHA3_384Digest)));
    if CB_SHA3_512.Checked then MLAppend('   SHA3-512: '+Base64Str(@SHA3_512Digest, sizeof(SHA3_512Digest)));
    if CB_Blaks224.Checked then MLAppend('Blake2s-224: '+Base64Str(@Blaks_224Digest, sizeof(Blaks_224Digest)));
    if CB_Blaks256.Checked then MLAppend('Blake2s-256: '+Base64Str(@Blaks_256Digest, sizeof(Blaks_256Digest)));
    if CB_Blakb384.Checked then MLAppend('Blake2b-384: '+Base64Str(@Blakb_384Digest, sizeof(Blakb_384Digest)));
    if CB_Blakb512.Checked then MLAppend('Blake2b-512: '+Base64Str(@Blakb_512Digest, sizeof(Blakb_512Digest)));
  end
  else begin
    {swap bytes: display shall look like word / longint}
    {but HexStr constructs LSB first}
    HexUpper := CB_Upcase.checked;
    CRC16 := swap(CRC16);
    CRC32 := RB(CRC32);
    Adler := RB(Adler);
    if CB_CRC16.Checked    then MLAppend('      CRC16: '+HexStr(@CRC16,2));
    if CB_CRC24.Checked    then MLAppend('      CRC24: '+HexStr(@pgpsig,3));
    if CB_CRC32.Checked    then MLAppend('      CRC32: '+HexStr(@CRC32,4));
    if CB_Adler32.Checked  then MLAppend('    Adler32: '+HexStr(@adler,4));
    if CB_CRC64.Checked    then MLAppend('      CRC64: '+HexStr(@CRC64,8));
    if CB_ED2K.Checked then begin
                                MLAppend('    eDonkey: '+HexString(ED2KResults.eDonkey));
     if ED2KResults.differ then MLAppend('      eMule: '+HexString(ED2KResults.eMule));
    end;
    if CB_MD4.Checked      then MLAppend('        MD4: '+HexString(MD4Digest));
    if CB_MD5.Checked      then MLAppend('        MD5: '+HexString(MD5Digest));
    if CB_RMD160.Checked   then MLAppend('  RIPEMD160: '+HexString(RMD160Digest));
    if CB_SHA1.Checked     then MLAppend('       SHA1: '+HexString(SHA1Digest));
    if CB_SHA224.Checked   then MLAppend('     SHA224: '+HexString(SHA224Digest));
    if CB_SHA256.Checked   then MLAppend('     SHA256: '+HexString(SHA256Digest));
    if CB_SHA384.Checked   then MLAppend('     SHA384: '+HexString(SHA384Digest));
    if CB_SHA512.Checked   then MLAppend('     SHA512: '+HexString(SHA512Digest));
    if CB_SHA5_224.Checked then MLAppend(' SHA512/224: '+HexString(SHA5_224Digest));
    if CB_SHA5_256.Checked then MLAppend(' SHA512/256: '+HexString(SHA5_256Digest));
    if CB_Whirl.Checked    then MLAppend('  Whirlpool: '+HexString(WhirlDigest));
    if CB_SHA3_224.Checked then MLAppend('   SHA3-224: '+HexString(SHA3_224Digest));
    if CB_SHA3_256.Checked then MLAppend('   SHA3-256: '+HexString(SHA3_256Digest));
    if CB_SHA3_384.Checked then MLAppend('   SHA3-384: '+HexString(SHA3_384Digest));
    if CB_SHA3_512.Checked then MLAppend('   SHA3-512: '+HexString(SHA3_512Digest));
    if CB_Blaks224.Checked then MLAppend('Blake2s-224: '+HexString(Blaks_224Digest));
    if CB_Blaks256.Checked then MLAppend('Blake2s-256: '+HexString(Blaks_256Digest));
    if CB_Blakb384.Checked then MLAppend('Blake2b-384: '+HexString(Blakb_384Digest));
    if CB_Blakb512.Checked then MLAppend('Blake2b-512: '+HexString(Blakb_512Digest));
  end;
  MLAppend('');
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.SB_OpenFileClick(Sender: TObject);
  {-Select and process files}
var
  i: integer;
  blkcnt: longint;
begin
  if Hashing then begin
    bailout := true;
    exit;
  end;
  if Opendialog1.Execute then begin
    Hashing := true;
    bailout := false;
    SB_Openfile.Enabled := false;
    SB_Clear.Enabled := false;
    SB_Print.Enabled := false;
    SB_Test.Enabled := false;
    SB_Stop.Enabled := true;
    Screen.Cursor := crHourGlass;
    Application.ProcessMessages;
    Base64 := RG_Format.ItemIndex=1;
    Memo1.Lines.BeginUpdate;
    for i:=0 to Opendialog1.Files.Count-1 do begin
      FData := '';
      ProcessFiles(Opendialog1.Files[i],blkcnt);
      if bailout then break;
      {Add results for one file to display text}
      Memo1.Text := Memo1.Text + {$ifdef D12Plus} string {$endif}(FData);
      if (i and 15 = 0) or (blkcnt>7) then begin
        {Update display every 16th file or after a file with more than 500KB}
        memo1.Lines.EndUpdate;
//        Memo1.SetFocus;
//        Memo1.SelStart := length(memo1.text);
        memo1.Lines.BeginUpdate;
      end;
      Application.ProcessMessages;
    end;
    StatusBar.SimpleText := '';
    SB_Openfile.Enabled := true;
    SB_Clear.Enabled := true;
    SB_Print.Enabled := true;
    SB_Test.Enabled := true;
    SB_Stop.Enabled := false;
    Hashing := false;
    if bailout then begin
      Memo1.Text := Memo1.Text + {$ifdef D12Plus} string {$endif}(FData) + #13#10'** Stopped **'#13#10;
    end;
    memo1.Lines.EndUpdate;
    Screen.Cursor := crDefault;
    {caret to end of text}
    Memo1.SetFocus;
    Memo1.SelStart := length(memo1.text);
    Application.ProcessMessages;
  end;
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.SB_ClearClick(Sender: TObject);
  {-Clear memo}
begin
  Memo1.Clear;
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.SB_InfoClick(Sender: TObject);
  {-Show info}
begin
   MessageDlg( 'GCH Version '+XVersion+'  (c) 2002-2017  W.Ehrhardt'+#13+#10
              +'Open source freeware demo for Hash/CRC units'+#13+#10
              +HomePage+#13+#10+''+#13+#10
              +'To calculate hash und CRC check sums:'+#13+#10+''+#13+#10
              +'1. Select the display format: Hex (Upcase is optional) or Base64,'+#13+#10
              +'2. Check the items you want to calculate,'+#13+#10
              +'3. Press the calculator button, select the files to process, and press open. '+
                   'Check sums will be calculated and displayed in the memo area. '+
                   'Note that multiple files can be selected. '+
                   'Processed files are displayed in the status bar. '+
                   'Calculations can be aborted with the stop button.'+#13#10
              +'4. Check sums can be printed with the print button, '+
                   'saved to a text file with the export button, '+
                   'or selected/copied to the clipboard with standard Windows keys.',
              mtInformation, [mbOK], 0);
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.LoadIni;
  {-read INI file}
var
  IniFile : TInifile;
begin
  Inifile := TInifile.Create(ChangeFileExt(ParamStr(0), '.INI'));
  try
    CB_Adler32.Checked := IniFile.ReadBool('Options','Adler32'  , true);
    CB_CRC16.Checked   := IniFile.ReadBool('Options','CRC16'    , true);
    CB_CRC24.Checked   := IniFile.ReadBool('Options','CRC24'    , true);
    CB_CRC32.Checked   := IniFile.ReadBool('Options','CRC32'    , true);
    CB_CRC64.Checked   := IniFile.ReadBool('Options','CRC64'    , true);
    CB_ED2K.Checked    := IniFile.ReadBool('Options','eDonkey'  , true);
    CB_MD4.Checked     := IniFile.ReadBool('Options','MD4'      , true);
    CB_MD5.Checked     := IniFile.ReadBool('Options','MD5'      , true);
    CB_RMD160.Checked  := IniFile.ReadBool('Options','RIPEMD160', true);
    CB_SHA1.Checked    := IniFile.ReadBool('Options','SHA1'     , true);
    CB_SHA224.Checked  := IniFile.ReadBool('Options','SHA224'   , true);
    CB_SHA256.Checked  := IniFile.ReadBool('Options','SHA256'   , true);
    CB_SHA384.Checked  := IniFile.ReadBool('Options','SHA384'   , true);
    CB_SHA5_224.Checked:= IniFile.ReadBool('Options','SHA512/224', true);
    CB_SHA5_256.Checked:= IniFile.ReadBool('Options','SHA512/256', true);
    CB_SHA512.Checked  := IniFile.ReadBool('Options','SHA512'   , true);
    CB_Whirl.Checked   := IniFile.ReadBool('Options','Whirlpool', true);
    CB_SHA3_224.Checked:= IniFile.ReadBool('Options','SHA3-224', true);
    CB_SHA3_256.Checked:= IniFile.ReadBool('Options','SHA3-256', true);
    CB_SHA3_384.Checked:= IniFile.ReadBool('Options','SHA3-384', true);
    CB_SHA3_512.Checked:= IniFile.ReadBool('Options','SHA3-512', true);
    CB_Blaks224.Checked:= IniFile.ReadBool('Options','Blake2s-224', true);
    CB_Blaks256.Checked:= IniFile.ReadBool('Options','Blake2s-256', true);
    CB_Blakb384.Checked:= IniFile.ReadBool('Options','Blake2b-384', true);
    CB_Blakb512.Checked:= IniFile.ReadBool('Options','Blake2b-512', true);
    Base64             := IniFile.ReadBool('Options','Base64'   , false);
    CB_Upcase.Checked  := IniFile.ReadBool('Options','Upcase'   , false);
    RG_Format.ItemIndex := ord(Base64);
  finally
    IniFile.Free;
  end;
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.SaveIni;
  {-write INI file}
var
  IniFile : TInifile;
begin
  Inifile := TInifile.Create(ChangeFileExt(ParamStr(0), '.INI'));
  try
    try
      IniFile.EraseSection('Options');
      IniFile.WriteBool('Options','Adler32'  , CB_Adler32.Checked);
      IniFile.WriteBool('Options','CRC16'    , CB_CRC16.Checked  );
      IniFile.WriteBool('Options','CRC24'    , CB_CRC24.Checked  );
      IniFile.WriteBool('Options','CRC32'    , CB_CRC32.Checked  );
      IniFile.WriteBool('Options','CRC64'    , CB_CRC64.Checked  );
      IniFile.WriteBool('Options','eDonkey'  , CB_ED2K.Checked    );
      IniFile.WriteBool('Options','MD4'      , CB_MD4.Checked    );
      IniFile.WriteBool('Options','MD5'      , CB_MD5.Checked    );
      IniFile.WriteBool('Options','RIPEMD160', CB_RMD160.Checked );
      IniFile.WriteBool('Options','SHA1'     , CB_SHA1.Checked   );
      IniFile.WriteBool('Options','SHA224'   , CB_SHA224.Checked );
      IniFile.WriteBool('Options','SHA256'   , CB_SHA256.Checked );
      IniFile.WriteBool('Options','SHA384'   , CB_SHA384.Checked );
      IniFile.WriteBool('Options','SHA512'   , CB_SHA512.Checked );
      IniFile.WriteBool('Options','SHA512/224', CB_SHA5_224.Checked );
      IniFile.WriteBool('Options','SHA512/256', CB_SHA5_256.Checked );
      IniFile.WriteBool('Options','Blake2s-224', CB_Blaks224.Checked );
      IniFile.WriteBool('Options','Blake2s-256', CB_Blaks256.Checked );
      IniFile.WriteBool('Options','Blake2b-384', CB_Blakb384.Checked );
      IniFile.WriteBool('Options','Blake2b-512', CB_Blakb512.Checked );
      IniFile.WriteBool('Options','Whirlpool', CB_Whirl.Checked  );
      IniFile.WriteBool('Options','SHA3-224', CB_SHA3_224.Checked );
      IniFile.WriteBool('Options','SHA3-256', CB_SHA3_256.Checked );
      IniFile.WriteBool('Options','SHA3-384', CB_SHA3_384.Checked );
      IniFile.WriteBool('Options','SHA3-512', CB_SHA3_512.Checked );
      IniFile.WriteBool('Options','Upcase'   , CB_Upcase.Checked );
      IniFile.WriteBool('Options','Base64'   , Base64 );
     except
       MessageDlg('Cannot save to GCH.INI', mtError, [mbOK], 0);
     end;
  finally
    IniFile.Free;
  end;
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.FormShow(Sender: TObject);
  {-Load INI, set version label ...}
const
  first: boolean = true;
var
  i: integer;
  blkcnt: longint;
begin
  if first then begin
    GCH_Label.Caption := 'GCH';
    GCH_Label.Hint := HomePage;
    first := false;
    Hashing := false;
    bailout := false;
    LoadIni;
    {process command line files (no wild cards)}
    for i:=1 to ParamCount do begin
      if FileExists(Paramstr(i)) then ProcessFiles(Paramstr(i), blkcnt);
    end;
    Memo1.Text := {$ifdef D12Plus} string {$endif}(FData);
    Memo1.SetFocus;
    Memo1.SelStart := length(memo1.text);
    StatusBar.SimpleText := '';
  end;
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.FormClose(Sender: TObject; var Action: TCloseAction);
  {-Save INI on exit}
begin
  SaveIni;
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.RG_FormatExit(Sender: TObject);
  {-Update Base64 flag}
begin
  Base64 := RG_Format.ItemIndex=1;
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.SB_SetAll(value: boolean);
  {-Set all algorithm check boxes}
begin
  CB_Adler32.Checked := value;
  CB_CRC16.Checked   := value;
  CB_CRC24.Checked   := value;
  CB_CRC32.Checked   := value;
  CB_CRC64.Checked   := value;
  CB_ED2K.Checked    := value;
  CB_MD4.Checked     := value;
  CB_MD5.Checked     := value;
  CB_RMD160.Checked  := value;
  CB_SHA1.Checked    := value;
  CB_SHA224.Checked  := value;
  CB_SHA256.Checked  := value;
  CB_SHA384.Checked  := value;
  CB_SHA512.Checked  := value;
  CB_SHA5_224.Checked:= value;
  CB_SHA5_256.Checked:= value;
  CB_Whirl.Checked   := value;
  CB_SHA3_224.Checked:= value;
  CB_SHA3_256.Checked:= value;
  CB_SHA3_384.Checked:= value;
  CB_SHA3_512.Checked:= value;
  CB_Blaks224.Checked:= value;
  CB_Blaks256.Checked:= value;
  CB_Blakb384.Checked:= value;
  CB_Blakb512.Checked:= value;
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.SB_UncheckAllClick(Sender: TObject);
  {-Uncheck all algorithm check boxes}
begin
  SB_SetAll(false);
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.SB_CheckAllClick(Sender: TObject);
  {-Check all algorithm check boxes}
begin
  SB_SetAll(true);
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.SB_PrintClick(Sender: TObject);
  {-Print calculated check sums}
begin
  if PrintDialog.Execute then begin
    Application.ProcessMessages;
    Memo1.Print('GCH file checksums');
  end;
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.GCH_LabelClick(Sender: TObject);
  {-Browse WE home page}
begin
  ShellExecute(Application.Handle, nil, HomePage, '', '', SW_SHOWNORMAL);
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.SB_TestClick(Sender: TObject);
  {-Self test of all check sum algorithms}
  procedure report(const aname: ansistring; passed: boolean);
  const
    res: array[boolean] of ansistring = ('failed', 'passed');
  begin
    memo1.Lines.Append({$ifdef D12Plus} string {$endif}('Self test ' + aname + ' : '+res[passed]));
  end;
begin
  Memo1.Lines.Append('------------------------------');
  report('CRC16      ', CRC16SelfTest   );
  report('CRC24      ', CRC24SelfTest   );
  report('CRC32      ', CRC32SelfTest   );
  report('Adler32    ', Adler32SelfTest );
  report('CRC64      ', CRC64SelfTest   );
  report('eDonkey    ', ED2K_SelfTest   );
  report('MD4        ', MD4SelfTest     );
  report('MD5        ', MD5SelfTest     );
  report('RIPEMD160  ', RMD160SelfTest  );
  report('SHA1       ', SHA1SelfTest    );
  report('SHA224     ', SHA224SelfTest  );
  report('SHA256     ', SHA256SelfTest  );
  report('SHA384     ', SHA384SelfTest  );
  report('SHA512     ', SHA512SelfTest  );
  report('SHA512/224 ', SHA5_224SelfTest);
  report('SHA512/256 ', SHA5_256SelfTest);
  report('Whirlpool  ', Whirl_SelfTest  );
  report('SHA3-224   ', SHA3_224SelfTest);
  report('SHA3-256   ', SHA3_256SelfTest);
  report('SHA3-384   ', SHA3_384SelfTest);
  report('SHA3-512   ', SHA3_512SelfTest);
  report('Blake2s-224', Blaks224SelfTest);
  report('Blake2s-256', Blaks256SelfTest);
  report('Blake2b-384', Blakb384SelfTest);
  report('Blake2b-512', Blakb512SelfTest);
  Memo1.Lines.Append('------------------------------');
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.SB_StopClick(Sender: TObject);
  {-Stop a running calculation}
begin
  if Hashing then begin
    bailout := true;
    exit;
  end;
end;


{---------------------------------------------------------------------------}
procedure TCS_Main.SB_ExportClick(Sender: TObject);
  {-Export as text file}
begin
  if SaveDialog1.Execute then begin
     Memo1.Lines.SaveToFile(SaveDialog1.Filename);
  end;
end;

end.
