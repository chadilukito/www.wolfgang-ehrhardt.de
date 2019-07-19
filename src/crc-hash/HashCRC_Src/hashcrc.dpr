{$B-,D-,H-,I-,J+,P-,Q-,R-,S-,T-,V+,W-,X+}

{***************************************************************
 *
 * DLL Name : HashCRC
 * Purpose  : FAR manager plugin DLL for CRC/Hash
 * Author   : W.Ehrhardt
 * Compiler : Delphi 2-7/9-10, VP 2.1, FPC 2.0/2.2
 *            (fpc -Sd -O2 -dRelease hashcrc.dpr)
 * History  :
 * 17.03.02  1.0      Initial version
 * 21.09.02  1.1      Percent display via GetFilesize (for files > 2 GB)
 * 22.03.03  1.2      Two lines for SHA256, cancel with, VP compatible
 * 30.04.03  1.3      English lng file, new Delphi CheckEsc
 * 13.09.03  1.4      Adler32 and CRC64
 * 03.11.03  1.5      Speedup with new CRC/Hash basic routines (about 25%)
 * 23.12.03  1.6      SHA384/SHA512, English comments
 * 03.01.04  1.6.1    SHA224
 * 12.04.04  1.7      Base64, UpperCase, Adler32 shown as MSB Hex
 * 12.04.04  1.7.x1   Delphi 4 + compatible
 * 13.04.04  1.7.x2   Bugfix reading BUpcase from registry
 * 13.04.04  1.7.x3   Strict LSB HEX option, XL routines
 * 13.04.04  1.7.x4   L/M indicator
 * 14.04.04  1.7.x5   Test MinFarVersion 1.70 Beta 3 (1,70,591)
 * 13.01.05  1.8.x0   [File] and [Clipboard] button
 * 29.01.05  1.8.x1   Ask for overwrite
 * 29.01.05  1.8.x2   'Too many items' if Version < 1.70.1282 = Beta 4
 * 30.01.05  1.8.x3   InvVers variable, minimize crash danger with old FAR versions
 * 30.01.05  1.8.x4   AdvControl(..., ACTL_GETFARVERSION, @FARVers)
 * 30.01.05  1.8.     Counts=0 in GetPluginInfo if InvVers
 * 04.09.05  1.9.x0   Process PanelInfo.SelectedItems^ if more than one
 * 04.09.05  1.9.x1   Overwrite confirmation, lng entries for "Enter file name ..."
 * 05.09.05  1.9.x2   Get config options from registry early in OpenPlugin
 *                    Strict LSB hint in result file
 * 05.09.05  1.9.x3   Initialize/finalize only checked Hash/CRC functions
 * 06.09.05  1.9.x4   Config: List errors
 * 21.09.05  1.9.x5   "IO Error" message rewrite/close result file
 * 14.12.05  1.10.x0  GetMaxY, MaxSI
 * 15.12.05  1.10.x1  Whirlpool
 * 17.12.05  1.10.x2  Bugfix off-by-1 error config format
 * 01.02.06  1.11.x0  RIPEMD-160

 * 02.04.06  1.12.x0  CRC24 without config
 * 03.04.06  1.12.x1  CRC24 with config, MaxSIM, MaxMCnt
 * 03.04.06  1.12.x2  InitArr/TInitDialogItem
 * 04.04.06  1.12.x3  CRC24 Base64: always PGP MSB format, Hex: use Strict LSB HEX option
 * 04.04.06  1.12.x4  LSB hint in list file for CRC24 with Strict LSB HEX option
 * 11.04.06  1.12.x5  Use RB() function

 * 17.04.06  1.13.x0  Double check with ExistFile, ProcessFile: close file only if opened
 * 13.05.06  1.13.x1  Rewrite Process loop with calls to function/procedures
 * 13.05.06  1.13.x2  PE processing, Bugfix: Check IOResult after reading pesig
 * 13.05.06  1.13.x3  BPEMD5E, MPEMD5
 * 13.05.06  1.13.x4  Bugfix: Update all checked Hash/CRC not only MD5
 * 14.05.06  1.13.x5  AnyHC; force configuration if no CRC or Hash checked
 * 14.05.06  1.13.x6  MD5-Image, MD5-File, PE-MD5 in config
 * 15.05.06  1.13.x7  Option: Expand file name
 * 16.05.06  1.13.x8  Config: Disable Expand FN for 1.70 Beta 3
 * 21.05.06  1.13.x9  Typecast integer($FFFFFFFF) in ExistFile
 * 21.05.06  1.13.x10 Fixed values of MaxSIM and MaxMCnt
 * 23.05.06  1.13.x11 512 byte ExpFN, check length of expanded file name

 * 21.01.07  1.14     Bug fix Whirlpool for files sizes above 512MB

 * 11.02.07  1.15     Fix for Delphi eof bug with files > 4GB

 * 20.02.07  1.16.x0  MD4/eDonkey
 * 20.02.07  1.16.x1  FPC 2 compatibility
 * 20.02.07  1.16.x2  New config dialog layout
 * 23.02.07  1.16.x3  eDonkey AND eMule
 * 04.03.07  1.16.x4  eMule=MD4 for zero length files

 * 01.10.07  1.17     Bug fix SHA512/384 for files sizes above 512MB

 ****************************************************************}

(*-------------------------------------------------------------------------
 (C) Copyright 2002-2007 Wolfgang Ehrhardt

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

{$i STD.INC}

{$ifndef VirtualPascal}
  {$MINENUMSIZE 4}
{$else}
  {&Delphi+,AlignData+,AlignRec+,StdCall+,Use32-}
{$endif}

{$ifdef D4Plus}
  {$define D4Plus_OR_FPC}
{$endif}
{$ifdef FPC}
  {$define D4Plus_OR_FPC}
{$endif}

{.$define DEBUG}

library hashcrc;

uses windows,
  {$ifdef VirtualPascal}
    strings, crt,
  {$endif}
  PE_Def,
  MD4 in 'md4.pas',
  ED2K in 'ed2k.pas',
  MD5 in 'md5.pas',
  RMD160 in 'Rmd160.pas',
  SHA1 in 'Sha1.pas',
  CRC16 in 'CRC16.pas',
  CRC24 in 'crc24.pas',
  CRC32 in 'crc32.pas',
  CRC64 in 'crc64.pas',
  Adler32 in 'adler32.pas',
  SHA224 in 'Sha224.pas',
  SHA256 in 'Sha256.pas',
  SHA384 in 'Sha384.pas',
  SHA512 in 'Sha512.pas',
  plugin in 'plugin.pas',
  mem_util in 'mem_util.pas',
  Whirl512 in 'whirl512.pas',
  Hash in 'hash.pas';

{$R *.RES}

const
  BCRC16 : BOOL = true;
  BCRC24 : BOOL = false;
  BCRC32 : BOOL = true;
  BCRC64 : BOOL = false;
  BAdler : BOOL = false;
  BMD4   : BOOL = false;
  BED2K  : BOOL = false;
  BMD5   : BOOL = true;
  BRMD160: BOOL = false;
  BSHA1  : BOOL = true;
  BSHA224: BOOL = false;
  BSHA256: BOOL = true;
  BSHA384: BOOL = false;
  BSHA512: BOOL = true;
  BWhirl : BOOL = false;
  BLSBHEX: BOOL = false;    {Strict LSB HEX display}
  BBase64: BOOL = false;    {Base64 output}
  BUpCase: BOOL = true;     {Hex uppercase}
  BLstErr: BOOL = false;    {List errors in Multi file mode}
  BPEMD5:  BOOL = true;     {Special PE file processing for MD5}
  BExpNam: BOOL = false;    {Show expanded filename}

const
  Warn13 : boolean = true;
  InvVers: boolean = false;
  AnyHC:   boolean = true;

const
  MCRC16  = 1 shl 0;
  MCRC32  = 1 shl 1;
  MMD5    = 1 shl 2;
  MSHA1   = 1 shl 3;
  MSHA256 = 1 shl 4;
  MCRC64  = 1 shl 5;
  MAdler  = 1 shl 6;
  MSHA384 = 1 shl 7;
  MSHA512 = 1 shl 8;
  MSHA224 = 1 shl 9;
  MWhirl  = 1 shl 10;
  MRMD160 = 1 shl 11;
  MCRC24  = 1 shl 12;
  MMD4    = 1 shl 13;
  MED2K   = 1 shl 14;

  MAnyHC  = (1 shl 15)-1;   //Test mask for any Hash/CRC

  MExpNam = 1 shl 26;       //Show expanded fillname
  MPEMD5  = 1 shl 27;
  MLSBHEX = 1 shl 28;
  MUpcase = 1 shl 29;
  MBase64 = 1 shl 30;
  MLstErr = 1 shl 31;

  DefMask = MCRC16 or MCRC32 or MMD5 or MSHA1 or MSHA256 or MSHA512 or MCRC64 or MUpcase;

const
  PluginKey = '\HASHCRC';
  BufMax    = $F000;
  FARVers   : DWord = 0;

var
  FARAPI : TPluginStartupInfo;
  StdFun : TFarStandardFunctions;
  buf    : array[0..BufMax-1] of char;
  smd5fil: string[9];
  smd5img: string[9];

var
  PluginMenuStrings  : array[0..0] of PChar;
  PluginConfigStrings: array[0..0] of PChar;

type
  TMsg = (_MenuString,
          _Titel,
          _Percent_Done,
          _MB_done,
          _Calc_in_Progress,
          _Invalid_Input,
          _HashCRC_config,
          _OK,
          _Cancel,
          _Ask_CancelCalc,
          _Calculation_cancelled,
          _HexUppercase,
          _StrictLSB,
          _Btn_OK,
          _Btn_ClipBoard,
          _Btn_File,
          _File_done,
          _File_error,
          _Clipboard_done,
          _Clipboard_error,
          _Ask_Overwrite,
          _Too_many_items,
          _Enter_file_name,
          _Filename_for_list_of_Hash_CRC_results,
          _List_Errors,
          _MD5_File,
          _MD5_Image,
          _MD5_PE,
          _Expand_FName
          );

  TDiaStr = string[128];


{---------------------------------------------------------------------------}
function GetMsg(MsgId: TMsg): PChar;
  {-Get message fom lng file as PChar}
begin
  result:= FARAPI.GetMsg(FARAPI.ModuleNumber, integer(MsgId));
end;


{---------------------------------------------------------------------------}
function GetPMsg(MsgId: TMsg): string;
  {-Get message fom lng file as string}
begin
  {$ifdef VirtualPascal}
    result:= StrPas(FARAPI.GetMsg(FARAPI.ModuleNumber, integer(MsgId)));
  {$else}
    result:= FARAPI.GetMsg(FARAPI.ModuleNumber, integer(MsgId));
  {$endif}
end;


{---------------------------------------------------------------------------}
procedure ShowMessage(m: pchar; warn: boolean);
  {-Show info message, if warn use FMSG_WARNING}
var
  Msg: array[0..2] of pchar;
  FScreen: THandle;
  Flags: DWORD;
begin
  Msg[0] := GetMsg(_Titel);
  Msg[1] := m;
  Msg[2] := #01#00;
  Flags := FMSG_MB_OK;
  if warn then Flags := Flags or FMSG_WARNING;
  FScreen:= FarAPI.SaveScreen(0,0,-1,-1);
  FARAPI.Message(FARAPI.ModuleNumber, Flags, nil, @Msg,3, 0);
  FARAPI.RestoreScreen(FScreen);
end;


{$ifdef DEBUG}
{---------------------------------------------------------------------------}
procedure DebugMessage(m: pchar);
  {-Show debug message}
begin
  ShowMessage(m, false);
end;
{$endif}


{---------------------------------------------------------------------------}
procedure SetRegKey(sKey: PChar; Value: DWORD);
  {-Write value into registry}
var
  rb: shortstring;
  Key: HKEY;
  dwDisposition: DWORD;
begin
  {$ifdef VirtualPascal}
    rb := StrPas(FARAPI.Rootkey) + PluginKey + #0;
  {$else}
    rb := FARAPI.Rootkey;
    rb := rb + PluginKey + #0;
  {$endif}
  RegCreateKeyEx(HKEY_CURRENT_USER,
                 @rb[1],
                 0,nil,
                 REG_OPTION_NON_VOLATILE,
                 KEY_ALL_ACCESS,
                 nil,key,
                 @dwDisposition);
  RegSetValueEx(Key,sKey,0,REG_DWORD,@Value,4);
  RegCloseKey(Key);
end;


{---------------------------------------------------------------------------}
function GetRegKey(sKey: PChar; DefaultValue: DWORD): DWORD;
  {-Read value from registry}
var
  Key: HKEY;
  dwDisposition,res,dwType,dwSize: DWORD;
  rb: shortstring;
begin
  {$ifdef VirtualPascal}
    rb := StrPas(FARAPI.Rootkey) + PluginKey + #0;
  {$else}
    rb := FARAPI.Rootkey;
    rb := rb + PluginKey + #0;
  {$endif}
  res:=RegCreateKeyEx(HKEY_CURRENT_USER,
                      @rb[1],
                      0,nil,
                      REG_OPTION_NON_VOLATILE,
                      KEY_READ,
                      nil,key,
                      @dwDisposition);
  if res=ERROR_SUCCESS then begin
    dwSize:=4;
    res:=RegQueryValueEx(Key,sKey,nil,@dwType,@result,@dwSize);
    if res<>ERROR_SUCCESS then result:=DefaultValue;
  end;
  RegCloseKey(Key);
end;


{---------------------------------------------------------------------------}
procedure SetStartupInfo(var psi: TPluginStartupInfo); stdcall; export;
  {-Save API startup info, initialize Warn13}
const
  VMin = $0146;
  BMin = 1282;
var
  Vers, Build: word;
{
  Experimental results for ACTL_GETFARVERSION
  FAR   Vers Build
  1701: 0146 0001
  1702: 0146 0141
  1703: 0146 024F
  1704: 0146 0502
  1705: 0146 0662
}
begin
  {Dont overflow structure}
  if psi.StructSize<sizeof(FARAPI) then begin
    move(psi, FARAPI, psi.StructSize);
    InvVers := true;
    exit;
  end;
  FARAPI := psi;
  StdFun := FARAPI.FSF^;
  {Get FARVers via @ for < 1703, nil results in access violation}
  FARAPI.AdvControl(FARAPI.ModuleNumber, ACTL_GETFARVERSION, @FARVers);
  Build := FARVers shr 16;
  Vers  := FARVers and $FFFF;
  if (Vers<VMin) or ((Vers=VMin) and (Build<$024F)) then begin
    InvVers := true;
    exit;
  end;
  Warn13 := (Vers=VMin) and (Build<BMin);  {Warning for 1703}
end;


{---------------------------------------------------------------------------}
procedure GetRegFlags;
  {-Get Flags from registry and calculate boolean variables}
var
  Mask: DWord;
begin
  Mask := GetRegKey('Flags', DefMask);
  BCRC16  := Mask and MCRC16 <>0;
  BCRC24  := Mask and MCRC24 <>0;
  BCRC32  := Mask and MCRC32 <>0;
  BCRC64  := Mask and MCRC64 <>0;
  BAdler  := Mask and MAdler <>0;
  BMD5    := Mask and MMD5   <>0;
  BMD4    := Mask and MMD4   <>0;
  BED2K   := Mask and MED2K  <>0;
  BRMD160 := Mask and MRMD160<>0;
  BSHA1   := Mask and MSHA1  <>0;
  BSHA224 := Mask and MSHA224<>0;
  BSHA256 := Mask and MSHA256<>0;
  BSHA384 := Mask and MSHA384<>0;
  BSHA512 := Mask and MSHA512<>0;
  BWhirl  := Mask and MWhirl <>0;
  BLSBHEX := Mask and MLSBHEX<>0;
  BBase64 := Mask and MBase64<>0;
  BUpcase := Mask and MUpcase<>0;
  BLstErr := Mask and MLstErr<>0;
  BPEMD5  := Mask and MPEMD5 <>0;
  BExpNam := Mask and MExpNam<>0;
  AnyHC   := Mask and MAnyHC <>0;
end;


{---------------------------------------------------------------------------}
procedure GetPluginInfo(var pi: TPluginInfo); stdcall; export;
  {-Menu lines in FAR's Plugin/ConfigPlugin menu}
begin
  pi.StructSize:= sizeof(pi);
  pi.Flags:= 0;
  PluginMenuStrings[0]   := GetMsg(_MenuString);
  PluginConfigStrings[0] := GetMsg(_MenuString);
  pi.PluginMenuStrings   := @PluginMenuStrings;
  pi.PluginConfigStrings := @PluginConfigStrings;
  if InvVers then begin
    {Don't show menu lines for unsupported versions}
    pi.PluginMenuStringsNumber:= 0;
    pi.PluginConfigStringsNumber:= 0;
  end
  else begin
    pi.PluginMenuStringsNumber:= 1;
    pi.PluginConfigStringsNumber:= 1;
  end;
end;


{---------------------------------------------------------------------------}
function MovePchar(var data: array of char; p: PChar): integer;
  {-Copy PChar to data, result := length}
var
  i: integer;
begin
  result:=-1;
  for i:=low(data) to high(data) do begin
    data[i] := p[i];
    inc(result);
    if p[i]=#0 then exit;
  end;
end;

{---------------------------------------------------------------------------}
function Configure(ItemNumber: integer): integer; stdcall; export;
  {-Display configuration dialog}
var
  i,l,Mask: integer;
const
  itemsnum=26;
//  YE=itemsnum;
  XL=5;
  XR=20;
  {Use array of TInitDialogItem, this reduces static memory/file size (>10KB)}
  InitArr: packed array [0..itemsnum-1] of TInitDialogItem = (
    { 0} (ItemType:integer(DI_DoubleBOX); X1: 3; Y1: 1; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'(config)'),

    { 1} (ItemType:integer(DI_CHECKBOX);  X1:XL; Y1: 2; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'CRC16'),
    { 2} (ItemType:integer(DI_CHECKBOX);  X1:XL; Y1: 3; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'CRC24'),
    { 3} (ItemType:integer(DI_CHECKBOX);  X1:XL; Y1: 4; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'CRC32'),
    { 4} (ItemType:integer(DI_CHECKBOX);  X1:XL; Y1: 5; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'Adler32'),
    { 5} (ItemType:integer(DI_CHECKBOX);  X1:XL; Y1: 6; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'CRC64'),
    { 6} (ItemType:integer(DI_CHECKBOX);  X1:XL; Y1: 7; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'eDonkey'),
    { 7} (ItemType:integer(DI_CHECKBOX);  X1:XL; Y1: 8; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'MD4'),
    { 8} (ItemType:integer(DI_CHECKBOX);  X1:XL; Y1: 9; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'MD5'),

    { 9} (ItemType:integer(DI_CHECKBOX);  X1:XR; Y1: 2; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'RIPEMD160'),
    {10} (ItemType:integer(DI_CHECKBOX);  X1:XR; Y1: 3; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'SHA1'),
    {11} (ItemType:integer(DI_CHECKBOX);  X1:XR; Y1: 4; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'SHA224'),
    {12} (ItemType:integer(DI_CHECKBOX);  X1:XR; Y1: 5; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'SHA256'),
    {13} (ItemType:integer(DI_CHECKBOX);  X1:XR; Y1: 6; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'SHA384'),
    {14} (ItemType:integer(DI_CHECKBOX);  X1:XR; Y1: 7; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'SHA512'),
    {15} (ItemType:integer(DI_CHECKBOX);  X1:XR; Y1: 8; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'Whirlpool'),

    {16} (ItemType:integer(DI_TEXT);      X1: 0; Y1:10; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:DIF_SEPARATOR; DefaultButton:BOOL(0); Data:''),

    {17} (ItemType:integer(DI_CHECKBOX);  X1:XL; Y1:11; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'Base64'),
    {18} (ItemType:integer(DI_CHECKBOX);  X1:XL; Y1:12; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'(hup)'),
    {19} (ItemType:integer(DI_CHECKBOX);  X1:XL; Y1:13; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'(lsb)'),
    {20} (ItemType:integer(DI_CHECKBOX);  X1:XL; Y1:14; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'(err)'),
    {21} (ItemType:integer(DI_CHECKBOX);  X1:XL; Y1:15; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'(pe5)'),
    {22} (ItemType:integer(DI_CHECKBOX);  X1:XL; Y1:16; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:0; DefaultButton:BOOL(0); Data:'(exp)'),

    {23} (ItemType:integer(DI_TEXT);      X1: 0; Y1:17; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:DIF_SEPARATOR; DefaultButton:BOOL(0); Data:''),
    {24} (ItemType:integer(DI_BUTTON);    X1: 0; Y1:18; X2: 0; Y2: 0; Focus:0; Selected:BOOL(0); Flags:DIF_CENTERGROUP; DefaultButton:BOOL(1); Data:'(OK)'),
    {25} (ItemType:integer(DI_BUTTON);    X1: 0; Y1:18; X2: 0; Y2: 0; Focus:1; Selected:BOOL(0); Flags:DIF_CENTERGROUP; DefaultButton:BOOL(0); Data:'(Cancel)')
  );
var
  ConfigArr: packed array [0..itemsnum-1] of TFarDialogItem;

begin

  Result := 0;
  if InvVers then exit;

  {Disable Expand FN for 1,70 beta 3}
  if Warn13 then InitArr[20].Flags := DIF_DISABLE;

  {expand InitArr to ConfigArr}
  fillchar(ConfigArr, sizeof(ConfigArr), 0);
  for i:=0 to itemsnum-1 do begin
    ConfigArr[i].ItemType        := InitArr[i].ItemType;
    ConfigArr[i].X1              := InitArr[i].X1;
    ConfigArr[i].Y1              := InitArr[i].Y1;
    ConfigArr[i].X2              := InitArr[i].X2;
    ConfigArr[i].Y2              := InitArr[i].Y2;
    ConfigArr[i].Focus           := InitArr[i].Focus;
    ConfigArr[i].Param.Selected  := InitArr[i].Selected;
    ConfigArr[i].Flags           := InitArr[i].Flags;
    ConfigArr[i].DefaultButton   := InitArr[i].DefaultButton;
    MovePchar(ConfigArr[i].Data.Data, InitArr[i].Data);
  end;

  {fill language strings in config array, calculate width}
  l := 4 + MovePChar(ConfigArr[0].Data.Data, GetMsg(_HashCRC_config));
  i := 4 + MovePChar(ConfigArr[18].Data.Data, GetMsg(_HexUppercase));
  if i>l then l:=i;
  i := 4 + MovePChar(ConfigArr[19].Data.Data, GetMsg(_StrictLSB));
  if i>l then l:=i;
  i := 4 + MovePChar(ConfigArr[20].Data.Data, GetMsg(_List_Errors));
  if i>l then l:=i;
  i := 4 + MovePChar(ConfigArr[21].Data.Data, GetMsg(_MD5_PE));
  if i>l then l:=i;
  i := 4 + MovePChar(ConfigArr[22].Data.Data, GetMsg(_Expand_FName));
  if i>l then l:=i;
  i := 10 + MovePChar(ConfigArr[itemsnum-2].Data.Data, GetMsg(_OK))       {V1.4}
          + MovePChar(ConfigArr[itemsnum-1].Data.Data, GetMsg(_Cancel));  {V1.4}
  if i>l then l:=i;
  if XR+9>l then l:=XR+9;  {9=length('Whirlpool')}

  {Get Flags from registry and calculate boolean variables}
  GetRegFlags;

  ConfigArr[1].Param.Selected  := BCRC16;
  ConfigArr[2].Param.Selected  := BCRC24;
  ConfigArr[3].Param.Selected  := BCRC32;
  ConfigArr[4].Param.Selected  := BAdler;
  ConfigArr[5].Param.Selected  := BCRC64;
  ConfigArr[6].Param.Selected  := BED2K;
  ConfigArr[7].Param.Selected  := BMD4;
  ConfigArr[8].Param.Selected  := BMD5;
  ConfigArr[9].Param.Selected  := BRMD160;
  ConfigArr[10].Param.Selected := BSHA1;
  ConfigArr[11].Param.Selected := BSHA224;
  ConfigArr[12].Param.Selected := BSHA256;
  ConfigArr[13].Param.Selected := BSHA384;
  ConfigArr[14].Param.Selected := BSHA512;
  ConfigArr[15].Param.Selected := BWhirl;
  { sep.   [14]}
  ConfigArr[17].Param.Selected := BBase64;
  ConfigArr[18].Param.Selected := BUpcase;
  ConfigArr[19].Param.Selected := BLSBHEX;
  ConfigArr[20].Param.Selected := BLstErr;
  ConfigArr[21].Param.Selected := BPEMD5;
  ConfigArr[22].Param.Selected := BExpNam;

  l := l + 6;
  i := ConfigArr[itemsnum-1].Y1+1;
  ConfigArr[0].X2 := l;
  ConfigArr[0].Y2 := i;

  i:=FARAPI.Dialog(FARAPI.ModuleNumber,-1,-1,l+4,i+2, 'Config',@ConfigArr,itemsnum);

  if i=itemsnum-2 then begin  {V1.4}
    {OK-Button}
    BCRC16  := ConfigArr[1].Param.Selected;
    BCRC24  := ConfigArr[2].Param.Selected;
    BCRC32  := ConfigArr[3].Param.Selected;
    BAdler  := ConfigArr[4].Param.Selected;
    BCRC64  := ConfigArr[5].Param.Selected;
    BED2K   := ConfigArr[6].Param.Selected;
    BMD4    := ConfigArr[7].Param.Selected;
    BMD5    := ConfigArr[8].Param.Selected;
    BRMD160 := ConfigArr[9].Param.Selected;
    BSHA1   := ConfigArr[10].Param.Selected;
    BSHA224 := ConfigArr[11].Param.Selected;
    BSHA256 := ConfigArr[12].Param.Selected;
    BSHA384 := ConfigArr[13].Param.Selected;
    BSHA512 := ConfigArr[14].Param.Selected;
    BWhirl  := ConfigArr[15].Param.Selected;
    {  }
    BBase64 := ConfigArr[17].Param.Selected;
    BUpcase := ConfigArr[18].Param.Selected;
    BLSBHEX := ConfigArr[19].Param.Selected;
    BLstErr := ConfigArr[20].Param.Selected;
    BPEMD5  := ConfigArr[21].Param.Selected;
    BExpNam := ConfigArr[22].Param.Selected;

    Mask := 0;
    if BCRC16  then Mask := Mask or MCRC16;
    if BCRC24  then Mask := Mask or MCRC24;
    if BCRC32  then Mask := Mask or MCRC32;
    if BCRC64  then Mask := Mask or MCRC64;
    if BAdler  then Mask := Mask or MAdler;
    if BMD4    then Mask := Mask or MMD4;
    if BED2K   then Mask := Mask or MED2K;
    if BMD5    then Mask := Mask or MMD5;
    if BRMD160 then Mask := Mask or MRMD160;
    if BSHA1   then Mask := Mask or MSHA1;
    if BSHA224 then Mask := Mask or MSHA224;
    if BSHA256 then Mask := Mask or MSHA256;
    if BSHA384 then Mask := Mask or MSHA384;
    if BSHA512 then Mask := Mask or MSHA512;
    if BWhirl  then Mask := Mask or MWhirl;
    if BUpcase then Mask := Mask or MUpcase;
    if BBase64 then Mask := Mask or MBase64;
    if BLSBHEX then Mask := Mask or MLSBHEX;
    if BLstErr then Mask := Mask or MLstErr;
    if BPEMD5  then Mask := Mask or MPEMD5;
    if BExpNam then Mask := Mask or MExpNam;
    SetRegKey('Flags', Mask);
    Result := 1;
  end
  else if (i=-1) or (i=itemsnum-1) then begin    {V1.4}
    {Cancel-Button}
    {$ifdef DEBUG}
      DebugMessage('Configuration cancelled!')
    {$endif}
  end;
end;


{---------------------------------------------------------------------------}
{$ifdef VirtualPascal}
  function CheckEsc: boolean;
    {-Check if Esc key pressed}
  begin
    CheckEsc := keypressed and (readkey=#27);
  end;
{$else}
  function CheckEsc: boolean;
    {-Check if Esc key pressed}
  var
    Console: THandle;
    InBuf: Windows.TInputRecord;
    Cnt: DWORD;
  begin
    result:= false;
    Console:= GetStdHandle(STD_INPUT_HANDLE);
    if GetNumberOfConsoleInputEvents(Console, Cnt) then begin
      while PeekConsoleInput(Console,Inbuf,1,Cnt) and (Cnt>0) do begin
        ReadConsoleInput(Console,InBuf,1,Cnt);
        {$ifdef D4Plus_OR_FPC}
          if (InBuf.EventType=KEY_EVENT) and InBuf.Event.KeyEvent.bKeyDown and (InBuf.Event.KeyEvent.wVirtualKeyCode=VK_Escape) then begin
            result:= true;
            break;
          end;
        {$else}
          if (InBuf.EventType=KEY_EVENT) and InBuf.KeyEvent.bKeyDown and (InBuf.KeyEvent.wVirtualKeyCode=VK_Escape) then begin
            result:= true;
            break;
          end;
        {$endif}
      end;
    end;
  end;
{$endif}


{---------------------------------------------------------------------------}
function RB(A: longint): longint; assembler;  {&frame-}
  {-Reverse byte order in longint}
asm
  {$ifdef LoadArgs}
    mov eax,[A]
  {$endif}
  xchg al,ah
  rol  eax,16
  xchg al,ah
end;


{---------------------------------------------------------------------------}
function ExistFile(FName: pchar): boolean;
  {-Test if file FName exists}
var
  Code: integer;
begin
  Code := GetFileAttributes(FName);
  ExistFile := (Code<>integer($FFFFFFFF)) and ((Code and FILE_ATTRIBUTE_DIRECTORY)=0);
end;


{---------------------------------------------------------------------------}
function GetPEImgSize(var f: file): comp;
  {-Calculate PE file image size, -1 if Error, 0 if no PE}
var
  mzhdr : TIMAGE_DOS_HEADER;
  pefhdr: TIMAGE_FILE_HEADER;
  pesig : longint;
  pseca : PSECTION_HDR_ARRAY;
  imgsize, pr,sr: comp;
  shaoff: longint;
  nsec  : word;
  i: integer;
const
  TwoPow32 : comp =4294967296.0;     //as typed const to avoid FPC warning
const
  MaxSec = sizeof(buf) div sizeof(TIMAGE_SECTION_HEADER);
begin
  GetPEImgSize := -1;
  seek(f,0);
  blockread(f, mzhdr, sizeof(mzhdr));
  if IOResult<>0 then exit;
  if mzhdr.e_magic=IMAGE_DOS_SIGNATURE then begin
    seek(f, mzhdr.e_lfanew);
    blockread(f,pesig,sizeof(pesig));
    if IOResult<>0 then exit;
    if pesig=IMAGE_NT_SIGNATURE_L then begin
      blockread(f, pefhdr, sizeof(pefhdr));
      if IOResult<>0 then exit;
      nsec := pefhdr.NumberOfSections;
      {Section headers are read into buffer, nsec is the maximum}
      {number that is allowed, should be OK for allmost all PEs}
      if nsec>MaxSec then nsec := MaxSec;
      {Calcalate file position of secttion header array}
      shaoff := mzhdr.e_lfanew+sizeof(pesig)+sizeof(pefhdr)+pefhdr.SizeOfOptionalHeader;
      {postion an read}
      seek(f,shaoff);
      blockread(f,buf,nsec*sizeof(TIMAGE_SECTION_HEADER));
      if IOResult<>0 then exit;
      {set pointer, init "maximum of raw data offset + raw data size"}
      pseca := PSECTION_HDR_ARRAY(@buf);
      imgsize := 0;
      {loop through sections, update maximum}
      for i:=1 to nsec do with pseca^[i] do begin
        {convert negative longints to DWORDs and comps}
        pr := PointerToRawData; if pr<0 then pr := pr + TwoPow32;
        sr := SizeOfRawData;    if sr<0 then sr := sr + TwoPow32;
        sr := sr + pr;
        if sr>imgsize then imgsize := sr;
      end;
      GetPEImgSize := imgsize;
    end
    else GetPEImgSize := 0; {no PE signature}
  end
  else GetPEImgSize := 0;  {no MZ signature}
end;


{---------------------------------------------------------------------------}
function OpenPlugin(OpenFrom: integer; Item: integer): THandle; stdcall; export;
  {-The actual plugin, calculate Hash/CRC and display/write results}
const
  MaxSIM =3+24;      {3 lines header, 24 lines Hash/CRC}
  MaxMCnt=MaxSIM+4;  {Total items in result dialog}
var
  MCnt, Err, SI, k, lf, MaxSI:  integer;
  Msg: array[0..MaxMCnt-1] of PChar;
  Cancel: array[0..1] of Pchar;
  PanelInfo: TPanelInfo;
  f: file;
  tf:textfile;
  MD4Context   : THashContext;     MD4Digest: TMD4Digest;
  ED2KContext  : TED2KContext;    ED2KResult: TED2KResult;
  MD5Context   : THashContext;     MD5Digest: TMD5Digest;
  MD5PEContext : THashContext;   MD5PEDigest: TMD5Digest;       {for PE image MD5}
  RMD160Context: THashContext;  RMD160Digest: TRMD160Digest;
  SHA1Context  : THashContext;    SHA1Digest: TSHA1Digest;
  SHA256Context: THashContext;  SHA256Digest: TSHA256Digest;
  SHA224Context: THashContext;  SHA224Digest: TSHA224Digest;
  SHA384Context: THashContext;  SHA384Digest: TSHA384Digest;
  SHA512Context: THashContext;  SHA512Digest: TSHA512Digest;
  WhirlContext : THashContext;   WhirlDigest: TWhirlDigest;
  CRC16: word;
  CRC24: longint;  pgpdig: TPGPDigest;
  CRC32: longint;
  CRC64: TCRC64;
  Adler: longint;
  FScreen: THandle;
  Aborted: boolean;
  PEDone: boolean;
  FName,hctx: ansistring;              //Filename, help context
  BufIdx: integer;
  pd: shortstring;
  SAM: array[3..MaxSIM] of TDiaStr;    //array for <Name>: <hex string>

  {$ifdef D4Plus_OR_FPC}
    FSC: _Large_Integer;               //file size from GetFileSize
  {$else}
    FSC: TLargeInteger;                //file size from GetFileSize
  {$endif}
  Busy: array[0..2] of PChar;          //Progess display

  ExpFN: array[0..512] of char;
  UsePE: boolean;

const
  iopt = FIB_BUTTONS or FIB_EXPANDENV; //options inputbox filename

const
  faVolumeID  = $00000008;             //Volume ID files
  faDirectory = $00000010;             //Directory files


  {--------------------------------------------------------------}
  procedure AddToBuf(s: shortstring);
    {-Append string to clipboard/file buffer}
  var
    i: integer;
  begin
    for i:=1 to length(s) do begin
      if BufIdx<BufMax then begin
        Buf[BufIdx] := s[i];
        inc(BufIdx);
      end;
    end;
  end;


  {--------------------------------------------------------------}
  procedure AddToBufPC(pc: pchar);
    {-Append string to clipboard/file buffer}
  begin
    while pc^<>#0 do begin
      if BufIdx<BufMax then begin
        Buf[BufIdx] := pc^;
        inc(BufIdx);
      end;
      inc(pc);
    end;
  end;


  {--------------------------------------------------------------}
  procedure BuildPart(h: shortstring; p: PByte; L: integer);
    {-Insert one checksum in Msg/Buf}
  var
    i: integer;
    x: string[255];
  begin
    if BBase64 then x := Base64Str(p,L) else x := HexStr(p,L);
    AddToBuf(h);
    AddToBuf(x);
    AddToBuf(#13#10);
    while x<>'' do begin
      if (SI<MaxSI) and (MCnt<MaxMCnt) then begin
        SAM[SI] := h+copy(x,1,48)+#0;
        Msg[MCnt] := @SAM[SI][1];
        inc(MCnt);
        inc(SI);
      end;
      delete(x,1,48);
      {space fill for followup lines}
      for i:=1 to length(h) do h[i] := ' ';
    end;
  end;


  {--------------------------------------------------------------}
  function FileWriteOK(const FN: string): boolean;
    {-Check if file exists, ask for overwrite}
  var
    Over: array[0..1] of PChar;        //Overwrite confirmation
  begin
    FileWriteOK := false;
    system.assign(f, FN);
    {File mode is already set to "readonly"}
    reset(f,1);
    if IOResult=0 then begin
      close(f);
      if IOResult<>0 then;
      Over[0] := GetMsg(_Titel);
      Over[1] := GetMsg(_Ask_Overwrite);
      if FARAPI.Message(FARAPI.ModuleNumber, FMSG_WARNING or FMSG_MB_YESNO, nil, @over, 2, 0)<>0 then exit;
    end;
    FileWriteOK := true;
  end;

  {--------------------------------------------------------------}
  procedure InitSums;
   {-Initialize checked Hash/CRC functions}
  begin
    if BRMD160 then RMD160Init(RMD160Context);
    if BSHA1   then SHA1Init(SHA1Context);
    if BSHA224 then SHA224Init(SHA224Context);
    if BSHA256 then SHA256Init(SHA256Context);
    if BSHA384 then SHA384Init(SHA384Context);
    if BSHA512 then SHA512Init(SHA512Context);
    if BWhirl  then Whirl_Init(WhirlContext);
    if BMD4    then MD4Init(MD4Context);
    if BED2K   then ED2K_Init(ED2KContext);
    if BMD5    then MD5Init(MD5Context);
    if BCRC16  then CRC16Init(CRC16);
    if BCRC24  then CRC24Init(CRC24);
    if BCRC32  then CRC32Init(CRC32);
    if BCRC64  then CRC64Init(CRC64);
    if BAdler  then Adler32Init(Adler);
  end;

  {--------------------------------------------------------------}
  procedure UpdateSums(n: longint);
   {-Update checked Hash/CRC functions}
  begin
    if BRMD160 then RMD160UpdateXL(RMD160Context,@buf,n);
    if BSHA1   then SHA1UpdateXL(SHA1Context,@buf,n);
    if BSHA224 then SHA224UpdateXL(SHA224Context,@buf,n);
    if BSHA256 then SHA256UpdateXL(SHA256Context,@buf,n);
    if BSHA384 then SHA384UpdateXL(SHA384Context,@buf,n);
    if BSHA512 then SHA512UpdateXL(SHA512Context,@buf,n);
    if BWhirl  then Whirl_UpdateXL(WhirlContext,@buf,n);
    if BMD4    then MD4UpdateXL(MD4Context,@buf,n);
    if BED2K   then ED2K_UpdateXL(ED2KContext,@buf,n);
    if BMD5    then MD5UpdateXL(MD5Context,@buf,n);
    if BCRC16  then CRC16UpdateXL(CRC16,@buf,n);
    if BCRC24  then CRC24UpdateXL(CRC24,@buf,n);
    if BCRC32  then CRC32UpdateXL(CRC32,@buf,n);
    if BCRC64  then CRC64UpdateXL(CRC64,@buf,n);
    if BAdler  then Adler32UpdateXL(Adler,@buf,n);
  end;

  {--------------------------------------------------------------}
  procedure FinalizeSums;
   {-Finalize checked Hash/CRC functions}
  begin
    if BRMD160 then RMD160Final(RMD160Context,RMD160Digest);
    if BSHA1   then SHA1Final(SHA1Context,SHA1Digest);
    if BSHA224 then SHA224Final(SHA224Context,SHA224Digest);
    if BSHA256 then SHA256Final(SHA256Context,SHA256Digest);
    if BSHA384 then SHA384Final(SHA384Context,SHA384Digest);
    if BSHA512 then SHA512Final(SHA512Context,SHA512Digest);
    if BWhirl  then Whirl_Final(WhirlContext,WhirlDigest);
    if BMD4    then MD4Final(MD4Context,MD4Digest);
    if BED2K   then ED2K_Final(ED2KContext,ED2KResult);
    if BMD5    then MD5Final(MD5Context,MD5Digest);
    if BCRC16  then CRC16Final(CRC16);
    if BCRC24  then CRC24Final(CRC24);
    if BCRC32  then CRC32Final(CRC32);
    if BCRC64  then CRC64Final(CRC64);
    if BAdler  then Adler32Final(Adler);
  end;

  {--------------------------------------------------------------}
  function TestAbort: boolean;
    {-Check for Esc, display dialog, set Aborted=Result=true if user wants to break}
  var
    i: integer;
  begin
    if CheckEsc then begin
      Cancel[0] := Msg[0];
      Cancel[1] := GetMsg(_Ask_CancelCalc);
      i := FARAPI.Message(FARAPI.ModuleNumber, FMSG_Down or FMSG_WARNING or FMSG_MB_YESNO or FMSG_LEFTALIGN, nil, @cancel, 2, 0);
      if i=0 then begin
        Aborted := true;
        Msg[2] := GetMsg(_Calculation_cancelled);
        MCnt := 3;
      end;
    end;
    TestAbort := Aborted;
  end;

  {--------------------------------------------------------------}
  procedure DisplayProgress(LC: comp);
   {-Display progress indicator (% done=}
  begin
    if FSC.QuadPart > 0 then begin
      {show percent if file size available}
      str(round(100*LC/FSC.QuadPart):3, pd);
      pd := pd + GetPMsg(_Percent_done)+#0;
    end
    else begin
      {show MB if filesize not available}
      str(LC/1E6:1:1, pd);
      pd := pd + GetPMsg(_MB_done)+#0;
    end;
    Busy[2] := @pd[1];
    FARAPI.Message(FARAPI.ModuleNumber, 0, nil, @Busy,3, 0);
  end;


  {----------------------------------------------------------------}
  procedure processfile(const Filename: ansistring; UseFN: boolean);
    {-Calculate results for one file}
  var
    n: longint;
    LC, imgsize: comp;
  begin
    PEDone := false;
    assignfile(f,Filename);
    system.reset(f,1);
    Err := IOResult;
    if Err=0 then begin
      {Build fix part of progress dialog messages}
      Busy[0] := GetMsg(_Titel);
      if UseFN then Busy[1] := PChar(Filename)
      else Busy[1] := GetMsg(_Calc_in_Progress);
      {Get file size}
      FSC.LowPart := GetFileSize(PHandle(@f)^,@FSC.HighPart);
      if (FSC.LowPart=$FFFFFFFF) and (GetLastError<>NO_Error) then FSC.QuadPart := 0;
      {Initialize checked Hash/CRC functions}
      InitSums;
      {Initializ number of bytes read}
      LC := 0;
      {Do special processing if 64 bit file size availabe and PE-MD5 wanted}
      if (FSC.QuadPart>0) and UsePE then begin
        {Get imgsize = PE file image size, valid PE only if > 0}
        imgsize := GetPEImgSize(f);
        {Reposition to begin of file}
        system.seek(f,0);
        Err := IOResult;
        if (Err=0) and (imgsize>0) and (FSC.QuadPart>imgsize) then begin
          {Process PE "image" for PE file with "overlays"}
          {$ifdef DEBUG}
            DebugMessage('Start PE');
          {$endif}
          while imgsize>0 do begin
            {$ifdef DEBUG}
              str(imgsize:1:0,pd);
              pd := 'Rest '+pd+#0;
              DebugMessage(@pd[1]);
            {$endif}
            {read maximum remaining bytes that fit into buffer}
            {this is necessary for two part md5, otherwise some}
            {bytes from overlay are merged into image digest}
            if imgsize>sizeof(buf) then n:=sizeof(buf) else n:=round(imgsize);
            if TestAbort then break;
            DisplayProgress(LC);
            {read next block}
            blockread(f,buf,n);
            Err := IOResult;
            if Err<>0 then break;
            {Update numbers of bytes read and number of bytes left}
            LC := LC + n;
            imgsize := imgsize - n;
            {Update checked Hash/CRC}
            UpdateSums(n);
          end;
          if Err=0 then begin
            {PE-Image read, calculate intermediate MD5}
            {$ifdef DEBUG}
              DebugMessage('Final PE');
            {$endif}
            {Make a temporary copy of the MD5 context (so it cant be used for}
            {the remaining part) and calculate the intermediate MD5 digest}
            MD5PEContext := MD5Context;
            MD5Final(MD5PEContext,MD5PEDigest);
            {Flag PE processing was done, used for printout}
            PEDone := true;
          end;
        end;
      end;

      {standard read loop}
      {$ifdef DEBUG}
        DebugMessage('Start Standard');
      {$endif}
      {Process the "overlay" part of PEs or the whole file}
      {for PEs without overlay and other files}
      repeat
        if TestAbort then break;
        DisplayProgress(LC);
        {read next block}
        blockread(f,buf,sizeof(buf),n);
        Err := IOResult;
        if Err<>0 then break;
        LC := LC + n;
        {Update checked Hash/CRC}
        UpdateSums(n);
        {avoid Delphi eof bug: end of file if no complete block}
      until sizeof(buf)<>n;
      {Finalize checked Hash/CRC functions}
      FinalizeSums;
      system.close(f);
      n := IOResult;
    end;
  end;


  {--------------------------------------------------------------}
  procedure WritePart(h: shortstring; p: PByte; L: integer);
    {-Write one checksum to result file}
  var
    x: string[255];
  begin
    if BBase64 then x := Base64Str(p,L) else x := HexStr(p,L);
    writeln(tf, h, x);
  end;


  {--------------------------------------------------------------}
  function GetMaxY: integer;
    {-Return number of screen/panel lines}
  var
    stdout: THandle;
    lpConsoleScreenBufferInfo: TConsoleScreenBufferInfo;
  begin
    stdout := GetStdHandle(STD_OUTPUT_HANDLE);
    if (stdout<>INVALID_HANDLE_VALUE) and (GetConsoleScreenBufferInfo(stdout, lpConsoleScreenBufferInfo)) then begin
      Result := lpConsoleScreenBufferInfo.srWindow.Bottom;
    end
    else begin
      {Console info not available: use panel info but this number}
      {not a very reliable result for the number of screen lines!}
      Result := PanelInfo.PanelRect.Bottom;
    end;
  end;

begin

  {$ifdef VirtualPascal}
    FileMode := $40; {open_access_ReadOnly or open_share_DenyNone;}
  {$else}
    FileMode := 0;
  {$endif}

  result:= INVALID_HANDLE_VALUE;
  if InvVers then exit;

  {Get config options from registry}
  GetRegFlags;

  UsePE := BMD5 and BPEMD5;

  if UsePE then begin
    {Build MD5 result names}
    smd5fil := copy(GetPMsg(_MD5_File),1,9);
    smd5img := copy(GetPMsg(_MD5_Image),1,9);
    while length(smd5fil)<9 do smd5fil := ' '+smd5fil;
    while length(smd5img)<9 do smd5img := ' '+smd5img;
  end;

  {Get panel info}
  FARAPI.Control(INVALID_HANDLE_VALUE, FCTL_GETPANELINFO, @PanelInfo);

  if PanelInfo.PanelType<>PTYPE_FILEPANEL then exit;

  if not AnyHC then begin
    {Force configuration if no CRC or Hash checked}
    Configure(0);
    GetRegFlags;
  end;


  if PanelInfo.SelectedItemsNumber>1 then begin

    {----------------------------------------------------}
    {--------------  Multi file mode  -------------------}
    {----------------------------------------------------}
    hctx := FARAPI.ModuleName;
    hctx := '<'+hctx+'>Multimode'+#0;
    if FARAPI.InputBox(GetMsg(_Enter_file_name), GetMsg(_Filename_for_list_of_Hash_CRC_results),
                       'HashCRC_Hist', 'hashcrc.lst', buf, 256, Pchar(hctx), iopt)<>0
    then begin
      FName := buf;
      if FileWriteOK(FName) then begin
        system.assign(tf,buf);
        rewrite(tf);
        if IOResult<>0 then begin
          ShowMessage(PChar(GetPMsg(_File_error)+': '+FName), true);
          exit;
        end;
        if (not BBase64) and BLSBHEX then begin
          {Show Strict LSB hint}
          if BCRC16 or BCRC24 or BCRC32 or BAdler then begin
            writeln(tf,'(', GetMsg(_StrictLSB),')');
            writeln(tf);
          end;
        end;
        HexUpper := BUpcase;
        for k:=0 to PanelInfo.SelectedItemsNumber-1 do begin
          FName := PanelInfo.SelectedItems^[k].Finddata.cFileName;
          Err := 0;
          Aborted := false;
          Msg[0]:= GetMsg(_Titel);
          Msg[1]:= PChar(FName);
          FScreen := FarAPI.SaveScreen(0,0,-1,-1);
          ProcessFile(FName, true);
          FARAPI.RestoreScreen(FScreen);
          if Aborted then begin
            MCnt := 3;
            FARAPI.Message(FARAPI.ModuleNumber, FMSG_MB_OK or FMSG_LEFTALIGN, 'Contents', @Msg, MCnt, 0);
            break;
          end;
          if Err=0 then begin
            {Output expanded file name, if function available and option checked}
            if Warn13 or (not BExpNam) then writeln(tf,FName)
            else begin
              lf := 1+StdFun.ConvertNameToReal(PanelInfo.SelectedItems^[k].Finddata.cFileName, ExpFN, sizeof(ExpFN));
              if lf<sizeof(ExpFN) then writeln(tf,ExpFN) else writeln(tf,FName);
            end;
            Long2PGP(CRC24, pgpdig);
            if (not BBase64) and (not BLSBHEX) then begin
              {swap bytes: display shall look like word / longint}
              {but HexStr constructs LSB first}
              CRC16 := swap(CRC16);
              CRC32 := RB(CRC32);
              Adler := RB(Adler);
            end;
            if BCRC16  then WritePart('    CRC16: ', @CRC16, sizeof(CRC16));
            if BCRC24  then begin
              if BBase64 or (not BLSBHEX) then WritePart('    CRC24: ', @pgpdig, 3)
              else WritePart('    CRC24: ', @CRC24,3)
            end;
            if BCRC32  then WritePart('    CRC32: ', @CRC32, sizeof(CRC32));
            if BAdler  then WritePart('  Adler32: ', @Adler, sizeof(adler));
            if BCRC64  then WritePart('    CRC64: ', @CRC64, sizeof(CRC64));
            if BED2K then begin
                            WritePart('  eDonkey: ', @ED2KResult.eDonkey, sizeof(ED2KResult.eDonkey));
              if ED2KResult.differ then begin
                            WritePart('    eMule: ', @ED2KResult.eMule, sizeof(ED2KResult.eMule));
              end;
            end;
            if BMD4    then WritePart('      MD4: ', @MD4Digest, sizeof(MD4Digest));
            if PEDone  then begin
                            WritePart(smd5img+': ', @MD5PEDigest, sizeof(MD5Digest));
                            WritePart(smd5fil+': ', @MD5Digest, sizeof(MD5Digest));
            end
            else begin
              if BMD5  then WritePart('      MD5: ', @MD5Digest, sizeof(MD5Digest));
            end;
            if BRMD160 then WritePart('RIPEMD160: ', @RMD160Digest, sizeof(RMD160Digest));
            if BSHA1   then WritePart('     SHA1: ', @SHA1Digest, sizeof(SHA1Digest));
            if BSHA224 then WritePart('   SHA224: ', @SHA224Digest, sizeof(SHA224Digest));
            if BSHA256 then WritePart('   SHA256: ', @SHA256Digest, sizeof(SHA256Digest));
            if BSHA384 then WritePart('   SHA384: ', @SHA384Digest, sizeof(SHA384Digest));
            if BSHA512 then WritePart('   SHA512: ', @SHA512Digest, sizeof(SHA512Digest));
            if BWhirl  then WritePart('Whirlpool: ', @WhirlDigest, sizeof(WhirlDigest));
            writeln(tf);
          end
          else begin
            if BLstErr then begin
              writeln(tf,FName);
              writeln(tf,' *** ', GetMsg(_File_error), ': ', Err);
              writeln(tf);
            end;
          end;
        end;
        close(tf);
        if IOResult<>0 then ShowMessage(PChar(GetPMsg(_File_error)+': '+FName), true);
      end;
    end;
  end

  else begin

    {----------------------------------------------------}
    {--------------  Single file mode  ------------------}
    {----------------------------------------------------}
    if (PanelInfo.SelectedItemsNumber=0) or (PanelInfo.CurrentItem<=0) then exit;

    with PanelInfo.PanelItems^[PanelInfo.CurrentItem].FindData do begin
      Msg[0] := GetMsg(_Titel);
      Msg[1] := PanelInfo.PanelItems^[PanelInfo.CurrentItem].FindData.cFileName;
      Msg[2] := #01#00;
      if dwFileAttributes and (faVolumeID or faDirectory) <> 0 then exit;
      {double check, above check does not exclude files from archives etc}
      if not ExistFile(Msg[1]) then exit;
    end;

    Err := 1;
    MCnt := 3;
    Aborted := false;

    if (PanelInfo.ItemsNumber>0) and PanelInfo.Visible and PanelInfo.Focus then begin
      FName   := Msg[1];
      FScreen := FarAPI.SaveScreen(0,0,-1,-1);
      ProcessFile(FName, true);
      FARAPI.RestoreScreen(FScreen);

      if (Err=0) and not Aborted then begin
        if not BBase64 then begin
          if not BLSBHEX then begin
            {swap bytes: display shall look like word / longint}
            {but HexStr constructs LSB first}
            CRC16 := swap(CRC16);
            CRC32 := RB(CRC32);
            Adler := RB(Adler);
            Msg[2]:= #01'M'#00;
          end
          else Msg[2]:= #01'L'#00;
        end;
        Long2PGP(CRC24, pgpdig);
        HexUpper := BUpcase;
        SI := 3;
        MaxSI := GetMaxY-6;
        If MaxSI>MaxSIM then MaxSI := MaxSIM;
        MCnt := 3;
        BufIdx := 0;
        {Output expanded file name, if function available and option checked}
        if Warn13 or (not BExpNam) then AddToBuf(Fname)
        else begin
          lf := 1+StdFun.ConvertNameToReal(PanelInfo.PanelItems^[PanelInfo.CurrentItem].FindData.cFileName, ExpFN, sizeof(ExpFN));
          if lf<sizeof(ExpFN) then AddToBufPC(ExpFN) else AddToBuf(Fname);
        end;

        AddToBuf(#13#10);
        if BCRC16  then BuildPart('    CRC16: ', @CRC16, sizeof(CRC16));
        if BCRC24  then begin
          if BBase64 or (not BLSBHEX) then BuildPart('    CRC24: ', @pgpdig, 3)
          else BuildPart('    CRC24: ', @CRC24,3)
        end;
        if BCRC32  then BuildPart('    CRC32: ', @CRC32, sizeof(CRC32));
        if BAdler  then BuildPart('  Adler32: ', @Adler, sizeof(adler));
        if BCRC64  then BuildPart('    CRC64: ', @CRC64, sizeof(CRC64));
        if BED2K then begin
                        BuildPart('  eDonkey: ', @ED2KResult.eDonkey, sizeof(ED2KResult.eDonkey));
          if ED2KResult.differ then begin
                        BuildPart('    eMule: ', @ED2KResult.eMule, sizeof(ED2KResult.eMule));
          end;
        end;

        if BMD4    then BuildPart('      MD4: ', @MD4Digest, sizeof(MD4Digest));
        if PEDone  then begin
                        BuildPart(smd5img+': ', @MD5PEDigest, sizeof(MD5Digest));
                        BuildPart(smd5fil+': ', @MD5Digest, sizeof(MD5Digest));
        end
        else begin
          if BMD5  then BuildPart('      MD5: ', @MD5Digest, sizeof(MD5Digest));
        end;
        if BRMD160 then BuildPart('RIPEMD160: ', @RMD160Digest, sizeof(RMD160Digest));
        if BSHA1   then BuildPart('     SHA1: ', @SHA1Digest, sizeof(SHA1Digest));
        if BSHA224 then BuildPart('   SHA224: ', @SHA224Digest, sizeof(SHA224Digest));
        if BSHA256 then BuildPart('   SHA256: ', @SHA256Digest, sizeof(SHA256Digest));
        if BSHA384 then BuildPart('   SHA384: ', @SHA384Digest, sizeof(SHA384Digest));
        if BSHA512 then BuildPart('   SHA512: ', @SHA512Digest, sizeof(SHA512Digest));
        if BWhirl  then BuildPart('Whirlpool: ', @WhirlDigest, sizeof(WhirlDigest));
        AddToBuf(#0#0);
        Msg[MCnt] := #01#00;
        inc(MCnt);
        Msg[MCnt] := GetMsg(_Btn_OK);
        inc(MCnt);
        Msg[MCnt] := GetMsg(_Btn_ClipBoard);
        inc(MCnt);
        Msg[MCnt] := GetMsg(_Btn_File);
        inc(MCnt);

        repeat
          {Check if MCnt < 13 for older Far versions}
          if Warn13 and (MCnt>12) then begin
            ShowMessage(GetMsg(_Too_many_items), true);
            exit;
          end;
          k := FARAPI.Message(FARAPI.ModuleNumber,FMSG_LEFTALIGN,'Contents', @Msg, MCnt, 3);
          if k=1 then begin
            {Button 1: clipboard}
            if StdFun.CopyToClipboard(Pchar(@buf))<>0 then ShowMessage(GetMsg(_ClipBoard_done), false)
            else ShowMessage(GetMsg(_ClipBoard_error), true);
          end
          else if k=2 then begin
            {Button 2: File}
            if FileWriteOK(FName+'.chf') then begin
              system.assign(f,Fname+'.chf');
              rewrite(f,1);
              blockwrite(f,buf,BufIdx);
              system.close(f);
              if IOResult=0 then ShowMessage(GetMsg(_File_done), false)
              else ShowMessage(GetMsg(_File_error), true);
            end;
          end
          else begin
            {OK, Esc ...}
            exit;
          end;
        until false;
      end; {if not Aborted}
    end;

    {Either error or cancelled, or too many items}
    if Err<>0 then begin
      Msg[3] := GetMsg(_Invalid_Input);
      Msg[4]:= #01#00;                   // separator line
      MCnt := 5;
    end;
    FARAPI.Message(FARAPI.ModuleNumber, FMSG_MB_OK or FMSG_LEFTALIGN, 'Contents', @Msg, MCnt, 0);

  end;

end;


{---------------------------------------------------------------------------}
function GetMinFarVersion: DWORD; stdcall; export;
  {-Return minimum FAR version for plugin}
begin
  GetMinFarVersion := MakeFarVersion(1,70,591);  {1.70 Beta 3}
end;


exports
  GetMinFarVersion,
  SetStartupInfo,
  GetPluginInfo,
  Configure,
  OpenPlugin;

begin
end.


