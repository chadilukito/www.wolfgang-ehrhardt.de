unit CRT;

{$A+,B-,C-,D+,E-,F-,G+,H+,I-,J+,K-,L+,M-,N+,O+,P-,Q-,R-,S-,T-,U-,V-,W-,X+,Y+}

{BP7 compatible CRT unit for Win32/64 Delphi}

interface

{$IFDEF CONDITIONALEXPRESSIONS}
  {$IF CompilerVersion >= 23.0}  {D16(XE2)+}
    {$DEFINE UNIT_SCOPE}
  {$IFEND}
  {$IF CompilerVersion >= 23.0}
    {$DEFINE TXTREC_CP}
  {$IFEND}
{$ENDIF}


uses
  {$ifdef UNIT_SCOPE}
    winapi.windows;
  {$else}
    Windows;
  {$endif}

(*************************************************************************

 DESCRIPTION   :  BP7 compatible CRT unit for Win32/64 Delphi

 REQUIREMENTS  :  D2-D7/D9-D10/D12/D17

 EXTERNAL DATA :

 MEMORY USAGE  :

 DISPLAY MODE  :  text

 REMARKS       :  The unit is tested with D17 (XE3) but NOT with D14-D16.
                  The symbols UNIT_SCOPE and TXTREC_CP are defined for D16+,
                  for UNIT_SCOPE this is consistent with official Delphi
                  documents; please report any problems.

 REFERENCES    :  [1] Will DeWitt's Delphi 2+ CRT unit from Code central
                      http://cc.embarcadero.com/Item.aspx?id=19810
                  [2] Phoenix Technical Reference Series: System BIOS for
                      IBM PC/XT/AT Computers and Compatibles
                  [3] Background info: CRT source codes from BP7, VP 2.1, FP 2.0
                  [4] Rudy Velthuis' freeware http://rvelthuis.de/programs/console.html

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 1.00               W. deWitt   Initial version
 1.10               WdW         Delphi 2 compatibility and other
 1.11               WdW         Delphi 7 separation etc
 1.12               WdW         Bug fixes
 1.20     21.03.04  WdW         Some additional extended Crt functionality
 1.21     23.09.05  W.Ehrhardt  Removed sysutils,
 1.30.00  10.10.06  we          Routines from Rudy Velthuis' console.pas:
                                TranslateKey, Readkey, Keypressed
 1.30.01  10.10.06  we          Keypressed with INPUT_RECORD
 1.30.02  11.10.06  we          Removed NOCRTEXTENSIONS
 1.30.03  11.10.06  we          Delay with DWORD
 1.30.04  11.10.06  we          RV Convertkey removed
 1.30.05  11.10.06  we          RV Keypressed D3 compatible
 1.30.06  11.10.06  we          Removed "deprecated"
 1.30.07  11.10.06  we          mask ENHANCED_KEY in readkey
 1.30.08  11.10.06  we          Removed unused consts
 1.30.09  11.10.06  we          (VPC:) Removed register, bug fix first 2 entries of RV CKeys (trailing ';')
 1.30.10  11.10.06  we          WindMin/WindMax longint
 1.31.00  11.10.06  we          removed crt.ini
 1.31.01  12.10.06  we          Hardware sound for Win9x, MessageBeep(0) for NT+, Hz now word
 1.31.02  12.10.06  we          Fixed LastMode vs. LASTMODE confusion, const _LASTMODE=-1;
                                LastMode and Actual_Mode integer
 1.31.03  13.10.06  we          Map modes with Font8x8 to C4350
 1.31.04  14.10.06  we          Removed RV routines (buggy Enhanced keys, no Alt+[A-Z] etc
                                Complete rewrite of keypressed/readkey
 1.31.05  14.10.06  we          Fix: NumPad-5, Numpad-/, Ctrl-PrtScr
 1.31.06  15.10.06  we          Fix: Crtl-2, Crtl-6
 1.31.07  15.10.06  we          Esc, ^A,^D,^F,^S,^Z, Num-Enter in CrtInput
 1.31.08  15.10.06  we          BP types in GotoXY, Sound, TextBackground, TextColor
 1.31.09  15.10.06  we          BP modes, textmode call clrscr; WhereX/Y: byte
 1.31.10  16.10.06  we          Window parameters bytes, WindMin/WindMax words,
 1.31.11  16.10.06  we          Normalize cursor, BufMax instead of f.BufPos in CrtInput
 1.31.12  17.10.06  we          Code clean up and comments
 1.31.13  17.10.06  we          More comments/references
 1.31.14  17.10.06  we          Bugfix scroll: byte -> smallint
 1.31.15  18.10.06  we          Last cosmetic changes in comment
 1.31.16  05.11.06  we          Keep only INPUT_RECORD as non pre-D4 type
 1.31.17  05.11.06  we          GetCursorPosXY
 1.31.18  07.11.06  we          CHAR_INFO etc reintroduced for Delphi2

 1.32.00  18.07.09  we          Delphi 2009 (D12) adjustments
 1.32.01  29.07.09  we          Updated URL for [1]
 1.32.02  02.06.10  we          CRTFix_01 for ^

 1.33.00  23.12.12  we          D17 (aka XE3) adjustments


**************************************************************************)


(*-------------------------------------------------------------------------
Portions Copyright (c) 1988-2003 Borland Software Corporation
Portions Copyright (c) 2006-2012 W.Ehrhardt

Disclaimer:
===========
This software is provided 'as-is', without any express or implied warranty.
In no event will the authors be held liable for any damages arising from
the use of this software.

If you use this code, please credit me and keep the references to the other
authors and sources.


Description:
============

This unit is a light version of Will DeWitt's code with several bug fixes
(especially readkey, extended key codes etc). Will's 'unit was based heavily
off of the Borland CBuilder 5 RTL'. Because of the unclear licence status of
Will's unit, my CRT source is not under zlib license.

Anyway, in this unit the code from Will/Borland is radically rewritten and
rearranged. The guiding requirement was to make it almost BP7 compatible.

The basic idea for separate hardware/software sound support is from Rudy
Velthuis' freeware console, but the implementation is different.

The supported keys for line editing are from BP7 (^A, ^H, ^D, ^F, ^M, ^S,
^Z), the paradigm shift from readkey to keypressed for doing the dirty work
is from FP. The key codes / translations / functionalities were taken from
the Phoenix BIOS book and a test program compiled with BP7.

There is still work to be done for some rare special extended keys, but this
work is delayed to bugfixes or problem reports.

-------------------------------------------------------------------------*)

const
                                { CRT modes }
  BW40          = 0;            { 40x25 B/W on Color Adapter }
  CO40          = 1;            { 40x25 Color on Color Adapter }
  BW80          = 2;            { 80x25 B/W on Color Adapter }
  CO80          = 3;            { 80x25 Color on Color Adapter }
  Mono          = 7;            { 80x25 on Monochrome Adapter }
  Font8x8       = 256;          { Add-in for ROM font }

                                { Delphi extension modes }
  Last_Mode     = -1;           { Use LastMode}
  Init_Mode     = -2;           { Mode at initialization}

  C40           = CO40;         { Mode constants for 3.0 compatibility }
  C80           = CO80;

  Black         = 0;            { Foreground and background color constants }
  Blue          = 1;
  Green         = 2;
  Cyan          = 3;
  Red           = 4;
  Magenta       = 5;
  Brown         = 6;
  LightGray     = 7;

  DarkGray      = 8;            { Foreground color constants }
  LightBlue     = 9;
  LightGreen    = 10;
  LightCyan     = 11;
  LightRed      = 12;
  LightMagenta  = 13;
  Yellow        = 14;
  White         = 15;

  Blink         = 128;          { Mask for blinking, does not work in Win32,}
                                { turns on high intensity background colors.}

var
  CheckBreak : boolean = true;  { Enable Ctrl-Break }
  CheckSnow  : boolean;         { Enable snow filtering }
  DirectVideo: boolean;         { Enable direct video addressing }
  LastMode   : integer;         { Current text mode }
  TextAttr   : byte;            { Current text attribute }
  CheckEOF   : boolean = false; { Enable Ctrl-Z }
  WindMin    : word;            { Window upper left coordinates }
  WindMax    : word;            { Window lower right coordinates }

procedure AssignCrt(var f: text);
  {-Associate the console with text file f}

procedure ClrEol;
  {-Clears all the chars from the cursor position to the end of the line}

procedure ClrScr;
  {-Clear the current window, screen if no window set}

procedure Delay(MS: word);
  {-Delay/Sleep for MS milliseconds}

procedure DelLine;
  {-Delete the line containing the cursor}

procedure GotoXY(X, Y: byte);
  {-Move cursor to col X, row Y (window relative)}

procedure HighVideo;
  {-Set high intensity forground}

procedure InsLine;
  {-Insert new line at cursor position}

function  KeyPressed: boolean;
  {-Return true if a character producing key has been pressed}

procedure LowVideo;
  {-Set low intensity forground}

procedure NormVideo;
  {-Set initial text attribute}

procedure NoSound;
  {-Sound off, hardware for Win9x, dummy for NT+}

function  ReadKey: AnsiChar;
  {-Read a character from the keyboard, sleep until keypressed}

procedure Sound(Hz: word);
  {-Sound on, hardware for Win9x / MesseageBeep(0) for NT+}

procedure TextBackground(Color: byte);
  {-Set background color part if text attribute}

procedure TextColor(Color: byte);
  {-Set foreground color part if text attribute}

procedure TextMode(Mode: integer);
  {-Set new text mode / NormalAttr and clrscr}

function  WhereX: byte;
  {-Return current column of cursor (window relative)}

function  WhereY: byte;
  {-Return current row of cursor (window relative)}

procedure Window(X1, Y1, X2, Y2: byte);
  {-Define screen area as net text window}


{$ifdef VER90}
procedure InitCRT;
  {-Interfaced for Delphi 2 to overcome IsConsole quirk, see initialization}
{$endif}


implementation

{Will deWitt lists the following line in his source code:}
{Copyright (c) 1988-2003 Borland Software Corporation}

{$ifdef FPC}
  Error('Not for Free Pascal');
{$endif}

{$ifdef VirtualPascal}
  Error('Not for VirtualPascal');
{$endif}

{$ifndef WIN32}
  {$ifndef WIN64}
    Error('At least Delphi 2');
  {$endif}
{$endif}

{$ifdef VER120}    {D4}
  {$define D4PLUS}
{$endif}

{$ifdef VER125}    {BCB4}
  {$define D4PLUS}
{$endif}

{$ifdef VER130}    {D5}
  {$define D4PLUS}
{$endif}

{$ifdef VER140}    {D6}
  {$define D4PLUS}
  {$define D6PLUS}
{$endif}

{$ifdef CONDITIONALEXPRESSIONS}  {D6+}
  {$ifndef D4PLUS}
    {$define D4PLUS}
  {$endif}
  {$ifndef D6PLUS}
    {$define D6PLUS}
  {$endif}
{$endif}


{$ifndef D6PLUS}
{Directly use Delphi 2-5 definitions to avoid sysutils overhead}
const
  {File mode magic numbers}
  fmClosed = $D7B0;
  fmInput  = $D7B1;
  fmOutput = $D7B2;
  fmInOut  = $D7B3;

type
  {Text file record structure used for text files}
  PTextBuf = ^TTextBuf;
  TTextBuf = array[0..127] of AnsiChar;
  TTextRec = packed record
               Handle   : integer;
               Mode     : integer;
               BufSize  : Cardinal;
               BufPos   : Cardinal;
               BufEnd   : Cardinal;
               BufPtr   : PAnsiChar;
               OpenFunc : pointer;
               InOutFunc: pointer;
               FlushFunc: pointer;
               CloseFunc: pointer;
               UserData : array[1..32] of byte;
               Name     : array[0..259] of AnsiChar;
               Buffer   : TTextBuf;
             end;
{$endif}



{$ifndef D4PLUS}
  { Types that are either incorrectly defined in Windows.pas in pre-Delphi 4,
    or that aren't defined at all. }
type
  CONSOLE_SCREEN_BUFFER_INFO = TConsoleScreenBufferInfo;
  CONSOLE_CURSOR_INFO = TConsoleCursorInfo;
  COORD = TCoord;
  SMALL_RECT = TSmallRect;

  CHAR_INFO = record
                case integer of
                  0: (UnicodeChar: WCHAR; Attributes: word);
                  1: (AsciiChar: AnsiChar);
              end;

  KEY_EVENT_RECORD = packed record
                       bKeyDown: BOOL;
                       wRepeatCount: word;
                       wVirtualKeyCode: word;
                       wVirtualScanCode: word;
                       case integer of
                         0: (UnicodeChar: WCHAR; dwControlKeyState: DWORD);
                         1: (AsciiChar: AnsiChar);
                     end;
  TKeyEventRecord = KEY_EVENT_RECORD;

  INPUT_RECORD = record
                   EventType: word;
                   Reserved: word;
                   Event: record case integer of
                     0: (KeyEvent: TKeyEventRecord);
                     1: (MouseEvent: TMouseEventRecord);
                     2: (WindowBufferSizeEvent: TWindowBufferSizeRecord);
                     3: (MenuEvent: TMenuEventRecord);
                     4: (FocusEvent: TFocusEventRecord);
                   end;
                 end;

function  ReadConsoleInputA(hConsoleInput: THandle; var lpBuffer: INPUT_RECORD; nLength: DWORD; var lpNumberOfEventsRead: DWORD): BOOL; stdcall;
  external 'kernel32.dll' name 'ReadConsoleInputA';
function  ScrollConsoleScreenBufferA(hConsoleOutput: THandle; const lpScrollRectangle: TSmallRect; lpClipRectangle: PSmallRect; dwDestinationOrigin: TCoord; var lpFill: CHAR_INFO): BOOL; stdcall;
  external 'kernel32.dll' name 'ScrollConsoleScreenBufferA';

{$endif}

type
  T2Bytes = packed record
              X,Y: byte;
            end;


type
  TScrollDir = (UP, DOWN);   {Enum type for scroll directions}


type
  TStringInfo = record
                  X, Y: integer;
                  SStart, SEnd: PAnsiChar;
                end;

var
  IsWinNT     : boolean = true;    {Default: use Win32 functions, hardware if Win9x detected}

var
  ScreenWidth : integer = 0;       {current width of screen}
  ScreenHeight: integer = 0;       {current height of screen}
  NormalAttr  : byte    = $07;     {attribute for NormVideo}
  Orig_C      : COORD;             {original screen size}
  MaxLines    : integer = 50;      {Number of lines for Font8x8}

var
  InputHandle : THandle = INVALID_HANDLE_VALUE;  {handle for CRT input}
  OutputHandle: THandle = INVALID_HANDLE_VALUE;  {handle for CRT output}

var
  WMax        : T2Bytes absolute WindMax;
  WMin        : T2Bytes absolute WindMin;


{---------------------------------------------------------------------------}
procedure NormalizeCursor;
  {-Set cursor info, work around for a randomly disappearing }
  { cursor after mode set / clear screen}
var
  Info: CONSOLE_CURSOR_INFO;
begin
  SetConsoleCursorInfo(OutputHandle, Info);
  if Info.dwSize=0 then Info.dwSize := 25
  else if Info.dwSize<15 then Info.dwSize := 15
  else if Info.dwSize>99 then Info.dwSize := 99;
  Info.bVisible := True;
  SetConsoleCursorInfo(OutputHandle, Info);
end;


{---------------------------------------------------------------------------}
procedure SetNewMode(NewMode: integer);
 {-Set new text mode}
var
  C: COORD;
  R: SMALL_RECT;
begin
  if NewMode=Init_Mode then C := Orig_C
  else begin
    if NewMode=Last_Mode then NewMode := LastMode;
    if NewMode and Font8x8 <> 0 then C.Y := MaxLines else C.Y := 25;
    if (NewMode and $FF) in [CO40, BW40] then C.X :=40 else C.X := 80;
  end;
  R.Left := 0;
  R.Top := 0;
  R.Right := C.X - 1;
  R.Bottom := C.Y - 1;
  {Double SetConsoleScreenBufferSize seems sometimes necessary!}
  SetConsoleScreenBufferSize(OutputHandle, C);
  if not SetConsoleWindowInfo(OutputHandle, true, R) then exit;
  if SetConsoleScreenBufferSize(OutputHandle, C) then begin
    ScreenWidth := C.X;
    ScreenHeight := C.Y;
    WMin.X := 0;
    WMin.Y := 0;
    WMax.X := ScreenWidth - 1;
    WMax.Y := ScreenHeight - 1;
    LastMode := NewMode;
  end;
end;


{---------------------------------------------------------------------------}
function CtrlHandlerRoutine(dwCtrlType: DWORD): BOOL; stdcall;
  {-Console CTRL+C / CTRL+BREAK handler routine}
begin
  Result := false;
  case dwCtrlType of
    CTRL_CLOSE_EVENT,
    CTRL_BREAK_EVENT,
        CTRL_C_EVENT: begin
                        Result := true;
                        if IsConsole and CheckBreak then halt;
                      end;
  end;
end;



{---------------------------------------------------------------------------}
procedure InitVideo;
  {-Get console buffer/window info; initialize internal variables for current mode}
var
  Info: CONSOLE_SCREEN_BUFFER_INFO;
  C: COORD;
begin
  {Get initial screen info}
  if GetConsoleScreenBufferInfo(OutputHandle, Info) then begin
    {save original screen size}
    Orig_C := info.dwSize;
    NormalAttr := Info.wAttributes;
    TextAttr := Info.wAttributes;
    ScreenWidth := Info.dwSize.X;
    ScreenHeight := Info.dwSize.Y;
  end;

  {Get number of lines for Font8x8}
  C := GetLargestConsoleWindowSize(OutputHandle);
  if C.Y <= 43 then MaxLines := 43 else MaxLines := 50;

  {Always assume color modes for Win32}
  if ScreenWidth<=40 then LastMode := CO40 else LastMode := CO80;
  if ScreenHeight>25 then LastMode := LastMode or Font8x8;

  {Set legacy variables}
  CheckSnow := false;
  DirectVideo := true;

  {Set WindMin/Windmax}
  WMin.X := 0;
  WMin.Y := 0;
  WMax.X := ScreenWidth - 1;
  WMax.Y := ScreenHeight - 1;

  if (ScreenWidth>255) or (ScreenHeight>255) then begin
    {Paranoia: Make sure screen dimensions fit into bytes}
    SetNewMode(LastMode);
  end;
end;


{---------------------------------------------------------------------------}
procedure MoveCursor(X, Y: word);
  {-Move cursor  to X/Y position  (internal)}
var
  C: COORD;
begin
  C.X := X;
  C.Y := Y;
  SetConsoleCursorPosition(OutputHandle, C);
end;


{---------------------------------------------------------------------------}
procedure Scroll(Dir: TScrollDir; X1, Y1, X2, Y2, NumLines: smallint);
  {-Scroll a given area by NumLines, clear if NumLines=0}
var
  Fill: CHAR_INFO;
  R: SMALL_RECT;
  C: COORD;
begin
  Fill.AsciiChar := ' ';
  Fill.Attributes := TextAttr;
  if NumLines=0 then NumLines := Y2 - Y1 + 1;
  R.Left := X1;
  R.Top := Y1;
  R.Right := X2;
  R.Bottom := Y2;
  C.X := X1;
  if Dir=UP then C.Y := Y1 - NumLines
  else C.Y := Y1 + NumLines;
  ScrollConsoleScreenBufferA(OutputHandle, R, @R, C, Fill);
end;


{---------------------------------------------------------------------------}
procedure GetCursorPosXY(var cx,cy: integer);
  {-get cursor X/Y positions  (internal)}
var
  Info: CONSOLE_SCREEN_BUFFER_INFO;
begin
  if GetConsoleScreenBufferInfo(OutputHandle, Info) then begin
    cx := Info.dwCursorPosition.X;
    cy := Info.dwCursorPosition.Y;
  end
  else begin
    cx := 0;
    cy := 0;
  end
end;


{---------------------------------------------------------------------------}
function CursorPosX: integer;
  {-get cursor X position  (internal)}
var
  dummy: integer;
begin
  GetCursorPosXY(Result, dummy);
end;


{---------------------------------------------------------------------------}
function CursorPosY: integer;
  {-get cursor Y position  (internal)}
var
  dummy: integer;
begin
  GetCursorPosXY(dummy, Result);
end;


{---------------------------------------------------------------------------}
function CrtClose(var f: TTextRec): integer;
  {Close input/output, ie remove association of f with CRT}
begin
  CloseHandle(f.Handle);
  fillchar(f, sizeof(f), 0);
  f.Handle := integer(INVALID_HANDLE_VALUE);
  f.Mode := fmClosed;
  Result := 0;
end;


{---------------------------------------------------------------------------}
function CrtInput(var f: TTextRec): integer;
  {-CRT line input. read up to f.BufSize characters into f.BufPtr^}
var
  BufMax: cardinal;
  ch: AnsiChar;

  {---------------------------------------------------}
  procedure DoBackSpace;
    {-Do one Backspace and replace with space}
  begin
     if f.BufEnd > 0 then begin
       write(#8' '#8);
       dec(f.BufEnd);
     end;
  end;

  {---------------------------------------------------}
  procedure DoEnter;
    {-Perform Enter function, insert additional LineFeed}
  begin
    f.BufPtr[f.BufEnd] := #13;
    inc(f.BufEnd);
    if f.BufEnd + 1 < f.BufSize then begin
      f.BufPtr[f.BufEnd] := #10;
      inc(f.BufEnd);
    end;
    write(#13#10);
  end;

  {---------------------------------------------------}
  procedure DoRecover;
    {-"Recover" a previously erased char}
  begin
    if f.BufEnd < BufMax then begin
      write(f.BufPtr[f.BufEnd]);
      inc(f.BufEnd);
    end;
  end;

begin
  {CrtInput reads up to BufSize characters into BufPtr^, and returns the number}
  {of characters read in BufEnd. In addition, it stores zero in BufPos. If the}
  {CrtInput function returns zero in BufEnd as a result of an input request, Eof}
  {becomes true for the file.}
  f.BufPos := 0;
  f.BufEnd := 0;
  BufMax   := 0;
  while f.BufEnd < f.BufSize do begin
    ch := readkey;
    case ch of
         #0:  begin
                if ReadKey=#28 then begin
                  {Numpad Enter}
                  f.BufPtr[f.BufEnd] := #13;
                  DoEnter;
                  break;
                end;
              end;
    #1..#31:  begin
                {ASCII ctrl chars}
                case ch of
                   #27,
                    ^A: while f.BufEnd > 0 do DoBackSpace;
                    ^H: DoBackSpace;
                    ^D: DoRecover;
                    ^F: while f.BufEnd < BufMax do DoRecover;
                    ^M: begin
                          DoEnter;
                          break;
                        end;
                    ^S: DoBackSpace;
                    ^Z: if CheckEOF then begin
                          inc(f.BufEnd);
                          break;
                        end;
                  else  {drop!}
                end;
              end;
         else begin
                f.BufPtr[f.BufEnd] := ch;
                write(ch);
                inc(f.BufEnd);
                {Update max. BufMax}
                if f.BufEnd>BufMax then BufMax := f.BufEnd;
              end;
       end;
  end;
  Result := 0;
end;



{---------------------------------------------------------------------------}
function CrtInFlush(var f: TTextRec): integer;
  {-called at the end of each Read, Readln}
begin
  Result := 0;
end;



{ Internal Output Functions }
{---------------------------------------------------------------------------}
function CrtOutput(var f: TTextRec): integer;
  {-write BufPos characters from BufPtr^,}
var
  S: TStringInfo;
  Hidden: boolean;

const
  MAX_CELLS = 64;     { C++ RTL defined this as 32}

  procedure Flush(var S: TStringInfo);
    {-Flush a string of characters to screen}
  var
    i, Len: integer;
    Size, C: COORD;
    Region: SMALL_RECT;
    Cells: packed array[0..MAX_CELLS-1] of CHAR_INFO;
  begin
    Len := S.SEnd - S.SStart;
    if Len=0 then exit;
    for i:=0 to Len-1 do begin
      Cells[i].AsciiChar := S.SStart[i];
      Cells[i].Attributes := TextAttr;
    end;
    Size.X := Len;
    Size.Y := 1;
    C.X := 0;
    C.Y := 0;
    Region.Left := S.X - Len;
    Region.Right := S.X - 1;
    Region.Top := S.Y;
    Region.Bottom := Region.Top;
    WriteConsoleOutputA(OutputHandle, @Cells[0], Size, C, Region);
    S.SStart := S.SEnd;
  end;

begin
  GetCursorPosXY(S.X, S.Y);
  S.SStart := f.BufPtr;
  S.SEnd := f.BufPtr;

  {write BufPos characters from BufPtr^, and return zero in BufPos}
  while f.BufPos > 0 do begin
    dec(f.BufPos);
    Hidden := true;
    case S.SEnd[0] of
      #7: begin
            Flush(S);
            MessageBeep(0);
          end;
      #8: begin
            Flush(S);
            if S.X > WMin.X then dec(S.X);
          end;
     #10: begin
            Flush(S);
            inc(S.Y);
          end;
     #13: begin
            Flush(S);
            S.X := WMin.X;
          end;
     else begin
            Hidden := false;
            inc(S.X);
          end;
    end;
    inc(S.SEnd);
    if Hidden then S.SStart := S.SEnd;
    if S.SEnd-S.SStart >= MAX_CELLS then Flush(S);
    if S.X > WMax.X then begin
      Flush(S);
      S.X := WMin.X;
      inc(S.Y);
    end;
    if S.Y > WMax.Y then begin
      Flush(S);
      Scroll(UP, WMin.X, WMin.Y, WMax.X, WMax.Y, 1);
      dec(S.Y);
    end;
  end;

  Flush(S);
  MoveCursor(S.X, S.Y);
  Result := 0;
end;


{---------------------------------------------------------------------------}
function CrtOpen(var f: TTextRec): integer;
  {-Prepare f for input or output according to the f.Mode value}
var
  Info: CONSOLE_SCREEN_BUFFER_INFO;
begin
  Result := 0;
  {The CreateFile function enables a process to get a handle of its console's}
  {input buffer and active screen buffer, even if STDIN and STDOUT have been}
  {redirected. To open a handle of a console's input buffer, specify the CONIN$}
  {value in a call to CreateFile. Specify the CONOUT$ value in a call to}
  {CreateFile to open a handle of a console's active screen buffer.}
  case f.Mode of
    fmInput: begin
               InputHandle := CreateFile('CONIN$', GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING, 0, 0);
               f.Handle := InputHandle;
               f.Mode := fmInput;
               if f.BufPtr=nil then begin
                 f.BufPtr := @f.Buffer;
                 f.BufSize := sizeof(f.Buffer)
               end;
               SetConsoleMode(f.Handle, 0);
               SetConsoleCtrlHandler(@CtrlHandlerRoutine, true);
               f.InOutFunc := @CrtInput;
               f.FlushFunc := @CrtInFlush;
               f.CloseFunc := @CrtClose;
               {$ifdef TXTREC_CP}
                 if f.CodePage = 0 then begin
                   if GetFileType(f.Handle)=FILE_TYPE_CHAR then begin
                     {f.Mode=fmInput}
                     f.CodePage := GetConsoleCP
                   end
                   else f.CodePage := DefaultSystemCodePage;
                 end;
                 f.MBCSLength := 0;
                 f.MBCSBufPos := 0;
               {$endif}
             end;
     fmInOut,
     fmOutput: begin
               OutputHandle := CreateFile('CONOUT$', GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING, 0, 0);
               {$ifdef D6PLUS}
                 {Delphi 6 and above default to LF-only line breaks}
                 f.Mode := fmClosed;
                 SetLineBreakStyle(text(f), tlbsCRLF);
               {$endif}
               f.Handle := OutputHandle;
               f.Mode := fmOutput;
               if f.BufPtr=nil then begin
                 f.BufPtr := @f.Buffer;
                 f.BufSize := sizeof(f.Buffer)
               end;
               InitVideo;
               if (GetConsoleScreenBufferInfo(f.Handle, Info)) then begin
                 SetConsoleMode(f.Handle, 0);
                 f.InOutFunc := @CrtOutput;
                 f.FlushFunc := @CrtOutput;
                 f.CloseFunc := @CrtClose;
                 {$ifdef TXTREC_CP}
                   if f.CodePage = 0 then begin
                     if GetFileType(f.Handle) = FILE_TYPE_CHAR then begin
                       {f.Mode=fmOutput}
                       f.CodePage := GetConsoleOutputCP
                     end
                     else f.CodePage := DefaultSystemCodePage;
                   end;
                   f.MBCSLength := 0;
                   f.MBCSBufPos := 0;
                 {$endif}
               end
               else begin
                 Result := GetLastError;
               end;
             end;
  end; {case}
end;


{---------------------------------------------------------------------------}
procedure AssignCrt(var f: text);
  {-Associate the console with text file f}
begin
  with TTextRec(f) do begin
    Mode := fmClosed;
    BufSize := sizeof(Buffer);
    BufPtr := @Buffer;
    OpenFunc := @CrtOpen;
    InOutFunc := nil;
    FlushFunc := nil;
    CloseFunc := nil;
    fillchar(Name, sizeof(Name), 0);
  end;
end;


{---------------------------------------------------------------------------}
procedure ClrEol;
  {-Clears all the chars from the cursor position to the end of the line}
var
  C: COORD;
  CX, CY: integer;
  Len, NumWritten: DWORD;
begin
  GetCursorPosXY(CX, CY);
  if WMax.X > CX then begin
    C.X := CX;
    C.Y := CY;
    Len := WMax.X - C.X + 1;
    FillConsoleOutputCharacter(OutputHandle, ' ', Len, C, NumWritten);
    FillConsoleOutputAttribute(OutputHandle, TextAttr, Len, C, NumWritten);
  end;
end;


{---------------------------------------------------------------------------}
procedure ClrScr;
  {-Clear the current window, screen if no window set}
var
  C: COORD;
  i: integer;
  Len, NumWritten: DWORD;
begin
  if (WMin.X=0) and (WMin.Y=0) and (WMax.X=ScreenWidth-1) and (WMax.Y=ScreenHeight-1) then begin
    Len := ScreenWidth * ScreenHeight;
    C.X := 0;
    C.Y := 0;
    FillConsoleOutputCharacter(OutputHandle, ' ', Len, C, NumWritten);
    FillConsoleOutputAttribute(OutputHandle, TextAttr, Len, C, NumWritten);
  end
  else begin
    Len := WMax.X - WMin.X + 1;
    C.X := WMin.X;
    for i:=WMin.Y to WMax.Y do begin
      C.Y := i;
      FillConsoleOutputCharacter(OutputHandle, ' ', Len, C, NumWritten);
      FillConsoleOutputAttribute(OutputHandle, TextAttr, Len, C, NumWritten);
    end;
  end;
  GotoXY(1, 1);
  NormalizeCursor;
end;


{---------------------------------------------------------------------------}
procedure Delay(MS: word);
  {-Delay/Sleep for MS milliseconds}
begin
  Sleep(MS);
end;


{---------------------------------------------------------------------------}
procedure DelLine;
  {-Return true if a character producing key has been pressed}
begin
  Scroll(UP, WMin.X, CursorPosY, WMax.X, WMax.Y, 1);
end;


{---------------------------------------------------------------------------}
procedure GotoXY(X, Y: byte);
  {-Move cursor to col X, row Y (window relative)}
var
  R, C: integer;
begin
  R := integer(Y)-1 + WMin.Y;
  C := integer(X)-1 + WMin.X;
  if (R<WMin.Y) or (R>WMax.Y) or (C<WMin.X) or (C>WMax.X) then exit;
  MoveCursor(C, R);
end;


{---------------------------------------------------------------------------}
procedure HighVideo;
  {-Set high intensity forground}
begin
  TextAttr := TextAttr or $08;
end;


{---------------------------------------------------------------------------}
procedure InsLine;
  {-Insert new line at cursor position}
begin
  Scroll(DOWN, WMin.X, CursorPosY, WMax.X, WMax.Y, 1);
end;


{---------------------------------------------------------------------------}
procedure LowVideo;
  {-Set low intensity forground}
begin
  TextAttr := TextAttr and $77;
end;


{---------------------------------------------------------------------------}
procedure NormVideo;
  {-Set initial text attribute}
begin
  TextAttr := NormalAttr;
end;


{---------------------------------------------------------------------------}
procedure TextBackground(Color: byte);
  {-Set background color part if text attribute}
begin
  TextAttr := (TextAttr and $8F) or ((Color shl 4) and $7F);
end;


{---------------------------------------------------------------------------}
procedure TextColor(Color: byte);
  {-Set foreground color part if text attribute}
begin
  TextAttr := (TextAttr and $70) or (Color and $8F);
end;


{---------------------------------------------------------------------------}
procedure TextMode(Mode: integer);
  {-Set new text mode / NormalAttr and clrscr}
begin
  SetNewMode(Mode);
  TextAttr := NormalAttr;
  ClrScr;
end;


{---------------------------------------------------------------------------}
function WhereX: byte;
  {-Return current column of cursor (window relative)}
var
  diff: integer;
begin
  diff := CursorPosX - WMin.X + 1;
  if diff<0 then diff := 0;
  if diff>255 then diff := 255;
  Result := byte(diff);
end;


{---------------------------------------------------------------------------}
function WhereY: byte;
  {-Return current row of cursor (window relative)}
var
  diff: integer;
begin
  diff := CursorPosY - WMin.Y + 1;
  if diff<0 then diff := 0;
  if diff>255 then diff := 255;
  Result := byte(diff);
end;


{---------------------------------------------------------------------------}
procedure Window(X1, Y1, X2, Y2: byte);
  {-Define screen area as net text window}
begin
  if (X1<1) or (X2>ScreenWidth) or (Y1<1) or (Y2>ScreenHeight) or (X2<=X1) or (Y2<=Y1) then exit;
  WMin.X := X1-1;
  WMax.X := X2-1;
  WMin.Y := Y1-1;
  WMax.Y := Y2-1;
  MoveCursor(WMin.X, WMin.Y);
end;


{---------------------------------------------------------------------------}
procedure InitCRT;
  {-initialize Input/Output for CRT, see Delphi 2 notes in initialization}
var
  OSVersionInfo: TOSVersionInfo;
begin
  OSVersionInfo.dwOSVersionInfoSize := sizeof(OSVersionInfo);
  {Get OS Version used for hardware sound if not NT+}
  if GetVersionEx(OSVersionInfo) then IsWinNT := OSVersionInfo.dwPlatformId = VER_PLATFORM_WIN32_NT;
  {Paranoia: detect version / alignment conflicts}
  if sizeof(TTextRec)=sizeof(text) then begin
    AssignCrt(Input);
    reset(Input);
    AssignCrt(Output);
    rewrite(Output);
  end
  else CheckBreak := false;
end;


{---------------------------------------------------------------------------}
{----------------------------- Sound ---------------------------------------}
{---------------------------------------------------------------------------}


{---------------------------------------------------------------------------}
procedure Sound(Hz: word);
  {-Sound on, hardware for Win9x / MesseageBeep(0) for NT+}
begin
{$ifdef WIN32}
  if IsWinNT then begin
    {Because Beep(. , .) acts synchronous and waits there is no}
    {simple compatible Sound procedure, use lame MessageBeep(0)}
    MessageBeep(0);
  end
  else asm
        mov  cx,[Hz]
        cmp  cx,37
        jb   @2
        mov  ax,$34dd
        mov  dx,$0012
        div  cx
        mov  cx,ax
        in   al,$61
        test al,$03
        jnz  @1
        or   al,03
        out  $61,al
        mov  al,$b6
        out  $43,al
    @1: mov  al,cl
        out  $42,al
        mov  al,ch
        out  $42,al
    @2:
  end;
{$else}
   {$ifdef WIN64}
      MessageBeep(0);
   {$endif}
{$endif}
end;


{---------------------------------------------------------------------------}
procedure NoSound;
  {-Sound off, hardware for Win9x, dummy for NT+}
begin
 {$ifdef WIN32}
  if IsWinNT then {nothing because Sound uses MessageBeep(0)}
  else asm
     in   al,$61
     and  al,$fc
     out  $61,al
  end;
 {$endif}
end;



{---------------------------------------------------------------------------}
{-----------------------  Readkey / Keypressed  ----------------------------}
{---------------------------------------------------------------------------}

var
  ScanCode : byte;            {Current code for keypressed}
  ExtSCode : boolean;         {Current key press produced extended code}
  InAltNum : boolean;         {In Alt+Numpad entry mode}
  AltNumVal: byte;            {Accumulated Alt+Numpad code}


 {---------------------------------------------------------------------------}
function KeyPressed : boolean;
  {-Return true if a character producing key is pressed}
var
  NumEvents,NumRead : dword;
  InputRec : INPUT_RECORD;
  IsAlt, IsCtrl, IsShift: boolean;
  nc: integer;
const
  No_Keys = [VK_SHIFT, VK_MENU {=Alt}, VK_CONTROL, VK_CAPITAL{=Caps}, VK_NUMLOCK, VK_SCROLL];
  NumNum : array[$47..$53] of byte = (7,8,9,$FF,4,5,6,$FF,1,2,3,0,$FF);
  CtrlNum: array[$47..$53] of byte = ($77, $8D, $84, $8E, $73, $8F, $74, $4E, $75, $91, $76, $92, $93);
begin
  if ScanCode<>0 then begin
    Result := true;
    exit;
  end;
  Result := false;
  repeat
    GetNumberOfConsoleInputEvents(InputHandle,NumEvents);
    if NumEvents=0 then break;
    ReadConsoleInputA(InputHandle,InputRec,1,NumRead);
    if (NumRead>0) and (InputRec.EventType=KEY_EVENT) then with InputRec.Event.KeyEvent do begin
      if bKeyDown then begin
        IsAlt   := dwControlKeyState and (RIGHT_ALT_PRESSED or LEFT_ALT_PRESSED) <> 0;
        IsCtrl  := dwControlKeyState and (RIGHT_CTRL_PRESSED or LEFT_CTRL_PRESSED) <> 0;
        IsShift := dwControlKeyState and SHIFT_PRESSED <> 0;
        {Consider potential character producing keys}
        if not (wVirtualKeyCode in No_Keys) then begin
          Result:=true;
          //writeln(wVirtualScanCode:5, wVirtualKeyCode:5, ord(AsciiChar):5);
          if (AsciiChar=#0) or (dwControlKeyState and (LEFT_ALT_PRESSED or ENHANCED_KEY) <> 0) then begin
            {Real extended keys or Alt/Cursor block}
            ExtSCode := true;
            if (wVirtualScanCode=$37) and (dwControlKeyState and ENHANCED_KEY <> 0) then begin
              {Ctrl-PrtScr}
              if wVirtualScanCode=$37 then ScanCode := 114;
            end
            else begin
              if wVirtualScanCode in [1,2,4,5,6,8,9,10,11,13] then begin
                {Only Ctrl+2 (VSC=3) and Ctrl+6 (VSC=7) generate key codes}
                Result := false;
                ExtSCode := false;
                ScanCode := 0;
              end
              else begin
                {-Convert VirtualScanCode to CRT Scancode}
                Scancode := wVirtualScanCode;
                if IsAlt then begin
                  case ScanCode of
                    $02..$0D: inc(ScanCode, $76);  {Digits  .. BS}
                         $1C: Scancode := $A6;     {Enter}
                         $35: Scancode := $A4;     {/}
                    $3B..$44: inc(Scancode, $2D);  {F1 - F10}
                    $47..$49,
                    $4B, $4D,
                    $4F..$53: inc(Scancode, $50);  {Extended cursor block keys}
                    $57..$58: inc(Scancode, $34);  {F11, F12}
                  end
                end
                else if IsCtrl then begin
                  case Scancode of
                         $07: ScanCode := $1E;
                         $0C: ScanCode := $1F;
                         $0F: Scancode := $94;    {Tab}
                         $35: Scancode := $95;    {Keypad \}
                         $37: Scancode := $96;    {Keypad *}
                    $3B..$44: inc(Scancode, $23); {F1 - F10}
                    $47..$53: Scancode := CtrlNum[Scancode];  {Keypad num keys}
                    $57..$58: inc(Scancode, $32); {F1 - F10}
                  end
                end
                else if IsShift then begin
                  case Scancode of
                    $3B..$44: inc(Scancode, $19); {F1 - F10}
                    $57..$58: inc(Scancode, $30); {F1 - F10}
                  end
                end
                else begin
                  case Scancode of
                    $57..$58: inc(Scancode, $2E); {F1 - F10}
                  {$ifdef CRTFix_01}
                    $29: begin
                           {Some Windows/keyboards declare ^ as Extended}
                           ExtSCode := false;
                           AsciiChar:= '^';
                           ScanCode := byte(AsciiChar);              
                         end;
                   {$endif}
                  end;
                end;
                if (AsciiChar='/') and (not IsAlt) then begin
                  {Windows declares Numpad-/ as Extended}
                  ScanCode := 47;
                  ExtSCode := false;
                end;
              end;
            end;
          end
          else begin
            {redeclare some of the keys as extended}
            if (AsciiChar=#9) and IsShift then begin
              {shift-tab }
              ExtSCode := true;
              ScanCode := 15;
            end
            else if (AsciiChar=#240) and (dwControlKeyState=0) then begin
              {Numpad 5}
              ExtSCode := true;
              ScanCode := 76;
            end
            else begin
              ExtSCode := false;
              ScanCode := byte(AsciiChar);
            end;
          end;
          if IsAlt and (dwControlKeyState and ENHANCED_KEY = 0) then begin
            {Alt pressed and no ENHANCED_KEY, gather AltNum code}
            if wVirtualScanCode in [$47..$52] then begin
              nc := NumNum[wVirtualScanCode];
              if nc>9 then break
              else begin
                InAltNum := true;
                AltNumVal := (10*AltNumVal + nc) and $FF;
                Result := false;
                ExtSCode := false;
                ScanCode := 0;
              end;
            end
            else exit;
          end
          else exit;
        end;
      end
      else begin
        {Process Key UP: finish AltNum entry if ALT=VK_Menu is released}
        if (wVirtualKeyCode=VK_MENU) and InAltNum and (AltNumVal>0) then begin
          ScanCode := AltNumVal;
          Result := true;
          InAltNum := false;
          AltNumVal := 0;
          exit;
        end;
      end;
    end;
    if Result then exit;
  until false;
end;


{---------------------------------------------------------------------------}
function ReadKey: AnsiChar;
  {-Read a character from the keyboard, sleep until keypressed}
begin
  while not KeyPressed do sleep(1);
  if ExtSCode then begin
    {Extended code: first return #0 and (with a second call) the char code}
    Result := #0;
    ExtSCode := false;
  end
  else begin
    Result := AnsiChar(ScanCode);
    ScanCode := 0;
  end;
end;


begin
  { This initialization code does not work as expected in Delphi 2.  In D2,
    IsConsole appears to be always false even if $APPTYPE is set to CONSOLE in
    the main project file. }
  {*we: IsConsole is true after begin in main program, so InitCrt}
  {    should be called again in the main program}
  {$ifdef VER90}
    InitCRT;
  {$endif}
  if IsConsole then InitCRT;
end.

