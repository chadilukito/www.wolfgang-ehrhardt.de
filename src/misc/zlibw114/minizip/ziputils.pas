unit ziputils;

(************************************************************************

ziputils.pas - IO on .zip files using zlib
  - definitions, declarations and routines used by both
    zip.pas and unzip.pas
    The file IO is implemented here.

  based on work by Gilles Vollant

  March 23th, 2000,
  Copyright (C) 2000 Jacques Nomssi Nzali}

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:

  Feb 2002
    - Source code reformating/reordering
    - global {$I-}
  Mar 2005
    - VER70: check MaxAvail
  Jul 2009
    - D12 fixes
  ------------------------------------------------------------------------

*************************************************************************)

{$i-}
{$x+}

interface

{$undef UseStream}
{$ifdef WIN32}
  {$define Delphi}
  {$ifdef UseStream}
    {$define Streams}
  {$endif}
{$endif}

uses
  {$ifdef Delphi}
    SysUtils,
  {$endif}
  ZLibH, ZLib;

{$ifdef Streams}
type
  FILEptr = TFileStream;
{$else}
type
  FILEptr = ^file;
{$endif}

type
  seek_mode = (SEEK_SET, SEEK_CUR, SEEK_END);
  open_mode = (fopenread, fopenwrite, fappendwrite);

function  fopen(filename: PChar8; mode: open_mode): FILEptr;

procedure fclose(fp: FILEptr);

function  fseek(fp: FILEptr; recPos: uLong; mode: seek_mode): int;

function  fread(buf: voidp; recSize, recCount: uInt; fp: FILEptr): uInt;

function  fwrite(buf: voidp; recSize, recCount: uInt; fp: FILEptr): uInt;

function  ftell(fp: FILEptr): uLong;

function  feof(fp: FILEptr): uInt;

{-------------------------------------------------------------------}

type
  zipFile = voidp;
  unzFile = voidp;

type
  z_off_t = long;

type
  tm_zip = record           {tm_zip contain date/time info}
             tm_sec : uInt; {seconds after the minute - [0,59]}
             tm_min : uInt; {minutes after the hour - [0,59]}
             tm_hour: uInt; {hours since midnight - [0,23]}
             tm_mday: uInt; {day of the month - [1,31]}
             tm_mon : uInt; {months since January - [0,11]}
             tm_year: uInt; {years - [1980..2044]}
           end;

  tm_unz = tm_zip;

const
  Z_BUFSIZE = (16384);
  Z_MAXFILENAMEINZIP = (256);

const
  CENTRALHEADERMAGIC = $02014b50;

const
  SIZECENTRALDIRITEM = $2e;
  SIZEZIPLOCALHEADER = $1e;

function ALLOC(size: int): voidp;

procedure TRYFREE(p: voidp);

const
  Paszip_copyright: PChar8 = ' Paszip Copyright 2000 Jacques Nomssi Nzali ';

implementation


{---------------------------------------------------------------------------}
function ALLOC(size: int): voidp;
begin
  ALLOC := zcalloc(nil, size, 1);
end;

{---------------------------------------------------------------------------}
procedure TRYFREE(p: voidp);
begin
  if Assigned(p) then zcfree(nil, p);
end;

{$ifdef Streams}

{----------------------------------------------------------------}
function fopen(filename: PChar8; mode: open_mode): FILEptr;
var
  fp: FILEptr;
begin
  fp := nil;
  try
    case mode of
       fopenread: fp := TFileStream.Create(filename, fmOpenRead);
      fopenwrite: fp := TFileStream.Create(filename, fmCreate);
    fappendwrite: begin
                    fp := TFileStream.Create(filename, fmOpenReadWrite);
                    fp.Seek(soFromEnd, 0);
                  end;
    end;
  except
    on EFOpenError do fp := nil;
  end;
  fopen := fp;
end;

{---------------------------------------------------------------------------}
procedure fclose(fp: FILEptr);
begin
  fp.Free;
end;


{---------------------------------------------------------------------------}
function  fread(buf: voidp; recSize, recCount: uInt; fp: FILEptr): uInt;
var
  totalSize, readcount: uInt;
begin
  if Assigned(buf) then begin
    totalSize := recCount * uInt(recSize);
    readCount := fp.read(buf^, totalSize);
    if readcount<>totalSize) then fread := readcount div recSize
    else fread := recCount;
  end
  else fread := 0;
end;


{---------------------------------------------------------------------------}
function fwrite(buf: voidp; recSize, recCount: uInt; fp: FILEptr): uInt;
var
  totalSize, written: uInt;
begin
  if Assigned(buf) then begin
    totalSize := recCount * uInt(recSize);
    written := fp.write(buf^, totalSize);
    if written<>totalSize then fwrite := written div recSize
    else fwrite := recCount;
  end
  else fwrite := 0;
end;

{---------------------------------------------------------------------------}
function fseek(fp: FILEptr; recPos: uLong; mode: seek_mode): int;
const
  fsmode: array[seek_mode] of word = (soFromBeginning, soFromCurrent, soFromEnd);
begin
  fp.Seek(recPos, fsmode[mode]);
  fseek := 0; {= 0 for success}
end;

{---------------------------------------------------------------------------}
function ftell(fp: FILEptr): uLong;
begin
  ftell := fp.Position;
end;

{---------------------------------------------------------------------------}
function feof(fp: FILEptr): uInt;
begin
  feof := 0;
  if Assigned(fp) then begin
    if fp.Position=fp.Size then feof := 1 else feof := 0;
  end;
end;

{$else}


{----------------------------------------------------------------}
function fopen(filename: PChar8; mode: open_mode): FILEptr;
var
  fp: FILEptr;
  OldFileMode: byte;
begin
  OldFileMode := FileMode;

  {$ifdef VER70}
    fp := nil;
    if sizeof(file)+16 > MaxAvail then exit;
  {$endif}

  GetMem(fp, sizeof(file));
  z_assign(fp^, filename);

  case mode of
     fopenread: begin
                  FileMode := 0;
                  reset(fp^, 1);
                end;
    fopenwrite: begin
                  FileMode := 1;
                  rewrite(fp^, 1);
                end;
  fappendwrite: begin
                  FileMode := 2;
                  reset(fp^, 1);
                  Seek(fp^, FileSize(fp^));
                end;
  end;

  FileMode := OldFileMode;

  if IOResult<>0 then begin
    FreeMem(fp, sizeof(file));
    fp := nil;
  end;

  fopen := fp;
end;

{---------------------------------------------------------------------------}
procedure fclose(fp: FILEptr);
begin
  if Assigned(fp) then begin
    system.close(fp^);
    if IOResult=0 then ;  {avoid InOutRes}
    FreeMem(fp, sizeof(file));
  end;
end;


{---------------------------------------------------------------------------}
function  fread(buf: voidp; recSize, recCount: uInt; fp: FILEptr): uInt;
var
  totalSize, readcount: uInt;
begin
  if Assigned(buf) then begin
    totalSize := recCount * uInt(recSize);
    system.blockread(fp^, buf^, totalSize, readcount);
    if readcount<>totalSize then fread := readcount div recSize
    else fread := recCount;
  end
  else fread := 0;
end;


{---------------------------------------------------------------------------}
function  fwrite(buf: voidp; recSize, recCount: uInt; fp: FILEptr): uInt;
var
  totalSize, written: uInt;
begin
  if Assigned(buf) then begin
    totalSize := recCount * uInt(recSize);
    system.blockwrite(fp^, buf^, totalSize, written);
    if written<>totalSize then fwrite := written div recSize
    else fwrite := recCount;
  end
  else fwrite := 0;
end;

{---------------------------------------------------------------------------}
function fseek(fp: FILEptr; recPos: uLong; mode: seek_mode): int;
begin
  case mode of
    SEEK_SET: Seek(fp^, recPos);
    SEEK_CUR: Seek(fp^, FilePos(fp^)+longint(recPos));
    SEEK_END: Seek(fp^, FileSize(fp^)-1-longint(recPos)); {?? check}
  end;
  fseek := IOResult; {= 0 for success}
end;

{---------------------------------------------------------------------------}
function ftell(fp: FILEptr): uLong;
begin
  ftell := FilePos(fp^);
end;

{---------------------------------------------------------------------------}
function feof(fp: FILEptr): uInt;
begin
  feof := 0;
  if Assigned(fp) then begin
    if eof(fp^) then feof := 1 else feof := 0;
  end;
end;

{$endif}


end.
