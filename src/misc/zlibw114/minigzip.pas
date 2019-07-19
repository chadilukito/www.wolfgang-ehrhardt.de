program minigzip;

(************************************************************************
 minigzip.c -- simulate gzip using the zlib compression library
 Copyright (C) 1995-1998 Jean-loup Gailly.

 minigzip is a minimal implementation of the gzip utility. This is
 only an example of using zlib and isn't meant to replace the
 full-featured gzip. No attempt is made to deal with file systems
 limiting names to 14 or 8+3 characters, etc... Error checking is
 very limited. So use minigzip only for testing; use gzip for the
 real thing. On MSDOS, use only on file names without extension
 or in pipe mode.

  Pascal translation based on code contributed by Francisco Javier Crespo
  Copyright (C) 1998 by Jacques Nomssi Nzali
  For conditions of distribution and use, see copyright notice in readme.txt

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:

  Feb 2002
    - global {$i-}
    - Reintroduced Z_OK
    - Erase infile after -d
    - option loop until ParamCount-1
    - source code reformating/reordering
  Mar 2005
    - Code cleanup for WWW upload
  Jul 2008
    - Replace two ioerr := IOResult to avoid warnungs
    - some typecasts for len
  Jul 2009
    - D12 fixes
  ------------------------------------------------------------------------

*************************************************************************)

{$ifdef WIN32}
  {$ifndef VirtualPascal}
    {$apptype console}
  {$endif}
{$endif}

{$ifdef WIN64}
  {$apptype console}
{$endif}


{$i-}

uses
  {$ifdef VER80}
    WinCrt,
  {$endif}
  gzio, ZLibH;

const
  BUFLEN       = 16384;
  GZ_SUFFIX    = '.gz';

{$define MAXSEG_64K}  {*we W0800, replace MAXSEF_64K}

var
  buf : packed array[0..BUFLEN-1] of byte; { Global uses BSS instead of stack }
  prog: str255;


{---------------------------------------------------------------------------}
procedure error(const msg: str255);
  {-Display error message and halt}
begin
  writeln(prog,': ',msg);
  halt(1);
end;


{---------------------------------------------------------------------------}
procedure gz_compress(var infile: file; outfile: gzFile);
  {-Compress input to output then close both files}
var
  len  : uInt;
  ioerr: integer;
  err  : int;
begin

  while true do begin
    blockread(infile, buf, BUFLEN, len);
    ioerr := IOResult;
    if ioerr<>0 then begin
      writeln('read error: ',ioerr);
      halt(1);
    end;
    if len=0 then break;
    if gzwrite(outfile, @buf, len)<>int(len) then error(gzerror(outfile, err)); {Jul 2008}
  end;

  if gzclose(outfile)<>Z_OK then error('gzclose error');
  close(infile);
  if IOResult<>0 then {??};   {Jul 2008}
end;



{---------------------------------------------------------------------------}
procedure gz_uncompress(infile: gzFile; var outfile: file);
  {-Uncompress input to output then close both files}
var
  len    : int;
  written: uInt;
  ioerr  : integer;
  err    : int;
begin
  while true do begin
    len := gzread(infile, @buf, BUFLEN);
    if len<0 then error(gzerror(infile, err));
    if len=0 then break;
    blockwrite(outfile, buf, len, written);
    if written<>uInt(len) then error('write error'); {Jul 2008}
  end;

  close(outfile);
  ioerr := IOResult;
  if ioerr<>0 then begin
    writeln('close error: ',ioerr);
    halt(1);
  end;

  if gzclose(infile)<>Z_OK then error('gzclose error');
end;



{---------------------------------------------------------------------------}
procedure file_compress(const filename, mode: str255);
  {-Compress the given file: create a corresponding .gz file and remove the original}
var
  infile : file;
  outfile: gzFile;
  ioerr  : integer;
  outname: str255;
begin
  system.assign(infile, {$ifdef unicode} string {$endif}(filename));
  reset(infile,1);
  ioerr := IOResult;
  if ioerr<>0 then begin
    writeln('open error: ',ioerr);
    halt(1);
  end;

  outname := filename + GZ_SUFFIX;
  outfile := gzopen(outname, mode);

  if outfile=nil then begin
    writeln(prog,': can''t gzopen ',outname);
    halt(1);
  end;

  gz_compress(infile, outfile);
  {*we: infile is closed}
  erase(infile);
  if IOResult<>0 then {??};  {Jul 2008}
end;


{---------------------------------------------------------------------------}
procedure file_uncompress(const filename: str255);
  {-Uncompress the given file and remove the original}
var
  infile : gzFile;
  outfile: file;
  ioerr  : integer;
  len    : integer;
  inname : str255;
  outname: str255;
begin
  len := length(filename);

  if copy(filename,len-2,3)=GZ_SUFFIX then begin
    inname := filename;
    outname := copy(filename,0,len-3);
  end
  else begin
    inname := filename + GZ_SUFFIX;
    outname := filename;
  end;

  infile := gzopen(inname, 'r');
  if infile=nil then begin
    writeln(prog,': can''t gzopen ',inname);
    halt(1);
  end;

  system.assign(outfile, {$ifdef unicode} string {$endif}(outname));
  rewrite(outfile,1);
  ioerr := IOResult;
  if ioerr<>0 then begin
    writeln('open error: ',ioerr);
    halt(1);
  end;

  gz_uncompress(infile, outfile);

  {*we: outfile is closed, renable erasing of infile}
  system.assign(outfile, {$ifdef unicode} string {$endif}(inname));
  erase(outfile);
  ioerr := IOResult;
  if ioerr<>0 then begin
    writeln(': can''t erase ',inname);
    halt(1);
  end;
end;


var
  uncompr: boolean;
  outmode: string[20];
  i      : integer;
  option : string[2];

begin
  uncompr := false;
  outmode := 'w6 ';
  prog := {$ifdef unicode} str255 {$endif}(paramstr(0));

  GZ_windowBits := 13;
  GZ_memLevel   := 6;

  if (ParamCount = 0) then begin
    writeln('Error: STDIO/STDOUT not supported yet');
    writeln;
    writeln('Usage:  minigzip [-d] [-f] [-h] [-1 to -9] <file>');
    writeln('  -d : decompress');
    writeln('  -f : compress with Z_FILTERED');
    writeln('  -h : compress with Z_HUFFMAN_ONLY');
    writeln('  -1 to -9 : compression level');
    exit;
  end;

  for i:=1 to ParamCount-1 do begin
    option := {$ifdef unicode} str255 {$endif}(paramstr(i));
    if (option = '-d') then uncompr := true;
    if (option = '-f') then outmode[3] := 'f';
    if (option = '-h') then outmode[3] := 'h';
    if (option[1] = '-') and (option[2] >= '1') and (option[2] <= '9') then outmode[2] := option[2];
  end;

  if uncompr then file_uncompress({$ifdef unicode} str255 {$endif}(ParamStr(ParamCount)))
  else file_compress({$ifdef unicode} str255 {$endif}(ParamStr(ParamCount)), outmode);
end.
