program MiniZip;

(************************************************************************
  minizip demo package by Gilles Vollant

  Usage : minizip [-o] file.zip [files_to_add]

  a file.zip file is created, all files listed in [files_to_add] are added
  to the new .zip file.
  -o an existing .zip file with be overwritten without warning

  Pascal translation
  Copyright (C) 2000 by Jacques Nomssi Nzali
  For conditions of distribution and use, see copyright notice in readme.txt

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:
  Feb 2002
    - Source code reformating/reordering
    - use Delphi32 Result variable
    - Use SysUtils/FileExists for Delphi/FPC, new code otherwise
    - global {$i-}
    - better help
    - Pascal style for paramstr and string input
  Apr 2004
    - use z_assign
  Aug 2005
    - FPC 2.0 fixes (other FPC no longer supported)
  Jul 2009
    - D12 fixes
  ------------------------------------------------------------------------

*************************************************************************)


{$ifdef FPC}
  {$ifdef VER1}
    {$FATAL Only for FPC V2+}
  {$endif}
{$endif}


{$ifdef WIN32}
  {$ifndef VirtualPascal}
    {$apptype console}
    {$define Delphi}
    {$ifndef FPC}
      {$define Delphi32}
      {$J+}
    {$endif}
  {$endif}
{$else}
  {$A+,B-,D+,E-,F+,G+,I-,L+,N-,P-,Q-,R-,S+,T-,V-,X+,Y+}
  {$M $F000,0,655360}
{$endif}

{$i-,x+}

uses
  {$ifdef Delphi}
    SysUtils, Windows,
  {$else}
    WinDos, strings,
  {$endif}
  ZLibH, ziputils, zip;

const
  WRITEBUFFERSIZE = Z_BUFSIZE;
  MAXFILENAME = Z_MAXFILENAMEINZIP;

{$ifdef Delphi32}

{$ifdef UNICODE}
{---------------------------------------------------------------------------}
function filetime(f: PChar8; var tmzip: tm_zip; var dt: uLong): uLong;
  {-get filetime of file f}
  {tmzip: return value: access, modific, creation times, dt: dostime}
var
  ftLocal: TFileTime;
  hFind: THandle;
  ff32: TWIN32FindData;
  s: widestring;
begin
  result := 0;
  dt := 0;
  s := widestring(f);
  hFind := FindFirstFile(PWideChar(s), ff32);
  if hFind<>INVALID_HANDLE_VALUE then begin
    FileTimeToLocalFileTime(ff32.ftLastWriteTime,ftLocal);
    FileTimeToDosDateTime(ftLocal,LongRec(dt).hi,LongRec(dt).lo);
    FindClose(hFind);
    result := 1;
  end;
end;
{$else}
{---------------------------------------------------------------------------}
function filetime(f: PChar8; var tmzip: tm_zip; var dt: uLong): uLong;
  {-get filetime of file f}
  {tmzip: return value: access, modific, creation times, dt: dostime}
var
  ftLocal: TFileTime;
  hFind: THandle;
  ff32: TWIN32FindData;
begin
  result := 0;
  dt := 0;
  hFind := FindFirstFile(f, ff32);
  if hFind<>INVALID_HANDLE_VALUE then begin
    FileTimeToLocalFileTime(ff32.ftLastWriteTime,ftLocal);
    FileTimeToDosDateTime(ftLocal,LongRec(dt).hi,LongRec(dt).lo);
    FindClose(hFind);
    result := 1;
  end;
end;
{$endif}


{$else}

{$ifdef FPC}
{---------------------------------------------------------------------------}
function filetime(f: PChar8; var tmzip: tm_zip; var dt: uLong): uLong;
  {-get filetime of file f}
  {tmzip: return value: access, modific, creation times, dt: dostime}
var
  ftLocal: TFileTime;
  hFind: THandle;
  ff32: TWIN32FindData;
begin
  filetime := 0;
  dt := 0;
  hFind := FindFirstFile(f, @ff32);
  if hFind<>INVALID_HANDLE_VALUE then begin
    FileTimeToLocalFileTime(ff32.ftLastWriteTime,ftLocal);        {FPC2 fix}
    FileTimeToDosDateTime(ftLocal,LongRec(dt).hi,LongRec(dt).lo); {FPC2 fix}
    FindClose(hFind);
    filetime := 1;
  end;
end;

{$else}

{---------------------------------------------------------------------------}
function filetime(f: PChar8; var tmzip: tm_zip; var dt: uLong): uLong;
  {-get filetime of file f}
  {tmzip: return value: access, modific, creation times, dt: dostime}
var
  fl: file;
  yy, mm, dd, dow: word;
  h, m, s, hund: word; {For GetTime}
  dtrec: TDateTime; {For Pack/UnpackTime}
begin
  z_assign(fl, f);
  reset(fl, 1);
  if IOResult = 0 then begin
    GetFTime(fl,dt); {Get creation time}
    UnpackTime(dt, dtrec);
    close(fl);
    InOutRes := 0;
    tmzip.tm_sec  := dtrec.sec;
    tmzip.tm_min  := dtrec.min;
    tmzip.tm_hour := dtrec.hour;
    tmzip.tm_mday := dtrec.day;
    tmzip.tm_mon  := dtrec.month;
    tmzip.tm_year := dtrec.year;
  end;
  filetime := 0;
end;


{---------------------------------------------------------------------------}
function FileExists(FName: PChar8): boolean;
  {-Test, file Fname exists}
var
  m: byte;
  f: file;
begin
  m := filemode;
  filemode := 0;
  z_assign(f, FName);
  reset(f,1);
  FileExists := IOResult=0;
  filemode := m;
end;

{$endif}
{$endif}


{---------------------------------------------------------------------------}
procedure do_banner;
begin
  writeln('MiniZip 0.15, demo package written by Gilles Vollant');
  writeln('Pascal port by Jacques Nomssi Nzali / W.Ehrhardt');
  writeln;
end;


{---------------------------------------------------------------------------}
procedure do_help;
begin
  writeln('Usage: minizip [-<n>] [-o] file.zip [files_to_add]');
  writeln('  <n>: compression level 0 .. 9, 0=store');
  writeln('   -o: overwrite existing zip file');
  writeln;
end;


{---------------------------------------------------------------------------}
function main: int;
var
  i: int;
  opt_overwrite: int;
  opt_compress_level: int;
  zipfilenamearg: int;
  zipok: int;
  err: int;
  size_buf: int;
  buf: voidp;
  c: char8;
  dot_found: int;
  zf: zipFile;
  errclose: int;
  fin: FILEptr;
  size_read: int;
  filenameinzip: PChar8;
  zi: zip_fileinfo;
  answer: char8;
  method: int;
  filename_try: array[0..MAXFILENAME-1] of char8;
  argstr: string[128];

begin
  opt_overwrite := 0;
  opt_compress_level := Z_DEFAULT_COMPRESSION;
  zipfilenamearg := 0;
  err := 0;
  main := 0;

  do_banner;
  if ParamCount=0 then begin
    do_help;
    main := 0;
    exit;
  end
  else begin
    for i:=1 to ParamCount do begin
      argstr := {$ifdef unicode} str255 {$endif} (ParamStr(i));
      if argstr[1]='-' then begin
        delete(argstr,1,1);
        if length(argstr)=1 then begin
          c := Upcase(argstr[1]);
	  if upcase(c)='O' then opt_overwrite := 1;
          if (c>='0') and (c<='9') then opt_compress_level := byte(c)-byte('0');
	end;
      end
      else if zipfilenamearg=0 then zipfilenamearg := i;
    end;
  end;

  size_buf := WRITEBUFFERSIZE;
  buf := ALLOC(size_buf);
  if buf=nil then begin
    writeln('Error allocating memory');
    main := ZIP_INTERNALERROR;
    exit;
  end;

  if zipfilenamearg=0 then zipok := 0
  else begin
    dot_found := 0;
    zipok := 1 ;
    argstr := {$ifdef unicode} str255 {$endif}(ParamStr(zipfilenamearg)) + #0;
    strcopy(filename_try, PChar8(@argstr[1]));
    for i:=0 to strlen(filename_try)-1 do begin
      if filename_try[i]='.' then dot_found := 1;
    end;
    if dot_found=0 then strcat(filename_try,'.zip');

    if (opt_overwrite=0) and FileExists( {$ifdef unicode} string {$endif}(filename_try)) then begin
      repeat
	writeln('The file ',filename_try, ' exist. Overwrite ? [y]es, [n]o: ');
	readln(answer);
	answer := Upcase(answer);
      until (answer='Y') or (answer='N');
      if answer='N' then zipok := 0;
    end;
  end;
  if opt_compress_level<>0 then method := Z_DEFLATED else method := 0;

  if zipok=1 then begin
    zf := zipOpen(filename_try,0);
    if zf=nil then begin
      writeln('error opening ', filename_try);
      err := ZIP_ERRNO;
    end
    else writeln('creating ',filename_try);

    i := zipfilenamearg+1;
    while (i<=ParamCount) and (err=ZIP_OK) do begin
      argstr :=  {$ifdef unicode} str255 {$endif}(ParamStr(i))+#0;
      if (argstr[1]<>'-') and (argstr[1]<>'/') then begin
        filenameinzip := PChar8(@argstr[1]);
        zi.tmz_date.tm_sec := 0;
        zi.tmz_date.tm_min := 0;
        zi.tmz_date.tm_hour := 0;
        zi.tmz_date.tm_mday := 0;
        zi.tmz_date.tm_min := 0;
        zi.tmz_date.tm_year := 0;
        zi.dosDate := 0;
        zi.internal_fa := 0;
        zi.external_fa := 0;
        filetime(filenameinzip,zi.tmz_date,zi.dosDate);
        err := zipOpenNewFileInZip(zf,filenameinzip,@zi,nil,0,nil,0,nil,method,opt_compress_level);
        if err<>ZIP_OK then writeln('error in opening ',filenameinzip,' in zipfile')
        else begin
          fin := fopen(filenameinzip, fopenread);
          if fin=nil then begin
            err := ZIP_ERRNO;
            writeln('error in opening ',filenameinzip,' for reading');
          end;

          if err=ZIP_OK then
          repeat
            err := ZIP_OK;
            size_read := fread(buf,1,size_buf,fin);
            if size_read<size_buf then begin
              if feof(fin)=0 then begin
                writeln('error in reading ',filenameinzip);
                err := ZIP_ERRNO;
              end;
            end;
            if size_read>0 then begin
              err := zipWriteInFileInZip (zf,buf,size_read);
              if (err<0) then writeln('error in writing ',filenameinzip,' in the zipfile');
            end;
          until (err <> ZIP_OK) or (size_read=0);

          fclose(fin);
        end;
        if err<0 then err := ZIP_ERRNO
        else begin
          err := zipCloseFileInZip(zf);
          if err<>ZIP_OK then writeln('error in closing ',filenameinzip,' in the zipfile');
        end;
        inc(i);
      end; {while}
    end; {if}

    errclose := zipClose(zf,nil);
    if errclose<>ZIP_OK then writeln('error in closing ',filename_try);
  end;

  TRYFREE(buf); {FreeMem(buf, size_buf);}
end;

begin
  main;
  write('Done...');
end.
