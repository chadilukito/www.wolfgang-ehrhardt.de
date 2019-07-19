program MiniUnz;

(************************************************************************
  mini unzip demo package by Gilles Vollant

  Usage : miniunz [-exvlo] file.zip [file_to_extract]

  -l or -v list the content of the zipfile.
        -x extract a specific file or all files if [file_to_extract] is missing
        -e like -x, but extract without path information
        -o overwrite an existing file without warning

  Pascal tranlastion
  Copyright (C) 2000 by Jacques Nomssi Nzali
  for conditions of distribution and use, see copyright notice in readme.txt

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:

  Feb 2002
    - Source code reformating/reordering
    - global {$I-}
    - some pascal string style changes
    - fixed description of -x/-e options
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
    {$FATAL Only for FPC V2}
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
  zlibH, zlib, ziputils,
  unzip;

const
  CASESENSITIVITY = 0;
  WRITEBUFFERSIZE = 8192;


{change_file_date : change the date/time of a file
    filename : the filename of the file where date/time must be modified
    dosdate : the new date at the MSDos format (4 bytes)
    tmu_date : the SAME new date at the tm_unz format}

{$ifdef Delphi32}

{$ifdef UNICODE}
  {---------------------------------------------------------------------------}
  procedure change_file_date(const filename: PChar8; dosdate: uLong; tmu_date: tm_unz);
  var
    hFile: THandle;
    ftm,ftLocal,ftCreate,ftLastAcc,ftLastWrite: TFileTime;
    s: widestring;
  begin
    s := widestring(filename);
    hFile := CreateFile(PWideChar(s),GENERIC_READ or GENERIC_WRITE, 0,nil,OPEN_EXISTING,0,0);
    GetFileTime(hFile, @ftCreate, @ftLastAcc, @ftLastWrite);
    DosDateTimeToFileTime(word((dosdate shl 16)), word(dosdate), ftLocal);
    LocalFileTimeToFileTime(ftLocal, ftm);
    SetFileTime(hFile,@ftm, @ftLastAcc, @ftm);
    CloseHandle(hFile);
  end;
{$else}
  {---------------------------------------------------------------------------}
  procedure change_file_date(const filename: PChar8; dosdate: uLong; tmu_date: tm_unz);
  var
    hFile: THandle;
    ftm,ftLocal,ftCreate,ftLastAcc,ftLastWrite: TFileTime;
  begin
    hFile := CreateFile(filename,GENERIC_READ or GENERIC_WRITE, 0,nil,OPEN_EXISTING,0,0);
    GetFileTime(hFile, @ftCreate, @ftLastAcc, @ftLastWrite);
    DosDateTimeToFileTime(word((dosdate shl 16)), word(dosdate), ftLocal);
    LocalFileTimeToFileTime(ftLocal, ftm);
    SetFileTime(hFile,@ftm, @ftLastAcc, @ftm);
    CloseHandle(hFile);
  end;
{$endif}

{$else}

{$ifdef FPC}

{---------------------------------------------------------------------------}
procedure change_file_date(const filename: PChar8; dosdate: uLong; tmu_date: tm_unz);
var
  hFile: THandle;
  ftm,ftLocal,ftCreate,ftLastAcc,ftLastWrite: TFileTime;
begin
  hFile := CreateFile(filename,GENERIC_READ or GENERIC_WRITE, 0,nil,OPEN_EXISTING,0,0);
  GetFileTime(hFile, @ftCreate, @ftLastAcc, @ftLastWrite);
  DosDateTimeToFileTime(word((dosdate shl 16)), word(dosdate), @ftLocal);
  LocalFileTimeToFileTime(ftLocal, ftm);   {FPC2 fix}
  SetFileTime(hFile,ftm, ftLastAcc, ftm);
  CloseHandle(hFile);
end;

{$else} {msdos}

{---------------------------------------------------------------------------}
procedure change_file_date(const filename: PChar8; dosdate: uLong; tmu_date: tm_unz);
var
  f: file;
begin
  z_assign(f, filename);
  {open file for reading, otherwise, close will update time}
  reset(f, 1);
  if IOresult=0 then begin
    SetFTime(f,dosDate);
    close(f);
    InOutRes := 0;
  end;
end;

{$endif}
{$endif}


{mymkdir and change_file_date are not 100 % portable
  As I don't know well Unix, I wait feedback for the unix portion}

{---------------------------------------------------------------------------}
function mymkdir(dirname: PChar8): boolean;
var
  S: string;
begin
  {$ifdef unicode}
    S := string(dirname);
  {$else}
    S := StrPas(dirname);
  {$endif}
  mkdir(S);
  mymkdir := IOResult = 0;
end;


{---------------------------------------------------------------------------}
function makedir(newdir: PChar8): boolean;
var
  buffer : PChar8;
  p: PChar8;
  len: int;
var
  hold: char8;
begin
  makedir := false;
  len := strlen(newdir);
  if len<=0 then exit;
  buffer := PChar8(zcalloc(nil, len+1, 1));
  strcopy(buffer,newdir);
  if buffer[len-1]='/' then buffer[len-1] := #0;
  if mymkdir(buffer) then begin
    if Assigned(buffer) then zcfree(nil, buffer);
    makedir := true;
    exit;
  end;

  p := buffer+1;
  while true do  begin
    while( (p^<>#0) and (p^<>'\') and (p^<>'/') ) do inc(p);
    hold := p^;
    p^ := #0;
    if not mymkdir(buffer) then begin
      writeln('couldn''t create directory ',buffer);
      if Assigned(buffer) then zcfree(nil, buffer);
      exit;
    end;
    if hold=#0 then break;
    p^ := hold;
    inc(p);
  end;
  if Assigned(buffer) then zcfree(nil, buffer);
  makedir := true;
end;


{---------------------------------------------------------------------------}
procedure do_banner;
begin
  writeln('MiniUnz 0.15, demo package written by Gilles Vollant');
  writeln('Pascal port by Jacques Nomssi Nzali / W.Ehrhardt');
  writeln;
end;


{---------------------------------------------------------------------------}
procedure do_help;
begin
  writeln('Usage : miniunz [-exvlo] file.zip [file_to_extract]');
  writeln;
end;


{---------------------------------------------------------------------------}
function LeadingZero(w: word): str255;
var
  s: string[20];
begin
  str(w:0,s);
  if length(s)=1 then s := '0' + s;
  LeadingZero := s;
end;


{---------------------------------------------------------------------------}
function HexToStr(x: long): str255;
const
  ByteToChar: array[0..$F] of char8 ='0123456789ABCDEF';
var
  s: string[20];
  i: int;
begin
  s := '';
  for i := 0 to 3 do begin
    s := ByteToChar[byte(x) shr 4] + ByteToChar[byte(x) and $F] + s;
    x := x shr 8;
  end;
  HexToStr := s;
end;


{---------------------------------------------------------------------------}
function do_list(uf: unzFile): int;
var
  i: uLong;
  gi: unz_global_info;
  err: int;
var
  filename_inzip: array[0..255] of char8;
  file_info: unz_file_info;
  ratio: uLong;
  string_method: string[255];
var
  iLevel: uInt;
begin
  err := unzGetGlobalInfo(uf, gi);
  if err<>UNZ_OK then writeln('error ',err,' with zipfile in unzGetGlobalInfo');
  writeln(' Length  Method    Size Ratio   Date    Time   CRC-32   Name');
  writeln(' ------  ------    ---- ----- --------  ----  --------  ----');
  with file_info do begin
    for i := 0 to gi.number_entry-1 do begin
      ratio := 0;
      err := unzGetCurrentFileInfo(uf, @file_info, filename_inzip, sizeof(filename_inzip),nil,0,nil,0);
      if err<>UNZ_OK then begin
        writeln('error ',err,' with zipfile in unzGetCurrentFileInfo');
        break;
      end;
      if uncompressed_size>0 then ratio := (compressed_size*100) div uncompressed_size;

      if compression_method=0 then string_method := 'Stored'
      else if compression_method=Z_DEFLATED then begin
        iLevel := uInt((flag and $06) div 2);
        case iLevel of
           0: string_method := 'Defl:N';
           1: string_method := 'Defl:X';
         2,3: string_method := 'Defl:F'; {2:fast , 3: extra fast}
         else string_method := 'Unkn. ';
        end;
      end;

      writeln(uncompressed_size:7, '  ',
              string_method:6, ' ',
              compressed_size:7, ' ',
              ratio:3,'%  ',  LeadingZero(uLong(tmu_date.tm_mon)+1),'-',
              LeadingZero(uLong(tmu_date.tm_mday)):2,'-',
              LeadingZero(uLong(tmu_date.tm_year mod 100)):2,' ',
              LeadingZero(uLong(tmu_date.tm_hour)),':',
              LeadingZero(uLong(tmu_date.tm_min)),'  ',
              HexToStr(uLong(crc)),'  ',
              filename_inzip);

      if (i+1)<gi.number_entry then begin
        err := unzGoToNextFile(uf);
        if err<>UNZ_OK then begin
          writeln('error ',err,' with zipfile in unzGoToNextFile');
          break;
        end;
      end;
    end;
  end;
  do_list := 0;
end;


{---------------------------------------------------------------------------}
function do_extract_currentfile(uf: unzFile; popt_extract_without_path: int; var popt_overwrite: int): int;
var
  filename_withoutpath: PChar8;
  p: PChar8;
  err: int;
  fout: FILEptr;
  buf: pointer;
  size_buf: uInt;
  file_info: unz_file_info;
  write_filename: PChar8;
  skip: int;
  c,rep: char8;
  ftestexist: FILEptr;
  answer: string[10];
  filename_inzip: packed array[0..255] of char8;
begin
  fout := nil;
  err := unzGetCurrentFileInfo(uf, @file_info, filename_inzip, sizeof(filename_inzip), nil, 0, nil,0);
  if err<>UNZ_OK then begin
    writeln('error ',err, ' with zipfile in unzGetCurrentFileInfo');
    do_extract_currentfile := err;
    exit;
  end;

  size_buf := WRITEBUFFERSIZE;
  buf := zcalloc (nil, size_buf, 1);
  if buf=nil then begin
    writeln('Error allocating memory');
    do_extract_currentfile := UNZ_INTERNALERROR;
    exit;
  end;

  filename_withoutpath := filename_inzip;
  p := filename_withoutpath;
  while p^<>#0 do begin
    if (p^='/') or (p^='\') then filename_withoutpath := p+1;
    inc(p);
  end;

  if filename_withoutpath^=#0 then begin
    if popt_extract_without_path=0 then begin
      writeln('creating directory: ',filename_inzip);
      mymkdir(filename_inzip);
    end;
  end
  else begin
    skip := 0;
    if popt_extract_without_path=0 then write_filename := filename_inzip
    else write_filename := filename_withoutpath;

    err := unzOpenCurrentFile(uf);
    if err<>UNZ_OK then writeln('error ',err,' with zipfile in unzOpenCurrentFile');

    if ((popt_overwrite=0) and (err=UNZ_OK)) then begin
      rep := #0;
      ftestexist := fopen(write_filename,fopenread);
      if ftestexist<>nil then begin
        fclose(ftestexist);
        repeat
          write('The file ',write_filename, ' exist. Overwrite ? [y]es, [n]o, [A]ll: ');
          readln(answer);
          rep := upcase(answer[1]);
        until (rep='Y') or (rep='N') or (rep='A');
      end;

      if rep='N' then skip := 1;
      if rep='A' then popt_overwrite := 1;
    end;

    if (skip=0) and (err=UNZ_OK) then begin
      fout := fopen(write_filename,fopenwrite);

      {some zipfile don't contain directory alone before file}
      if (fout=nil) and (popt_extract_without_path=0) and
        (filename_withoutpath <> PChar8(@filename_inzip)) then
      begin
        c := (filename_withoutpath-1)^;
        (filename_withoutpath-1)^ := #0;
        makedir(write_filename);
        (filename_withoutpath-1)^ := c;
        fout := fopen(write_filename, fopenwrite);
      end;

      if fout=nil then writeln('error opening ',write_filename);
    end;

    if fout<>nil then begin
      writeln(' extracting: ',write_filename);
      repeat
        err := unzReadCurrentFile(uf,buf,size_buf);
        if err<0 then begin
          writeln('error ',err,' with zipfile in unzReadCurrentFile');
          break;
        end;
        if err>0 then begin
          if fwrite(buf,err,1,fout)<>1 then begin
            writeln('error in writing extracted file');
            err := UNZ_ERRNO;
            break;
          end;
        end;
      until err=0;
      fclose(fout);
      if err=0 then change_file_date(write_filename,file_info.dosDate, file_info.tmu_date);
    end;

    if err=UNZ_OK then begin
      err := unzCloseCurrentFile (uf);
      if err<>UNZ_OK then writeln('error ',err,' with zipfile in unzCloseCurrentFile')
      else unzCloseCurrentFile(uf); {don't lose the error}
    end;
  end;

  if buf<>nil then zcfree(nil, buf);
  do_extract_currentfile := err;
end;



{---------------------------------------------------------------------------}
function do_extract(uf: unzFile; opt_extract_without_path: int; opt_overwrite: int): int;
var
  i: uLong;
  gi: unz_global_info;
  err: int;
begin
  err := unzGetGlobalInfo (uf, gi);
  if err<>UNZ_OK then writeln('error ',err,' with zipfile in unzGetGlobalInfo ');

  for i:=0 to gi.number_entry-1 do begin
    if do_extract_currentfile(uf, opt_extract_without_path, opt_overwrite) <> UNZ_OK then break;
    if (i+1)<gi.number_entry then begin
      err := unzGoToNextFile(uf);
      if err<>UNZ_OK then begin
        writeln('error ',err,' with zipfile in unzGoToNextFile');
        break;
      end;
    end;
  end;
  do_extract := 0;
end;


{---------------------------------------------------------------------------}
function do_extract_onefile(uf: unzFile;
                            const filename: PChar8;
                            opt_extract_without_path: int;
                            opt_overwrite: int): int;
begin
  if unzLocateFile(uf,filename,CASESENSITIVITY)<>UNZ_OK then begin
    writeln('file ',filename,' not found in the zipfile');
    do_extract_onefile := 2;
    exit;
  end;
  if do_extract_currentfile(uf, opt_extract_without_path, opt_overwrite) = UNZ_OK then do_extract_onefile := 0
  else do_extract_onefile := 1;
end;


{---------------------------------------------------------------------------}
function main: int;
const
  zipfilename: PChar8 = nil;
  filename_to_extract: PChar8 = nil;
var
  i: int;
  opt_do_list: int;
  opt_do_extract: int;
  opt_do_extract_withoutpath: int;
  opt_overwrite: int;
  uf: unzFile;
  p: int;
  c: char8;
  pstr: string[255];
  filename_try: array[0..512-1] of char8;
begin
  opt_do_list := 0;
  opt_do_extract := 1;
  opt_do_extract_withoutpath := 0;
  opt_overwrite := 0;
  uf := nil;

  do_banner;
  if ParamCount=0 then begin
    do_help;
    halt(0);
  end
  else begin
    for i:=1 to ParamCount do begin
      pstr := {$ifdef unicode} str255 {$endif} (ParamStr(i));
      if pstr[1]='-' then begin
        for p := 2 to length(pstr) do begin
          c := pstr[p];
          case upcase(c) of
          'L',
          'V' : opt_do_list := 1;
          'X' : opt_do_extract := 1;
          'E' : begin
                  opt_do_extract := 1;
                  opt_do_extract_withoutpath := 1;
                end;
          'O' : opt_overwrite := 1;
          end;
        end;
      end
      else begin
        pstr := pstr + #0;
        if zipfilename=nil then zipfilename := StrNew(PChar8(@pstr[1]))
        else if filename_to_extract=nil then filename_to_extract := StrNew(PChar8(@pstr[1]));
      end;
    end; {for}
  end;

  if zipfilename<>nil then begin
    strcopy(filename_try,zipfilename);
    uf := unzOpen(zipfilename);
    if uf=nil then begin
      strcat(filename_try,'.zip');
      uf := unzOpen(filename_try);
    end;
  end;

  if uf=nil then begin
    writeln('Cannot open ',zipfilename,' or ',zipfilename,'.zip');
    halt(1);
  end;

  writeln(filename_try,' opened');

  if opt_do_list=1 then begin
    main := do_list(uf);
    exit;
  end
  else if opt_do_extract=1 then begin
    if filename_to_extract=nil then begin
      main := do_extract(uf,opt_do_extract_withoutpath,opt_overwrite);
      exit;
    end
    else begin
      main := do_extract_onefile(uf,filename_to_extract, opt_do_extract_withoutpath,opt_overwrite);
      exit;
    end;
  end;

  unzCloseCurrentFile(uf);

  strDispose(zipfilename);
  strDispose(filename_to_extract);
  main := 0;
end;

begin
  main;
end.
