program example;

(************************************************************************
  example.c -- usage example of the zlib compression library
  Copyright (C) 1995-1998 Jean-loup Gailly.

  Pascal translation
  Copyright (C) 1998 by Jacques Nomssi Nzali
  For conditions of distribution and use, see copyright notice in readme.txt
  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:

  Feb 2002
    - Source code reformating/reordering
    - make code work under BP7/DPMI&Win, VPascal
    - a) fixed buggy "var comprLen" in test_compress,
      b) removed (un)comprLenL mess.
      a+b) made test_sync work correctly
  Mar 2005
    - Code cleanup for WWW upload
  May 2005
    - Changed comprLen, uncomprLen from const to var (no need for $J+}
  Jul 2009
    - D12 fixes
  Sep 2015
    - UNIT_SCOPE fixes

  ------------------------------------------------------------------------

*************************************************************************)

{$ifdef WIN32}
  {$define WIN32or64}
  {$ifndef VirtualPascal}
    {$apptype console}
  {$endif}
{$endif}

{$ifdef WIN64}
  {$define WIN32or64}
  {$apptype console}
{$endif}


{$x+}

{$define TEST_COMPRESS}
{$define TEST_GZIO}
{$define TEST_INFLATE}
{$define TEST_DEFLATE}
{$define TEST_SYNC}
{$define TEST_DICT}
{$define TEST_FLUSH}

{$ifdef CONDITIONALEXPRESSIONS}  {D6+}
  {$define D4Plus}
  {$ifdef ver230}
    {$define unit_scope}
  {$endif}
  {$ifdef ver240}
    {$define unit_scope}
  {$endif}
  {$ifdef ver250}
    {$define unit_scope}
  {$endif}
  {$ifdef ver260}
    {$define unit_scope}
  {$endif}
  {$ifdef ver270}
    {$define unit_scope}
  {$endif}
  {$ifdef ver280}
    {$define unit_scope}
  {$endif}
  {$ifdef ver290}
    {$define unit_scope}
  {$endif}
  {$ifdef ver300}
    {$define unit_scope}
  {$endif}
{$endif}

uses
  {$ifdef ver80}
    WinCrt,                {Delphi 1}
  {$endif}

  {$ifdef ver70}
    {$ifdef WINDOWS}
      WinCrt,              {*we 0202, BP7/Win}
    {$endif}
  {$endif}

  {$ifndef win32or64}
    {$ifndef ver80}
      {$ifndef FPC}
        strings,
      {$endif}
    {$endif}
  {$endif}

  {$ifndef MSDOS}
    {$ifndef ver70}
      {$ifdef UNIT_SCOPE}
        system.SysUtils,
      {$else}
        SysUtils,
      {$endif}
    {$endif}
  {$endif}


{$ifdef UNIT_SCOPE}
  {Should use system.Ansistrings but then D17 does not know strlen}
  {$warn UNIT_DEPRECATED OFF}
  {$warn SYMBOL_DEPRECATED OFF}
{$endif}

  zLibH,
  zLib,
  gzIo;

{---------------------------------------------------------------------------}
procedure Stop;
begin
  write('Program halted...');
  readln;
  halt(1);
end;

{---------------------------------------------------------------------------}
procedure CHECK_ERR(err: int; const msg: str255);
begin
  if err<>Z_OK then begin
    write(msg, ' error: ', err);
    Stop;
  end;
end;

const
  hello: PChar8 = 'hello, hello!';
  {"hello world" would be more standard, but the repeated "hello"
  stresses the compression code better, sorry...}

{$ifdef TEST_DICT}
const
  dictionary: PChar8 = 'hello';
var
  dictId: uLong; {Adler32 value of the dictionary}
{$endif}


{$ifdef TEST_COMPRESS}
{---------------------------------------------------------------------------}
procedure test_compress(compr: pBytef; comprLen: uLong; uncompr: pBytef; uncomprLen: uLong);
 {-Test compress() and uncompress()} {*we 0202 removed var from comprLen}
var
  err: int;
  len: uLong;
begin
  len := strlen(hello)+1;
  err := compress(compr, comprLen, pBytef(hello)^, len);
  CHECK_ERR(err, 'compress');

  strcopy(PChar8(uncompr), 'garbage');

  err := uncompress(uncompr, uncomprLen, compr^, comprLen);
  CHECK_ERR(err, 'uncompress');

  if strcomp(PChar8(uncompr), hello) <> 0 then begin
    writeln('bad uncompress');
    Stop;
  end
  else writeln('uncompress(): ', StrPas(PChar8(uncompr)));
end;
{$endif}


{$ifdef TEST_GZIO}
{---------------------------------------------------------------------------}
procedure test_gzio(const outf,inf: str255; uncompr: pBytef; uncomprLen: int);
  {-Test read/write of .gz files}
var
  err: int;
  len: int;
var
  zfile: gzFile;
  pos: z_off_t;
begin
  len := strlen(hello)+1;

  zfile := gzopen(outf, 'w');
  if zfile=nil then begin
    writeln('_gzopen error');
    Stop;
  end;
  gzputc(zfile, 'h');
  if gzputs(zfile, 'ello')<>4 then begin
    writeln('gzputs err: ', gzerror(zfile, err));
    Stop;
  end;
  if gzputs(zfile, ', hello!')<>8 then begin
    writeln('gzputs err: ', gzerror(zfile, err));
    Stop;
  end;
  gzseek(zfile, Long(1), SEEK_CUR); {add one zero byte}
  gzclose(zfile);

  zfile := gzopen(inf, 'r');
  if zfile=nil then writeln('gzopen error');

  strcopy(PChar8(uncompr), 'garbage');

  uncomprLen := gzread(zfile, uncompr, uInt(uncomprLen));
  if uncomprLen<>len then begin
    writeln('gzread err: ', gzerror(zfile, err));
    Stop;
  end;
  if strcomp(PChar8(uncompr), hello)<>0 then begin
    writeln('bad gzread: ', PChar8(uncompr));
    Stop;
  end
  else writeln('gzread(): ', PChar8(uncompr));

  pos := gzseek(zfile, Long(-8), SEEK_CUR);
  if (pos<>6) or (gztell(zfile)<>pos) then begin
    writeln('gzseek error, pos=',pos,', gztell=',gztell(zfile));
    Stop;
  end;

  if char8(gzgetc(zfile))<>' ' then begin
    writeln('gzgetc error');
    Stop;
  end;

  gzgets(zfile, PChar8(uncompr), uncomprLen);
  uncomprLen := strlen(PChar8(uncompr));
  if uncomprLen<>6 then begin
    {"hello!"}
    writeln('gzgets err after gzseek: ', gzerror(zfile, err));
    Stop;
  end;
  if strcomp(PChar8(uncompr), hello+7)<>0 then begin
    writeln('bad gzgets after gzseek');
    Stop;
  end
  else writeln('gzgets() after gzseek: ', PChar8(uncompr));

  gzclose(zfile);
end;
{$endif}


{$ifdef TEST_DEFLATE}
{---------------------------------------------------------------------------}
procedure test_deflate(compr: pBytef; comprLen: uLong);
  {-Test deflate() with small buffers}
var
  c_stream: z_stream; {compression stream}
  err: int;
  len: int;
begin
  len := strlen(hello)+1;
  c_stream.zalloc := nil;    {alloc_func(0);}
  c_stream.zfree  := nil;    {free_func(0);}
  c_stream.opaque := nil;    {voidpf(0);}

  err := deflateInit(c_stream, Z_DEFAULT_COMPRESSION);
  CHECK_ERR(err, 'deflateInit');

  c_stream.next_in  := pBytef(hello);
  c_stream.next_out := compr;

  while (c_stream.total_in <> uLong(len)) and (c_stream.total_out < comprLen) do begin
    c_stream.avail_out := 1; {force small buffers}
    c_stream.avail_in := 1;
    err := deflate(c_stream, Z_NO_FLUSH);
    CHECK_ERR(err, 'deflate');
  end;

  {Finish the stream, still forcing small buffers:}
  while true do begin
    c_stream.avail_out := 1;
    err := deflate(c_stream, Z_FINISH);
    if err=Z_STREAM_END then break;
    CHECK_ERR(err, 'deflate');
  end;

  err := deflateEnd(c_stream);
  CHECK_ERR(err, 'deflateEnd');
end;
{$endif}


{$ifdef TEST_INFLATE}
{---------------------------------------------------------------------------}
procedure test_inflate(compr: pBytef; comprLen: uLong; uncompr: pBytef;  uncomprLen: uLong);
  {-Test inflate() with small buffers}
var
  err: int;
  d_stream: z_stream; {decompression stream}
begin
  strcopy(PChar8(uncompr), 'garbage');

  d_stream.zalloc := nil;   {alloc_func(0);}
  d_stream.zfree  := nil;   {free_func(0);}
  d_stream.opaque := nil;   {voidpf(0);}

  d_stream.next_in  := compr;
  d_stream.avail_in := 0;
  d_stream.next_out := uncompr;

  err := inflateInit(d_stream);
  CHECK_ERR(err, 'inflateInit');

  while (d_stream.total_out<uncomprLen) and (d_stream.total_in<comprLen) do begin
    d_stream.avail_out := 1; {force small buffers}
    d_stream.avail_in := 1;
    err := inflate(d_stream, Z_NO_FLUSH);
    if err=Z_STREAM_END then break;
    CHECK_ERR(err, 'inflate');
  end;

  err := inflateEnd(d_stream);
  CHECK_ERR(err, 'inflateEnd');

  if strcomp(PChar8(uncompr), hello)<>0 then begin
    writeln('bad inflate');
    exit;
  end
  else writeln('inflate(): ', StrPas(PChar8(uncompr)));
end;
{$endif}


{$ifdef TEST_DEFLATE}
{---------------------------------------------------------------------------}
procedure test_large_deflate(compr: pBytef; comprLen: uLong; uncompr: pBytef;  uncomprLen: uLong);
  {-Test deflate() with large buffers and dynamic change of compression level}
var
  c_stream: z_stream; {compression stream}
  err: int;
begin
  c_stream.zalloc := nil;    {alloc_func(0);}
  c_stream.zfree  := nil;    {free_func(0);}
  c_stream.opaque := nil;    {voidpf(0);}

  err := deflateInit(c_stream, Z_BEST_SPEED);
  CHECK_ERR(err, 'deflateInit');

  c_stream.next_out := compr;
  c_stream.avail_out := uInt(comprLen);

  {At this point, uncompr is still mostly zeroes, so it should compress very well:}

  c_stream.next_in := uncompr;
  c_stream.avail_in := uInt(uncomprLen);
  err := deflate(c_stream, Z_NO_FLUSH);
  CHECK_ERR(err, 'deflate');
  if c_stream.avail_in<>0 then begin
    writeln('deflate not greedy');
    exit;
  end;

  {Feed in already compressed data and switch to no compression:}
  deflateParams(c_stream, Z_NO_COMPRESSION, Z_DEFAULT_STRATEGY);
  c_stream.next_in := compr;
  c_stream.avail_in := uInt(comprLen div 2);
  err := deflate(c_stream, Z_NO_FLUSH);
  CHECK_ERR(err, 'deflate');

  {Switch back to compressing mode:}
  deflateParams(c_stream, Z_BEST_COMPRESSION, Z_FILTERED);
  c_stream.next_in := uncompr;
  c_stream.avail_in := uInt(uncomprLen);
  err := deflate(c_stream, Z_NO_FLUSH);
  CHECK_ERR(err, 'deflate');

  err := deflate(c_stream, Z_FINISH);
  if err<>Z_STREAM_END then begin
    writeln('deflate should report Z_STREAM_END');
    exit;
  end;
  err := deflateEnd(c_stream);
  CHECK_ERR(err, 'deflateEnd');
end;
{$endif}


{$ifdef TEST_INFLATE}
{---------------------------------------------------------------------------}
procedure test_large_inflate(compr: pBytef; comprLen: uLong; uncompr: pBytef;  uncomprLen: uLong);
  {-Test inflate() with large buffers}
var
  err: int;
  d_stream: z_stream; {decompression stream}
begin
  strcopy(PChar8(uncompr), 'garbage');

  d_stream.zalloc := nil;    {alloc_func(0);}
  d_stream.zfree  := nil;    {free_func(0);}
  d_stream.opaque := nil;    {voidpf(0);}

  d_stream.next_in  := compr;
  d_stream.avail_in := uInt(comprLen);

  err := inflateInit(d_stream);
  CHECK_ERR(err, 'inflateInit');

  while true do begin
    d_stream.next_out := uncompr;            {discard the output}
    d_stream.avail_out := uInt(uncomprLen);
    err := inflate(d_stream, Z_NO_FLUSH);
    if err=Z_STREAM_END then break;
    CHECK_ERR(err, 'large inflate');
  end;

  err := inflateEnd(d_stream);
  CHECK_ERR(err, 'inflateEnd');

  if d_stream.total_out <> 2*uncomprLen + comprLen div 2 then begin
    writeln('bad large inflate: ', d_stream.total_out);
    Stop;
  end
  else writeln('large_inflate(): OK');
end;
{$endif}


{$ifdef TEST_FLUSH}
{---------------------------------------------------------------------------}
procedure test_flush(compr: pBytef; var comprLen: uLong);
  {-Test deflate() with full flush}
var
  c_stream: z_stream; {compression stream}
  err: int;
  len: int;

begin
  len := strlen(hello)+1;
  c_stream.zalloc := nil;    {alloc_func(0);}
  c_stream.zfree  := nil;    {free_func(0);}
  c_stream.opaque := nil;    {voidpf(0);}

  err := deflateInit(c_stream, Z_DEFAULT_COMPRESSION);
  CHECK_ERR(err, 'deflateInit');

  c_stream.next_in := pBytef(hello);
  c_stream.next_out := compr;
  c_stream.avail_in := 3;
  c_stream.avail_out := uInt(comprLen);

  err := deflate(c_stream, Z_FULL_FLUSH);
  CHECK_ERR(err, 'deflate');

  Inc(pzByteArray(compr)^[3]); { force an error in first compressed block }
  c_stream.avail_in := len - 3;

  err := deflate(c_stream, Z_FINISH);
  if err<>Z_STREAM_END then CHECK_ERR(err, 'deflate');

  err := deflateEnd(c_stream);
  CHECK_ERR(err, 'deflateEnd');

  comprLen := c_stream.total_out;
end;
{$endif}

{$ifdef TEST_SYNC}
{---------------------------------------------------------------------------}
procedure test_sync(compr: pBytef; comprLen: uLong; uncompr: pBytef; uncomprLen: uLong);
  {-Test inflateSync()}
var
  err: int;
  d_stream: z_stream; {decompression stream}
begin
  strcopy(PChar8(uncompr), 'garbage');

  d_stream.zalloc := nil;    {alloc_func(0);}
  d_stream.zfree  := nil;    {free_func(0);}
  d_stream.opaque := nil;    {voidpf(0);}

  d_stream.next_in  := compr;
  d_stream.avail_in := 2; {just read the zlib header}

  err := inflateInit(d_stream);
  CHECK_ERR(err, 'inflateInit');

  d_stream.next_out := uncompr;
  d_stream.avail_out := uInt(uncomprLen);

  inflate(d_stream, Z_NO_FLUSH);
  CHECK_ERR(err, 'inflate');

  d_stream.avail_in := uInt(comprLen-2);   {read all compressed data}
  err := inflateSync(d_stream);           {but skip the damaged part}
  CHECK_ERR(err, 'inflateSync');

  err := inflate(d_stream, Z_FINISH);
  if err<>Z_DATA_ERROR then begin
    writeln('inflate should report DATA_ERROR');
    {Because of incorrect adler32}
    Stop;
  end;
  err := inflateEnd(d_stream);
  CHECK_ERR(err, 'inflateEnd');

  writeln('after inflateSync(): hel', StrPas(PChar8(uncompr)));
end;
{$endif}

{$ifdef TEST_DICT}
{---------------------------------------------------------------------------}
procedure test_dict_deflate(compr: pBytef; comprLen: uLong);
  {-Test deflate() with preset dictionary}
var
  c_stream: z_stream; {compression stream}
  err: int;
begin
  c_stream.zalloc := nil;  {(alloc_func)0;}
  c_stream.zfree  := nil;  {(free_func)0;}
  c_stream.opaque := nil;  {(voidpf)0;}

  err := deflateInit(c_stream, Z_BEST_COMPRESSION);
  CHECK_ERR(err, 'deflateInit');

  err := deflateSetDictionary(c_stream, pBytef(dictionary), StrLen(dictionary));
  CHECK_ERR(err, 'deflateSetDictionary');

  dictId := c_stream.adler;
  c_stream.next_out := compr;
  c_stream.avail_out := uInt(comprLen);

  c_stream.next_in := pBytef(hello);
  c_stream.avail_in := uInt(strlen(hello)+1);

  err := deflate(c_stream, Z_FINISH);
  if err<>Z_STREAM_END then begin
    writeln('deflate should report Z_STREAM_END');
    exit;
  end;
  err := deflateEnd(c_stream);
  CHECK_ERR(err, 'deflateEnd');
end;


{---------------------------------------------------------------------------}
procedure test_dict_inflate(compr: pBytef; comprLen: uLong; uncompr: pBytef; uncomprLen: uLong);
  {-Test inflate() with a preset dictionary}
var
  err: int;
  d_stream: z_stream; {decompression stream}
begin
  strcopy(PChar8(uncompr), 'garbage');

  d_stream.zalloc := nil;    {alloc_func(0);}
  d_stream.zfree  := nil;    {free_func(0);}
  d_stream.opaque := nil;    {voidpf(0);}

  d_stream.next_in  := compr;
  d_stream.avail_in := uInt(comprLen);

  err := inflateInit(d_stream);
  CHECK_ERR(err, 'inflateInit');

  d_stream.next_out := uncompr;
  d_stream.avail_out := uInt(uncomprLen);

  while true do begin
    err := inflate(d_stream, Z_NO_FLUSH);
    if err=Z_STREAM_END then break;
    if err=Z_NEED_DICT  then begin
      if d_stream.adler<>dictId then begin
        writeln('unexpected dictionary');
        Stop;
      end;
      err := inflateSetDictionary(d_stream, pBytef(dictionary), StrLen(dictionary));
    end;
    CHECK_ERR(err, 'inflate with dict');
  end;

  err := inflateEnd(d_stream);
  CHECK_ERR(err, 'inflateEnd');

  if strcomp(PChar8(uncompr), hello)<>0 then begin
    writeln('bad inflate with dict');
    Stop;
  end
  else writeln('inflate with dictionary: ', StrPas(PChar8(uncompr)));
end;
{$endif}


{---------------------------------------------------------------------------}
{-Usage:  example [output.gz  [input.gz]]}
const
  msdoslen = 25000;
var
  comprLen: uLong;
  uncomprLen: uLong;
var
  compr, uncompr: pBytef;
begin
  comprLen  := msdoslen div sizeof(uInt); {don't overflow on MSDOS}
  uncomprLen:= msdoslen div sizeof(uInt);

  if copy(zlibVersion,1,1)<>ZLIB_VERSION[1] then begin
    writeln('incompatible zlib version');
    Stop;
  end
  else if zlibVersion<>ZLIB_VERSION then writeln('warning: different zlib version');

  GetMem(compr, comprLen*sizeof(uInt));
  GetMem(uncompr, uncomprLen*sizeof(uInt));
  {compr and uncompr are cleared to avoid reading uninitialized
    data and to ensure that uncompr compresses well.}

  if (compr=Z_NULL) or (uncompr = Z_NULL) then begin
    writeln('out of memory');
    Stop;
  end;
  fillchar(compr^, comprLen*sizeof(uInt), 0);
  fillchar(uncompr^, uncomprLen*sizeof(uInt), 0);

  if (compr = Z_NULL) or (uncompr = Z_NULL) then begin
    writeln('out of memory');
    Stop;
  end;

  {$ifdef TEST_COMPRESS}
  test_compress(compr, comprLen, uncompr, uncomprLen);
  {$endif}

  {$ifdef TEST_GZIO}
    {$ifdef unicode}
       case ParamCount of
           0:  test_gzio('foo.gz', 'foo.gz', uncompr, int(uncomprLen));
           1:  test_gzio(str255(ParamStr(1)), 'foo.gz', uncompr, int(uncomprLen));
         else  test_gzio(str255(ParamStr(1)), str255(ParamStr(2)), uncompr, int(uncomprLen));
       end;
    {$else}
       case ParamCount of
           0:  test_gzio('foo.gz', 'foo.gz', uncompr, int(uncomprLen));
           1:  test_gzio(ParamStr(1), 'foo.gz', uncompr, int(uncomprLen));
         else  test_gzio(ParamStr(1), ParamStr(2), uncompr, int(uncomprLen));
       end;
    {$endif}
  {$endif}

  {$ifdef TEST_DEFLATE}
  writeln('small buffer Deflate');
  test_deflate(compr, comprLen);
  {$endif}

  {$ifdef TEST_INFLATE}
    test_inflate(compr, comprLen, uncompr, uncomprLen);
  {$endif}

  {$ifdef TEST_DEFLATE}
  writeln('large buffer Deflate');
  test_large_deflate(compr, comprLen, uncompr, uncomprLen);
  {$endif}

  {$ifdef TEST_INFLATE}
  writeln('large buffer Inflate');
  test_large_inflate(compr, comprLen, uncompr, uncomprLen);
  {$endif}

  {$ifdef TEST_FLUSH}
  test_flush(compr, comprLen);
  {$endif}

  {$ifdef TEST_SYNC}
  test_sync(compr, comprLen, uncompr, uncomprLen);
  {$endif}
  comprLen := uncomprLen;

  {$ifdef TEST_DICT}
  test_dict_deflate(compr, comprLen);
  test_dict_inflate(compr, comprLen, uncompr, uncomprLen);
  {$endif}

  FreeMem(compr, comprLen*sizeof(uInt));
  FreeMem(uncompr, uncomprLen*sizeof(uInt));
end.
