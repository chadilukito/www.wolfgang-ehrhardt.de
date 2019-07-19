unit gzIO;

(************************************************************************

  Pascal unit based on gzio.c -- IO on .gz files
  Copyright (C) 1995-1998 Jean-loup Gailly.

  Define NO_DEFLATE to compile this file without the compression code

  Pascal translation based on code contributed by Francisco Javier Crespo
  Copyright (C) 1998 by Jacques Nomssi Nzali
  For conditions of distribution and use, see copyright notice in readme.txt

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:

  Aug 2000
    - ZLIB 113 changes
  Feb 2002
    - allow variable windowbits/memlevel in gzopen
    - gzsetparams and gzeof in interface part
    - DEF_WBITS instead of MAX_WBITS for inflate
    - Source code reformating/reordering
    - global {$I-} because bracketing IO functions leaves {I+} on
    - check IOResult after writing .gz header
    - make code work under BP7/DPMI&Win
  Mar 2005
    - Code cleanup for WWW upload
  May 2005
    - gzopen: typecast Long(stream.avail_in)
    - do_flush: written: unsigned;
    - gzerror: missing exit if s=nil
  Aug 2008
    - gzopen: assign with fpath
  Jul 2009
    - D12 fixes
  Sep 2015
    - UNIT_SCOPE fixes
  ------------------------------------------------------------------------

*************************************************************************)

interface

{$x+}
{$i-}   {*we 0202}

uses
  ZLibH;

const
  SEEK_SET = 0; {seek from beginning of file}
  SEEK_CUR = 1; {seek from current position}
  SEEK_END = 2;

var
  GZ_windowBits : int; { = -MAX_WBITS;}    {*we 0202}
  GZ_memLevel   : int; { = DEF_MEM_LEVEL;} {allow variable windowbits/memlevel in gzopen}

type
  gzFile  = voidp;
  z_off_t = long;

function gzopen(const fpath, fmode: str255): gzFile;
  {-Opens a gzip (.gz) file for reading or writing.}

function gzread(f: gzfile; buf: voidp; len: uInt): int;
  {-Reads the given number of uncompressed bytes from the compressed file.}

function gzgetc(f: gzfile): int;
  {-Reads one byte from the compressed file.}

function gzgets(f: gzfile; buf: PChar8; len: int): PChar8;
  {-Read a string from the compressed file}

function gzseek(f: gzfile; offset: z_off_t; whence: int): z_off_t;
  {-Sets the starting position for the next gzread/gzwrite on the compressed file.}

function gzclose(f: gzfile): int;
  {-Flushes all pending output if necessary, closes the compressed file}

function gzerror(f: gzfile; var errnum: Int): str255;
  {-Flushes all pending output if necessary, closes the compressed file}

function gzsetparams(f: gzfile; level: int; strategy: int): int;
  {-Update the compression level and strategy.}

function gzeof(f: gzfile): boolean;
  {-Returns true when EOF has previously been detected reading the given input stream, otherwise false.}

function gztell(f: gzfile): z_off_t;
  {-Returns the starting position for the next gzread or gzwrite on the given compressed file.}


{$ifndef NO_DEFLATE}
function gzwrite(f: gzFile; buf: voidp; len: uInt): int;
  {-Writes the given number of uncompressed bytes into the compressed file.}

function gzputc(f: gzfile; c: char8): int;
  {-Writes c, converted to an unsigned char, into the compressed file.}

function gzputs(f: gzfile; s: PChar8): int;
  {-Writes the given null-terminated string to the compressed file}

function gzflush(f: gzFile; flush: int): int;
  {-Flushes all pending output into the compressed file.}
{$endif} {NO_DEFLATE}


implementation

{$I zconf.inc}

uses
  {$ifndef MSDOS}
    {$ifndef VER70}    {*we 0202: Not for BP7/Win}
      {$ifdef UNIT_SCOPE}
        system.SysUtils,
      {$else}
        SysUtils,
      {$endif}
    {$endif}
  {$endif}
  zlib, zcrc32;

{$ifdef UNIT_SCOPE}
  {Should use system.Ansistrings but then D17 does not know strlen}
  {$warn UNIT_DEPRECATED OFF}
  {$warn SYMBOL_DEPRECATED OFF}
{$endif}


const
  Z_EOF = -1;         {same value as in STDIO.H}
  Z_BUFSIZE = 16384;

  gz_magic : array[0..1] of byte = ($1F, $8B); {gzip magic header}

                      {gzip flag byte                        }
 {ASCII_FLAG  = $01;} {bit  0 set: file probably ascii text  }
  HEAD_CRC    = $02;  {bit  1 set: header CRC present        }
  EXTRA_FIELD = $04;  {bit  2 set: extra field present       }
  ORIG_NAME   = $08;  {bit  3 set: original file name present}
  COMMENT     = $10;  {bit  4 set: file comment present      }
  RESERVED    = $E0;  {bits 5..7: reserved                   }

type
  gz_stream = record
                stream      : z_stream;
                z_err       : int;        {error code for last stream operation          }
                zs_eof      : boolean;    {set if end of input file                      }
                zfile       : file;       {.gz file                                      }
                inbuf       : pBytef;     {input buffer                                  }
                outbuf      : pBytef;     {output buffer                                 }
                crc         : uLong;      {crc32 of uncompressed data                    }
                msg,                      {error message - limit 79 chars                }
                path        : string[79]; {path name for debugging only - limit 79 chars }
                transparent : boolean;    {true if input file is not a .gz file          }
                mode        : char8;       {'w' or 'r'                                    }
                startpos    : long;       {start of compressed data in file (header skipped)}
              end;

type
  gz_streamp = ^gz_stream;


{---------------------------------------------------------------------------}
function get_byte(s: gz_streamp): int;
  {-Read a byte from a gz_stream. Updates next_in and avail_in.}
  {Returns EOF for end of file.}
  {IN assertion: the stream s has been sucessfully opened for reading.}
begin
  with s^ do begin
    if zs_eof then begin
      get_byte := Z_EOF;
      exit;
    end;
    if stream.avail_in=0 then begin
      blockread(zfile, inbuf^, Z_BUFSIZE, stream.avail_in);
      if stream.avail_in=0 then begin
        zs_eof := true;
        if IOResult<>0 then z_err := Z_ERRNO;
        get_byte := Z_EOF;
        exit;
      end;
      stream.next_in := inbuf;
    end;
    dec(stream.avail_in);
    get_byte := stream.next_in^;
    inc(stream.next_in);
  end;
end;


{---------------------------------------------------------------------------}
procedure check_header(s: gz_streamp);
  {-Check the gzip header of a gz_stream opened for reading.}

  {Set the stream mode to transparent if the gzip magic header is not present.
  Set s^.err  to Z_DATA_ERROR if the magic header is present but the rest of
  the header is incorrect.

  IN assertion: the stream s has already been created sucessfully;
  s^.stream.avail_in is zero for the first time, but may be non-zero
  for concatenated .gz files.}

var
  method: int;  {method byte}
  flags : int;  {flags byte}
  len   : uInt;
  c     : int;
begin
  with s^ do begin
    {Check the gzip magic header}
    for len := 0 to 1 do begin
      c := get_byte(s);
      if c<>gz_magic[len] then begin
        if len<>0 then begin
          inc(stream.avail_in);
          dec(stream.next_in);
        end;
        if c<>Z_EOF then begin
          inc(stream.avail_in);
          dec(stream.next_in);
          transparent := true;
        end;
        if stream.avail_in<>0 then z_err := Z_OK else z_err := Z_STREAM_END;
        exit;
      end;
    end;

    method := get_byte(s);
    flags := get_byte(s);
    if (method <> Z_DEFLATED) or ((flags and RESERVED) <> 0) then begin
      z_err := Z_DATA_ERROR;
      exit;
    end;

    for len := 0 to 5 do get_byte(s); {Discard time, xflags and OS code}

    if (flags and EXTRA_FIELD) <> 0 then begin {skip the extra field}
      len := uInt(get_byte(s));
      len := len + (uInt(get_byte(s)) shr 8);
      {len is garbage if EOF but the loop below will quit anyway}
      while (len <> 0) and (get_byte(s) <> Z_EOF) do dec(len);
    end;

    if (flags and ORIG_NAME)<>0 then begin {skip the original file name}
      repeat
        c := get_byte(s);
      until (c = 0) or (c = Z_EOF);
    end;

    if (flags and COMMENT)<>0 then begin {skip the .gz file comment}
      repeat
        c := get_byte(s);
      until (c=0) or (c=Z_EOF);
    end;

    if (flags and HEAD_CRC)<>0 then begin {skip the header crc}
      get_byte(s);
      get_byte(s);
    end;

    if zs_eof then z_err := Z_DATA_ERROR else z_err := Z_OK;
  end;
end;


{---------------------------------------------------------------------------}
function destroy(var s: gz_streamp): int;
  {-Cleanup then free the given gz_stream. Return a zlib error code.}
  {Try freeing in the reverse order of allocations.}
begin
  destroy := Z_OK;
  if not Assigned(s) then begin
    destroy := Z_STREAM_ERROR;
    exit;
  end;

  with s^ do begin
    if stream.state <> nil then begin
      if mode='w' then begin
        {$ifdef NO_DEFLATE}
          destroy := Z_STREAM_ERROR;
        {$else}
          destroy := deflateEnd(s^.stream);
        {$endif}
      end
      else if mode='r' then begin
        destroy := inflateEnd(stream);
      end;
    end;

    if path<>'' then begin
      close(zfile);
      if IOResult<>0 then destroy := Z_ERRNO;
    end;

    if z_err<0 then destroy := z_err;

    if Assigned(inbuf)  then FreeMem(inbuf, Z_BUFSIZE);
    if Assigned(outbuf) then FreeMem(outbuf, Z_BUFSIZE);
  end;
  FreeMem(s, sizeof(gz_stream));
end;




{---------------------------------------------------------------------------}
function gzopen(const fpath, fmode: str255): gzFile;
  {-Opens a gzip (.gz) file for reading or writing.}

  {As Pascal does not use file descriptors, the code has been changed
  to accept only path names.

  The fmode parameter defaults to BINARY read or write operations ('r' or 'w')
  but can also include a compression level ('w9') or a strategy: Z_FILTERED
  as in 'w6f' or Z_HUFFMAN_ONLY as in 'w1h'. (See the description of
  deflateInit2 for more information about the strategy parameter.)

  gzopen can be used to open a file which is not in gzip format; in this
  case, gzread will directly read from the file without decompression.

  gzopen returns nil if the file could not be opened (non-zero IOResult)
  or if there was insufficient memory to allocate the (de)compression state
  (zlib error is Z_MEM_ERROR).}

var
  i       : uInt;
  err     : int;
  level   : int;        {compression level}
  strategy: int;        {compression strategy}
  s       : gz_streamp;

{$ifndef NO_DEFLATE}
  gzheader : array [0..9] of byte;
{$endif}

begin

  if (fpath='') or (fmode='') then begin
    gzopen := Z_NULL;
    exit;
  end;

  GetMem(s,sizeof(gz_stream));
  if not Assigned(s) then begin
    gzopen := Z_NULL;
    exit;
  end;

  level := Z_DEFAULT_COMPRESSION;
  strategy := Z_DEFAULT_STRATEGY;

  with s^ do begin
    stream.zalloc := nil;     {(alloc_func)0}
    stream.zfree := nil;      {(free_func)0}
    stream.opaque := nil;     {(voidpf)0}
    stream.next_in := Z_NULL;
    stream.next_out := Z_NULL;
    stream.avail_in := 0;
    stream.avail_out := 0;
    path := fpath; {limit to 255 chars}
    z_err := Z_OK;
    zs_eof := false;
    inbuf := Z_NULL;
    outbuf := Z_NULL;
    crc := crc32(0, Z_NULL, 0);
    msg := '';
    transparent := false;
    mode := #0;
    for i:=1 to length(mode) do begin
      case fmode[i] of
        'r'      : mode := 'r';
        'w'      : mode := 'w';
        '0'..'9' : level := ord(fmode[i])-ord('0');
        'f'      : strategy := Z_FILTERED;
        'h'      : strategy := Z_HUFFMAN_ONLY;
      end;
    end;
    if mode=chr(0) then begin
      destroy(s);
      gzopen := gzFile(Z_NULL);
      exit;
    end;

    if mode='w' then begin
      {$ifdef NO_DEFLATE}
        err := Z_STREAM_ERROR;
      {$else}
        {*we 0202: allow variable windowbits/memlevel in gzopen}
        {windowBits is passed < 0 to suppress zlib header}
        err := deflateInit2(stream, level, Z_DEFLATED, -abs(GZ_windowBits), GZ_memLevel, strategy);

        GetMem(outbuf, Z_BUFSIZE);
        stream.next_out := outbuf;
      {$endif}
      if (err <> Z_OK) or (outbuf = Z_NULL) then begin
        destroy(s);
        gzopen := gzFile(Z_NULL);
        exit;
      end;
    end
    else begin
      GetMem(inbuf, Z_BUFSIZE);
      stream.next_in := inbuf;

      {windowBits is passed < 0 to tell that there is no zlib header}
      {*we 0202: DEF_WBITS instead of MAX_WBITS for inflate}
      err := inflateInit2_(stream, -DEF_WBITS, ZLIB_VERSION, sizeof(z_stream));

      if (err <> Z_OK) or (inbuf = Z_NULL) then begin
        destroy(s);
        gzopen := gzFile(Z_NULL);
        exit;
      end;
    end;

    stream.avail_out := Z_BUFSIZE;

    {*WE Aug.2008: Use fpath in assign because the original paszlib code }
    { Assign(s^.gzfile, s^.path); truncates names with more than 79 chars}
    system.assign(zfile, {$ifdef unicode} string {$endif}(fpath));
    if mode='w' then rewrite(zfile,1) else reset(zfile,1);
    if IOResult<>0 then begin
      destroy(s);
      gzopen := gzFile(Z_NULL);
      exit;
    end;

    if mode = 'w' then begin {Write a very simple .gz header}
    {$ifndef NO_DEFLATE}
      fillchar(gzheader, sizeof(gzheader),0);
      gzheader[0] := gz_magic [0];
      gzheader[1] := gz_magic [1];
      gzheader[2] := Z_DEFLATED;   {method}
      blockwrite(zfile, gzheader, 10);
      {*we 0202: check IOResult after write .gz header}
      if IOResult<>0 then begin
        destroy(s);
        gzopen := gzFile(Z_NULL);
        exit;
      end;
      startpos := Long(10);
    {$endif}
    end
    else begin
      check_header(s); {skip the .gz header}
      startpos := FilePos(zfile) - Long(stream.avail_in);
    end;
  end;

  gzopen := gzFile(s);
end;



{---------------------------------------------------------------------------}
function gzsetparams(f: gzfile; level: int; strategy: int): int;
  {-Update the compression level and strategy.}
var
  s: gz_streamp;
  written: integer;
begin
  s := gz_streamp(f);
  if (s=nil) or (s^.mode <> 'w') then begin
    gzsetparams := Z_STREAM_ERROR;
    exit;
  end;

  with s^ do begin
    {Make room to allow flushing}
    if stream.avail_out=0 then begin
      stream.next_out := outbuf;
      blockwrite(zfile, outbuf^, Z_BUFSIZE, written);
      if (written <> Z_BUFSIZE) then z_err := Z_ERRNO;
      stream.avail_out := Z_BUFSIZE;
    end;
    gzsetparams := deflateParams(stream, level, strategy);
  end;
end;




{*we 113}
{---------------------------------------------------------------------------}
function getLong(s: gz_streamp): uLong;
   {-Reads a long in LSB order from the given gz_stream. Sets z_err in case of error.}
var
  x: packed array [0..3] of byte;
  c: int;
begin
  {x := uLong(get_byte(s));  - you can't do this with TP, no unsigned long}
  {the following assumes a little endian machine and TP}
  x[0] := byte(get_byte(s));
  x[1] := byte(get_byte(s));
  x[2] := byte(get_byte(s));
  c := get_byte(s);
  x[3] := byte(c);
  if c=Z_EOF then s^.z_err := Z_DATA_ERROR;
  GetLong := uLong(longint(x));
end;



{---------------------------------------------------------------------------}
function gzread(f: gzfile; buf: voidp; len: uInt): int;
  {-Reads the given number of uncompressed bytes from the compressed file.}

  {If the input file was not in gzip format, gzread copies the given number
  of bytes into the buffer.

  gzread returns the number of uncompressed bytes actually read
  (0 for end of file, -1 for error).}

var
  s        : gz_streamp;
  start    : pBytef;
  next_out : pBytef;
  n        : uInt;
  crclen   : uInt;     {Buffer length to update CRC32}       {*we113: filecrc/len deleted}
  bytes    : integer;  {bytes actually read in I/O blockread}
  total_in : uLong;
  total_out: uLong;

begin

  s := gz_streamp(f);
  start := pBytef(buf); {starting point for crc computation}

  if (s=nil) or (s^.mode<>'r') then begin
    gzread := Z_STREAM_ERROR;
    exit;
  end;

  with s^ do begin
    if (z_err=Z_DATA_ERROR) or (z_err=Z_ERRNO) then begin
      gzread := -1;
      exit;
    end;

    if z_err=Z_STREAM_END then begin
      gzread := 0;  {EOF}
      exit;
    end;

    stream.next_out := pBytef(buf);
    stream.avail_out := len;

    while stream.avail_out<>0 do begin

      if transparent then begin
        {Copy first the lookahead bytes:}
        n := stream.avail_in;
        if n>stream.avail_out then n := stream.avail_out;
        if n>0 then begin
          zmemcpy(stream.next_out, stream.next_in, n);
          inc(stream.next_out, n);
          inc(stream.next_in, n);
          dec(stream.avail_out, n);
          dec(stream.avail_in, n);
        end;
        if stream.avail_out>0 then begin
          blockread (zfile, stream.next_out^, stream.avail_out, bytes);
          dec(stream.avail_out, uInt(bytes));
        end;
        dec(len, stream.avail_out);
        inc(stream.total_in, uLong(len));
        inc(stream.total_out, uLong(len));
        gzread := int(len);
        exit;
      end; {if transparent}

      if (stream.avail_in=0) and (not zs_eof) then begin
        blockread(zfile, inbuf^, Z_BUFSIZE, stream.avail_in);
        if stream.avail_in=0 then begin
          zs_eof := true;
          if IOResult<>0 then begin
            z_err := Z_ERRNO;
            break;
          end;
        end;
        stream.next_in := inbuf;
      end;

      z_err := inflate(stream, Z_NO_FLUSH);

      if z_err=Z_STREAM_END then begin
        crclen := 0;
        next_out := stream.next_out;
        while next_out<>start do begin
          dec(next_out);
          inc(crclen);   {Hack because Pascal cannot substract pointers}
        end;
        {Check CRC and original size}
        crc := crc32(crc, start, crclen);
        start := stream.next_out;

        if crc<>getLong(s) then z_err := Z_DATA_ERROR
        else begin
          {*we 113}
          {The uncompressed length returned by above getlong() may}
          {be different from s->stream.total_out) in case of      }
          {concatenated .gz files. Check for such files:          }
          getLong(s);
          {Check for concatenated .gz files:}
          check_header(s);
          if z_err=Z_OK then begin
            total_in := stream.total_in;
            total_out := stream.total_out;
            inflateReset(stream);
            stream.total_in := total_in;
            stream.total_out := total_out;
            crc := crc32(0, Z_NULL, 0);
          end;
        end;
      end;

      if (z_err<>Z_OK) or zs_eof then break;

    end; {while}

    crclen := 0;
    next_out := stream.next_out;
    while next_out<>start do begin
      dec(next_out);
      inc(crclen);   {Hack because Pascal cannot substract pointers}
    end;
    crc := crc32(crc, start, crclen);
    gzread := int(len - stream.avail_out);
  end;
end;


{---------------------------------------------------------------------------}
function gzgetc(f: gzfile): int;
  {-Reads one byte from the compressed file.}
  {gzgetc returns this byte or -1 in case of end of file or error.}
var
  c: byte;
begin
  if gzread(f,@c,1)=1 then gzgetc := c else gzgetc := -1;
end;



{---------------------------------------------------------------------------}
function gzgets(f: gzfile; buf: PChar8; len: int): PChar8;
  {-Read a string from the compressed file}

  {Reads bytes from the compressed file until len-1 characters are read}
  {or a newline character is read and transferred to buf, or an end-of-file
  condition is encountered. The string is then zero-terminated.

  gzgets returns buf, or Z_NULL in case of error.
  The current implementation is not optimized at all.}

var
  b     : PChar8; {start of buffer}
  bytes : Int;   {number of bytes read by gzread}
  gzchar: char8;  {char read by gzread}
begin
  if (buf=Z_NULL) or (len<=0) then begin
    gzgets := Z_NULL;
    exit;
  end;

  b := buf;
  repeat
    dec(len);
    bytes := gzread(f, buf, 1);
    gzchar := buf^;
    inc(buf);
  until (len=0) or (bytes<>1) or (gzchar=chr(13));

  buf^ := chr(0);
  if (b=buf) and (len>0) then gzgets := Z_NULL else gzgets := b;
end;


{$ifndef NO_DEFLATE}


{---------------------------------------------------------------------------}
function gzwrite(f: gzfile; buf: voidp; len: uInt): int;
  {-Writes the given number of uncompressed bytes into the compressed file.}

  {gzwrite returns the number of uncompressed bytes actually written
  (0 in case of error).}
var
  s: gz_streamp;
  written: integer;
begin
  s := gz_streamp(f);
  if (s=nil) or (s^.mode<>'w') then begin
    gzwrite := Z_STREAM_ERROR;
    exit;
  end;

  with s^ do begin
    stream.next_in := pBytef(buf);
    stream.avail_in := len;
    while stream.avail_in<>0 do begin
      if stream.avail_out=0 then begin
        stream.next_out := outbuf;
        blockwrite(zfile, outbuf^, Z_BUFSIZE, written);
        if written<>Z_BUFSIZE then begin
          z_err := Z_ERRNO;
          break;
        end;
        stream.avail_out := Z_BUFSIZE;
      end;
      z_err := deflate(stream, Z_NO_FLUSH);
      if z_err<>Z_OK then break;
    end; {while}

    crc := crc32(crc, buf, len);
    gzwrite := int(len - stream.avail_in);
  end;
end;



{---------------------------------------------------------------------------}
function gzputc(f: gzfile; c: char8): int;
  {-Writes c, converted to an unsigned char, into the compressed file.}
  {gzputc returns the value that was written, or -1 in case of error.}
begin
  if gzwrite(f,@c,1)=1 then begin
    {$ifdef FPC}
      gzputc := int(ord(c))
    {$else}
      gzputc := int(c)
    {$endif}
  end
  else gzputc := -1;
end;


{---------------------------------------------------------------------------}
function gzputs(f: gzfile; s: PChar8): int;
  {-Writes the given null-terminated string to the compressed file}
  {the terminating null character is excluded}
  {gzputs returns the number of characters written, or -1 in case of error.}

  {$ifdef VER70}
    function StrLen(PS: PChar8): Word; assembler;
    asm
      cld
      les   di,PS
      mov   cx,0ffffh
      xor   al,al
      repne scasb
      mov   ax,0fffeh
      sub   ax,cx
    end;
  {$endif}
begin
  gzputs := gzwrite(f, voidp(s), strlen(s));
end;


{---------------------------------------------------------------------------}
function do_flush(f: gzfile; flush: int): int;
  {-Flushes all pending output into the compressed file.}
  {The parameter flush is as in the zdeflate() function.}
var
  len    : uInt;
  done   : boolean;
  s      : gz_streamp;
  written: unsigned; {*we May 2005}
begin
  done := false;
  s := gz_streamp(f);

  if (s=nil) or (s^.mode<>'w') then begin
    do_flush := Z_STREAM_ERROR;
    exit;
  end;

  with s^ do begin
    stream.avail_in := 0; {should be zero already anyway}

    while true do begin
      len := Z_BUFSIZE - stream.avail_out;
      if len<>0 then begin
        blockwrite(zfile, outbuf^, len, written);
        if written<>len then begin
          z_err := Z_ERRNO;
          do_flush := Z_ERRNO;
          exit;
        end;
        stream.next_out := outbuf;
        stream.avail_out := Z_BUFSIZE;
      end;

      if done then break;
      z_err := deflate(stream, flush);

      {Ignore the second of two consecutive flushes:}
      if (len=0) and (z_err=Z_BUF_ERROR) then z_err := Z_OK;

      {deflate has finished flushing only when it hasn't used up
      all the available space in the output buffer:}

      done := (stream.avail_out <> 0) or (z_err = Z_STREAM_END);
      if (z_err<>Z_OK) and (z_err<>Z_STREAM_END) then break;
    end; {while}

    if z_err=Z_STREAM_END then do_flush:=Z_OK else do_flush := z_err;
  end;
end;


{---------------------------------------------------------------------------}
function gzflush(f: gzfile; flush: int): int;
  {-Flushes all pending output into the compressed file.}

  {The parameter flush is as in the zdeflate() function.

  The return value is the zlib error number (see function gzerror below).
  gzflush returns Z_OK if the flush parameter is Z_FINISH and all output
  could be flushed.

  gzflush should be called only when strictly necessary because it can
  degrade compression.}
var
  err: int;
  s  : gz_streamp;
begin
  s := gz_streamp(f);
  err := do_flush(f, flush);
  if err<>0 then begin
    gzflush := err;
    exit;
  end;
  if s^.z_err=Z_STREAM_END then gzflush := Z_OK else gzflush := s^.z_err;
end;

{$endif} {NO DEFLATE}


{---------------------------------------------------------------------------}
function gzrewind(f: gzfile): int;
  {-Rewinds input file.}
var
  s: gz_streamp;
begin
  s := gz_streamp(f);
  if (s=nil) or (s^.mode<>'r') then begin
    gzrewind := -1;
    exit;
  end;

  with s^ do begin
    z_err := Z_OK;
    zs_eof := false;
    stream.avail_in := 0;
    stream.next_in := inbuf;
    crc := crc32(0, Z_NULL, 0);  {*we 113}

    if startpos=0 then begin {not a compressed file}
      seek(zfile, 0);
      gzrewind := 0;
      exit;
    end;

    inflateReset(stream);
    seek(zfile, startpos);
    gzrewind := int(IOResult);
  end;
end;


{---------------------------------------------------------------------------}
function gzseek(f: gzfile; offset: z_off_t; whence: int): z_off_t;
  {-Sets the starting position for the next gzread/gzwrite on the compressed file.}

  {The offset represents a number of bytes from the beginning
  of the uncompressed stream.

  gzseek returns the resulting offset, or -1 in case of error.
  SEEK_END is not implemented, returns error.
  In this version of the library, gzseek can be extremely slow.}

var
  s: gz_streamp;
  size: uInt;
begin
  s := gz_streamp(f);

  if (s=nil) or (whence=SEEK_END) or (s^.z_err=Z_ERRNO) or (s^.z_err=Z_DATA_ERROR) then begin
    gzseek := z_off_t(-1);
    exit;
  end;

  with s^ do begin
    if mode='w' then begin
      {$ifdef NO_DEFLATE}
        gzseek := z_off_t(-1);
        exit;
      {$else}
        if whence=SEEK_SET then dec(offset, stream.total_in);   {*we 113}
        if offset<0 then begin;
          gzseek := z_off_t(-1);
          exit;
        end;

        {At this point, offset is the number of zero bytes to write.}
        if inbuf = Z_NULL then begin
          GetMem(inbuf, Z_BUFSIZE);
          zmemzero(inbuf, Z_BUFSIZE);
        end;

        while offset>0 do begin
          size := Z_BUFSIZE;
          if offset<Z_BUFSIZE then size := uInt(offset);
          size := gzwrite(f, inbuf, size);
          if size=0 then begin
            gzseek := z_off_t(-1);
            exit;
          end;
          dec(offset,size);
        end;

        gzseek := z_off_t(stream.total_in);
        exit;
      {$endif}
    end;

    {Rest of function is for reading only}
    {compute absolute position}
    if whence=SEEK_CUR then inc(offset, stream.total_out);
    if offset<0 then begin
      gzseek := z_off_t(-1);
      exit;
    end;

    if transparent then begin
      stream.avail_in := 0;
      stream.next_in := inbuf;
      seek(zfile, offset);
      if IOResult<>0 then begin
        gzseek := z_off_t(-1);
        exit;
      end;

      stream.total_in := uLong(offset);
      stream.total_out := uLong(offset);
      gzseek := z_off_t(offset);
      exit;
    end;

    {For a negative seek, rewind and use positive seek}
    if uLong(offset) >= stream.total_out then dec(offset, stream.total_out)
    else if (gzrewind(f) <> 0) then begin
      gzseek := z_off_t(-1);
      exit;
    end;

    {offset is now the number of bytes to skip.}
    if (offset<>0) and (outbuf=Z_NULL) then GetMem(outbuf, Z_BUFSIZE);

    while offset>0 do begin
      size := Z_BUFSIZE;
      if offset<Z_BUFSIZE then size := int(offset);
      size := gzread(f, outbuf, size);
      if size<=0 then begin
        gzseek := z_off_t(-1);
        exit;
      end;
      dec(offset, size);
    end;

    gzseek := z_off_t(stream.total_out);
  end;
end;


{---------------------------------------------------------------------------}
function gztell(f: gzfile): z_off_t;
  {Returns the starting position for the next gzread or gzwrite on the given compressed file.}
  {This position represents a number of bytes in the uncompressed data stream.}
begin
  gztell := gzseek(f, 0, SEEK_CUR);
end;



{---------------------------------------------------------------------------}
function gzeof(f: gzfile): boolean;
  {-Returns true when EOF has previously been detected reading the given input stream, otherwise false.}
var
  s: gz_streamp;
begin
  s := gz_streamp(f);
  if (s=nil) or (s^.mode<>'r') then gzeof := false else gzeof := s^.zs_eof;
end;



{---------------------------------------------------------------------------}
procedure putLong(var f: file; x: uLong);
  {-Outputs a longint in LSB order to the given file}
var
  n: int;
  c: byte;
begin
  for n:=0 to 3 do begin
    c := x and $FF;
    blockwrite(f, c, 1);
    x := x shr 8;
  end;
end;


{---------------------------------------------------------------------------}
function gzclose(f: gzfile): int;
  {-Flushes all pending output if necessary, closes the compressed file}
  {and deallocates all the (de)compression state.}
  {The return value is the zlib error number (see function gzerror below)}
var
  err: int;
  s  : gz_streamp;
begin
  s := gz_streamp(f);
  if s=nil then begin
    gzclose := Z_STREAM_ERROR;
    exit;
  end;

  with s^ do begin
    if mode='w' then begin
      {$ifdef NO_DEFLATE}
        gzclose := Z_STREAM_ERROR;
        exit;
      {$else}
        err := do_flush(f, Z_FINISH);
        if err<>Z_OK then begin
          gzclose := destroy(gz_streamp(f));
          exit;
        end;
        putLong(zfile, crc);
        putLong(zfile, stream.total_in);
      {$endif}
    end;
  end;
  gzclose := destroy(gz_streamp(f));
end;



{---------------------------------------------------------------------------}
function gzerror(f: gzfile; var errnum: int): str255;
  {-Returns the error message for the last error which occured on the given compressed file.}
  {errnum is set to zlib error number. If an error occured in the file system
  and not in the compression library, errnum is set to Z_ERRNO and the
  application may consult errno to get the exact error code.}
var
  m : str255;
  s : gz_streamp;
begin
  s := gz_streamp(f);
  if s=nil then begin
    errnum := Z_STREAM_ERROR;
    gzerror := zError(Z_STREAM_ERROR);
    exit; {*we 05.2005}
  end;

  with s^ do begin
    errnum := z_err;
    if errnum=Z_OK then begin
      gzerror := zError(Z_OK);
      exit;
    end;

    m := stream.msg;
    if errnum=Z_ERRNO then m := '';
    if m='' then m := zError(z_err);

    msg := path+': '+m;
    gzerror := msg;
  end;
end;

begin
  GZ_windowBits := -MAX_WBITS;    {*we 0202}
  GZ_memLevel   := DEF_MEM_LEVEL; {allow variable windowbits/memlevel in gzopen}
end.
