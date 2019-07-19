unit zpipe;

(*************************************************************************

 DESCRIPTION     :  zlib's inflate() and deflate() made easy

 REQUIREMENTS    :  TP7, D1-D7/9/10, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  zlib memory + (2 buffers on stack)

 DISPLAY MODE    :  ---

 REFERENCES      :  zpipe.c: example of proper use of zlib's inflate() and
                    deflate(), Version 1.2, 9 Nov. 2004  Mark Adler


 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     08.04.05  WEhrhardt   Pascal translation of zpipe.c
 0.11     03.05.05  we          separated unit and test program
 0.12     13.07.08  we          avoid buggy Delphi eof for large files
**************************************************************************)


{$i-,x+}


interface


uses zlibh, zlib;


function def(var source, dest: file; level: int): int;
  {-Compress from file source to file dest until EOF on source.
    def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
    allocated for processing, Z_STREAM_ERROR if an invalid compression
    level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
    version of the library linked do not match, or Z_ERRNO if there is
    an error reading or writing the files.}


function inf(var source, dest: file): int;
  {-Decompress from file source to file dest until stream ends or EOF.
    inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
    allocated for processing, Z_DATA_ERROR if the deflate data is
    invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
    the version of the library linked do not match, or Z_ERRNO if there
    is an error reading or writing the files.}



implementation


{buffer size for Inflate/Deflate buffers}
const
 CHUNK=$1000;


{---------------------------------------------------------------------------}
function def(var source, dest: file; level: int): int;
  {-Compress from file source to file dest until EOF on source.
    def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
    allocated for processing, Z_STREAM_ERROR if an invalid compression
    level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
    version of the library linked do not match, or Z_ERRNO if there is
    an error reading or writing the files.}
var
  ret, flush: int;
  have,n: unsigned;
  strm: z_stream;
  inb, outb: array[0..CHUNK-1] of byte;
begin
  {allocate deflate state}
  strm.zalloc := nil;
  strm.zfree  := nil;
  strm.opaque := nil;
  ret := deflateInit(strm, level);
  if ret<>Z_OK then begin
    def := ret;
    exit;
  end;
  {compress until end of file}
  repeat
    blockread(source, inb, CHUNK, strm.avail_in);
    if IOResult<>0 then begin
      deflateEnd(strm);
      def := Z_ERRNO;
      exit;
    end;
    {0.12: avoid buggy Delphi eof for large files and use}
    {strm.avail_in=0 for eof(source)}

    if strm.avail_in=0 then flush := Z_FINISH else flush := Z_NO_FLUSH;

    strm.next_in := pBytef(@inb);

    {run deflate() on input until output buffer not full, finish
     compression if all of source has been read in}
    repeat
      strm.avail_out := CHUNK;
      strm.next_out  := pBytef(@outb);
      deflate(strm, flush);   {no bad return value}
      {assert(ret != Z_STREAM_ERROR);  /* state not clobbered */}
      have := CHUNK - strm.avail_out;
      blockwrite(dest, outb, have, n);
      if (IOresult<>0) or (have<>n) then begin
        deflateEnd(strm);
        def := Z_ERRNO;
        exit;
      end;
    until strm.avail_out<>0;

    {assert(strm.avail_in == 0);     /* all input will be used */}

    {done when last data in file processed}
  until flush=Z_FINISH;
  {assert(ret == Z_STREAM_END);        /* stream will be complete */}

  {clean up and return}
  deflateEnd(strm);
  def := Z_OK;
end;


{---------------------------------------------------------------------------}
function inf(var source, dest: file): int;
  {-Decompress from file source to file dest until stream ends or EOF.
    inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
    allocated for processing, Z_DATA_ERROR if the deflate data is
    invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
    the version of the library linked do not match, or Z_ERRNO if there
    is an error reading or writing the files.}
var
  ret: int;
  have,n: unsigned;
  strm: z_stream;
  inb, outb: array[0..CHUNK-1] of byte;
begin
  {allocate inflate state}
  strm.zalloc := nil;
  strm.zfree  := nil;
  strm.opaque := nil;

  strm.avail_in := 0;
  strm.next_in  := nil;
  ret := inflateInit(strm);
  if ret<>Z_OK then begin
    inf := ret;
    exit;
  end;

  {decompress until deflate stream ends or end of file}
  repeat
    blockread(source, inb, chunk, strm.avail_in);
    if IOResult<>0 then begin
      inflateEnd(strm);
      inf := Z_ERRNO;
      exit;
    end;
    if strm.avail_in=0 then break;
    strm.next_in := pBytef(@inb);

    {run inflate() on input until output buffer not full}
    repeat
      strm.avail_out := CHUNK;
      strm.next_out  := pBytef(@outb);
      ret := inflate(strm, Z_NO_FLUSH);
      {assert(ret != Z_STREAM_ERROR);  /* state not clobbered */}
      case ret of
          Z_NEED_DICT: begin
                         inf := Z_DATA_ERROR;
                         inflateEnd(strm);
                         exit;
                       end;
         Z_MEM_ERROR,
         Z_DATA_ERROR: begin
                         inflateEnd(strm);
                         inf := ret;
                         exit;
                       end;
      end;
      have := CHUNK - strm.avail_out;
      blockwrite(dest, outb, have, n);
      if (IOresult<>0) or (have<>n) then begin
        inflateEnd(strm);
        inf := Z_ERRNO;
        exit;
      end;
    until strm.avail_out<>0;
    {assert(strm.avail_in == 0);     /* all input will be used */}

    {done when inflate() says it's done}
  until ret=Z_STREAM_END;

  {clean up and return}
  inflateEnd(strm);
  if ret=Z_STREAM_END then inf := Z_OK
  else inf := Z_DATA_ERROR;
end;


end.
