unit zlibex;

(*************************************************************************

 DESCRIPTION     :  Customizable inflate and deflate zlib routines

 REQUIREMENTS    :  TP7, D1-D7/9/10, FPC, VP

 EXTERNAL DATA   :  ---

 MEMORY USAGE    :  64K (2*CHUNK) heap for buffers + zlib memory

 DISPLAY MODE    :  ---

 REFERENCES      :  zpipe.c: example of proper use of zlib's inflate() and
                    deflate(), Version 1.2, 9 Nov. 2004  Mark Adler
                    http://www.gzip.org/zlib/zlib_how.html

 Version  Date      Author      Modification
 -------  --------  -------     ------------------------------------------
 0.10     08.04.05  WEhrhardt   Pascal translation of zpipe.c
 0.20     03.05.05  we          replaced blockread/write with ReadF/WriteF
 0.21     03.05.05  we          dynamic in/out buffers
 0.22     03.05.05  we          xread/xwrite: n now unsigned
 0.23     03.05.05  we          D4+ and FPC adjustments
 0.24     03.05.05  we          new names: userdata, bread, bwrite
 0.25     03.05.05  we          Comments, new names: DefFile, InfFile
 0.26     06.05.05  we          Asserts, changed DeflateEx OK logic
 0.27     07.05.05  we          More comments
 0.28     15.07.08  we          avoid buggy Delphi eof for large files
**************************************************************************)


{$i-,x+}


interface


uses zlibh, zlib;


type
  TZReadF  = function(bufp, userdata: pointer; mlen: word; var done: boolean): longint;
             {-callback to 'read' up to mlen bytes into bufp^. done should}
             { be set if all data is 'read'. Function result is number of }
             { bytes actually 'read' or negative if error.                }
             { userdata is a pointer (to a structure) containing infos to }
             { customize the processing, e.g. files, crypto contexts etc  }

  TZWriteF = function(bufp, userdata: pointer; size: word): longint;
             {-callback to 'write' size bytes from bufp^. Function result }
             { is number of bytes actually 'written' or negative if error }
             { userdata is a pointer (to a structure) containing infos to }
             { customize the processing, e.g. files, crypto contexts etc  }



function InflateEx(ReadF: TZReadF; WriteF: TZWriteF; userdata: pointer): longint;
  {-Decompress data read by ReadF and writes it with WriteF using userdata}
  { DeflateEx returns Z_OK on success, Z_MEM_ERROR if memory could not be }
  { allocated for processing, Z_STREAM_ERROR if an invalid compression    }
  { level is supplied, or Z_ERRNO if there is an read/write error.        }

function DeflateEx(ReadF: TZReadF; WriteF: TZWriteF; level: int; userdata: pointer): longint;
  {-Compress data read by ReadF and writes it with WriteF using userdata  }
  { DeflateEx returns Z_OK on success, Z_MEM_ERROR if memory could not be }
  { allocated for processing, Z_DATA_ERROR if the deflate data is invalid }
  { or incomplete, or Z_ERRNO if there is an read/write error.            }

function DefFile(var source, dest: file; level: int): int;
  {-Compress from file source to file dest until EOF on source.         }
  { def() returns Z_OK on success, Z_MEM_ERROR if memory could not be   }
  { allocated for processing, Z_STREAM_ERROR if an invalid compression  }
  { level is supplied, Z_VERSION_ERROR if the version of zlib.h and the }
  { version of the library linked do not match, or Z_ERRNO if there is  }
  { an error reading or writing the files.                              }

function InfFile(var source, dest: file): int;
  {-Decompress from file source to file dest until stream ends or EOF.  }
  { inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be   }
  { allocated for processing, Z_DATA_ERROR if the deflate data is       }
  { invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and }
  { the version of the library linked do not match, or Z_ERRNO if there }
  { is an error reading or writing the files.                           }


implementation

{$ifdef FPC}
  {$define FPC_ProcVar}
  {$ifdef FPC_DELPHI}
    {$undef FPC_ProcVar}
  {$endif}
  {$ifdef FPC_TP}
    {$undef FPC_ProcVar}
  {$endif}
  {$ifdef FPC_GPC}
    {$undef FPC_ProcVar}
  {$endif}
{$else}
  {$undef FPC_ProcVar}
{$endif}


{buffer types for InflateEx/DeflateEx buffers}
const
  CHUNK=$8000;

type
  TZLXBuffer = array[0..CHUNK-1] of byte;
  PZLXBuffer = ^TZLXBuffer;


{---------------------------------------------------------------------------}
function InflateEx(ReadF: TZReadF; WriteF: TZWriteF; userdata: pointer): longint;
  {-Decompress data read by ReadF and writes it with WriteF using userdata}
  { DeflateEx returns Z_OK on success, Z_MEM_ERROR if memory could not be}
  { allocated for processing, Z_STREAM_ERROR if an invalid compression   }
  { level is supplied, or Z_ERRNO if there is an read/write error.       }
var
  ret: int;
  n,have: longint;
  pin, pout: PZLXBuffer;
  strm: z_stream;
  done: boolean;

  {-------------------------------------}
  procedure cleanup;
    {-clean up strm and buffer memory}
  begin
    inflateEnd(strm);
    freemem(pout,sizeof(TZLXBuffer));
    freemem(pin,sizeof(TZLXBuffer));
  end;

begin
  {allocate inflate state}
  strm.zalloc := nil;
  strm.zfree  := nil;
  strm.opaque := nil;

  strm.avail_in := 0;
  strm.next_in  := nil;
  ret := inflateInit(strm);
  if ret<>Z_OK then begin
    InflateEx := ret;
    exit;
  end;

  {allocate buffers}
  getmem(pout,sizeof(TZLXBuffer));
  getmem(pin,sizeof(TZLXBuffer));

  {decompress until deflate stream ends or end of file}
  repeat
    n := ReadF(pin, userdata, CHUNK, done);
    if n<0 then begin
      {negative n signals IO error}
      cleanup;
      InflateEx := Z_ERRNO;
      exit;
    end;

    {breaks and uses last ret code from inflateInit/inflate}
    if n=0 then break;

    strm.avail_in := n;
    strm.next_in  := pBytef(pin);

    {run inflate() on input until output buffer not full}
    repeat
      strm.avail_out := CHUNK;
      strm.next_out  := pBytef(pout);
      ret := inflate(strm, Z_NO_FLUSH);
      {$ifdef debug}
        assert(ret<>Z_STREAM_ERROR,'InflateEx: ret<>Z_STREAM_ERROR');  {state not clobbered}
      {$endif}
      case ret of
         Z_NEED_DICT,
         Z_MEM_ERROR,
         Z_DATA_ERROR: begin
                         {translate Z_NEED_DICT to Z_DATA_ERROR}
                         if ret=Z_NEED_DICT then ret := Z_DATA_ERROR;
                         cleanup;
                         InflateEx := ret;
                         exit;
                       end;
      end;
      have := CHUNK - strm.avail_out;
      n := WriteF(pout, userdata, have);
      if have<>n then begin
        {have is postive, so IO error (negative n) is captured here}
        cleanup;
        InflateEx := Z_ERRNO;
        exit;
      end;
    until strm.avail_out<>0;
    {$ifdef debug}
      assert(strm.avail_in=0, 'InflateEx: strm.avail_in=0');  {all input will be used}
    {$endif}

    {done when inflate() says it's done}
  until ret=Z_STREAM_END;

  {clean up and return}
  cleanup;
  if ret=Z_STREAM_END then InflateEx := Z_OK
  else InflateEx := Z_DATA_ERROR;
end;


{---------------------------------------------------------------------------}
function DeflateEx(ReadF: TZReadF; WriteF: TZWriteF; level: int; userdata: pointer): longint;
  {-Compress data read by ReadF and writes it with WriteF using userdata }
  { DeflateEx returns Z_OK on success, Z_MEM_ERROR if memory could not be}
  { allocated for processing, Z_DATA_ERROR if the deflate data is invalid}
  { or incomplete, or Z_ERRNO if there is an read/write error.           }
var
  ret, flush: int;
  have,n: longint;
  pin, pout: PZLXBuffer;
  strm: z_stream;
  done,OK: boolean;

  {-------------------------------------}
  procedure cleanup;
    {-clean up strm and buffer memory}
  begin
    deflateEnd(strm);
    freemem(pout,sizeof(TZLXBuffer));
    freemem(pin,sizeof(TZLXBuffer));
  end;

begin
  {allocate deflate state}
  strm.zalloc := nil;
  strm.zfree  := nil;
  strm.opaque := nil;
  ret := deflateInit(strm, level);
  if ret<>Z_OK then begin
    DeflateEx := ret;
    exit;
  end;
  {allocate buffers}
  getmem(pout,sizeof(TZLXBuffer));
  getmem(pin,sizeof(TZLXBuffer));
  {compress until end of file}
  repeat
    n := ReadF(pin, userdata, CHUNK, done);
    if n<0 then begin
      cleanup;
      DeflateEx := Z_ERRNO;
      exit;
    end;
    strm.avail_in := n;

    {done must be used to signal Z_FINISH in case that input}
    {size is an exact multiple of CHUNK, see zlib_how.html  }
    if done then flush := Z_FINISH else flush := Z_NO_FLUSH;
    strm.next_in := pBytef(pin);

    {run deflate() on input until output buffer not full,}
    {finish compression if all of source has been read in}
    repeat
      strm.avail_out := CHUNK;
      strm.next_out  := pBytef(pout);
      ret  := deflate(strm, flush);
      have := CHUNK - strm.avail_out;
      OK := (ret=Z_OK) or (ret=Z_STREAM_END);
      if OK then begin
        n := WriteF(pout, userdata, have);
        if have<>n then begin
          OK  := false;
          ret := Z_ERRNO;
        end;
      end;
      if not OK then begin
        {Deflate or WriteF error}
        cleanup;
        if ret<>0 then DeflateEx := ret
        else DeflateEx := Z_ERRNO;
        exit;
      end;
    until strm.avail_out<>0;
    {$ifdef debug}
      assert(strm.avail_in=0, 'DeflateEx: strm.avail_in=0');  {all input will be used}
    {$endif}
    {done when last data in file processed}
  until flush=Z_FINISH;
  {$ifdef debug}
    assert(ret=Z_STREAM_END, 'DeflateEx: ret=Z_STREAM_END');  {stream will be complete}
  {$endif}

  {clean up and return}
  cleanup;
  DeflateEx := Z_OK;
end;


{---------------------------------------------------------------------------}
{zpipe functions as special cases for zlibex callbacks                      }
{---------------------------------------------------------------------------}

{userdata record for simple file IO call backs a la zpipe}
type
  TTwoFiles = record
                pf1,pf2: ^file;
              end;
  PTwoFiles = ^TTwoFiles;


{---------------------------------------------------------------------------}
function bread(bufp,userdata: pointer; mlen: word; var done: boolean): longint; {$ifndef FPC} far; {$endif}
  {-read callback function}
var
  n: unsigned;
begin
  blockread(PTwoFiles(userdata)^.pf1^, bufp^, mlen, n);
  if IOResult<>0 then begin
    bread := -1;
    done  := true;
  end
  else begin
    bread := n;
    done  := n=0;
    {0.28: avoid buggy Delphi eof for large files}
    {done := eof(PTwoFiles(userdata)^.pf1^);}
  end;
end;


{---------------------------------------------------------------------------}
function bwrite(bufp,userdata: pointer; size: word): longint; {$ifndef FPC} far; {$endif}
  {-write callback function}
var
  n: unsigned;
begin
  blockwrite(PTwoFiles(userdata)^.pf2^, bufp^, size, n);
  if IOResult<>0 then bwrite := -1 else bwrite := n;
end;


{---------------------------------------------------------------------------}
function InfFile(var source, dest: file): int;
  {-Decompress from file source to file dest until stream ends or EOF.  }
  { inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be   }
  { allocated for processing, Z_DATA_ERROR if the deflate data is       }
  { invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and }
  { the version of the library linked do not match, or Z_ERRNO if there }
  { is an error reading or writing the files.                           }

var
  tf: TTwoFiles;
begin
  tf.pf1 := @source;
  tf.pf2 := @dest;
{$ifdef FPC_Procvar}
  InfFile := InflateEx(@bread, @bwrite, @tf);
{$else}
  InfFile := InflateEx(bread, bwrite, @tf);
{$endif}
end;


{---------------------------------------------------------------------------}
function DefFile(var source, dest: file; level: int): int;
  {-Compress from file source to file dest until EOF on source.         }
  { def() returns Z_OK on success, Z_MEM_ERROR if memory could not be   }
  { allocated for processing, Z_STREAM_ERROR if an invalid compression  }
  { level is supplied, Z_VERSION_ERROR if the version of zlib.h and the }
  { version of the library linked do not match, or Z_ERRNO if there is  }
  { an error reading or writing the files.                              }
var
  tf: TTwoFiles;
begin
  tf.pf1 := @source;
  tf.pf2 := @dest;
{$ifdef FPC_Procvar}
  DefFile := DeflateEx(@bread, @bwrite, level, @tf);
{$else}
  DefFile := DeflateEx(bread, bwrite, level, @tf);
{$endif}
end;


end.
