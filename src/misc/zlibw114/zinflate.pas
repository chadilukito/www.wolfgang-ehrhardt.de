unit zInflate;

(************************************************************************
  inflate.c -- zlib interface to inflate modules
  Copyright (C) 1995-1998 Mark Adler

  Pascal translation
  Copyright (C) 1998 by Jacques Nomssi Nzali
  For conditions of distribution and use, see copyright notice in readme.txt

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:
  Feb 2002
    - Source code reformating/reordering
  Mar 2005
    - Code cleanup for WWW upload
  May 2005
    - Trace: use #13#10 like C original
  Jul 2009
    - D12 fixes
  Sep 2015
    - FPC 3 / FPC_Procvar

*************************************************************************)



interface

{$x+}

uses
   zlibh;

function inflateInit(var z: z_stream): int;
  {Initializes the internal stream state for decompression. The fields
   zalloc, zfree and opaque must be initialized before by the caller.  If
   zalloc and zfree are set to Z_NULL, inflateInit updates them to use default
   allocation functions.

     inflateInit returns Z_OK if success, Z_MEM_ERROR if there was not
   enough memory, Z_VERSION_ERROR if the zlib library version is incompatible
   with the version assumed by the caller.  msg is set to null if there is no
   error message. inflateInit does not perform any decompression: this will be
   done by inflate().}



function inflateInit_(z: z_streamp; const version: str255; stream_size: int): int;

function inflateInit2_(var z: z_stream; w: int; const version: str255; stream_size: int): int;

function inflateInit2(var z: z_stream; windowBits: int): int;

  {Thes are other versions of inflateInit with an extra parameter. The
   fields next_in, avail_in, zalloc, zfree and opaque must be initialized
   before by the caller.

     The windowBits parameter is the base two logarithm of the maximum window
   size (the size of the history buffer).  It should be in the range 8..15 for
   this version of the library. The default value is 15 if inflateInit is used
   instead. If a compressed stream with a larger window size is given as
   input, inflate() will return with the error code Z_DATA_ERROR instead of
   trying to allocate a larger window.

      inflateInit2 returns Z_OK if success, Z_MEM_ERROR if there was not enough
   memory, Z_STREAM_ERROR if a parameter is invalid (such as a negative
   memLevel). msg is set to null if there is no error message.  inflateInit2
   does not perform any decompression apart from reading the zlib header if
   present: this will be done by inflate(). (So next_in and avail_in may be
   modified, but next_out and avail_out are unchanged.)}



function inflateEnd(var z: z_stream): int;
  {All dynamically allocated data structures for this stream are freed.
   This function discards any unprocessed input and does not flush any
   pending output.

     inflateEnd returns Z_OK if success, Z_STREAM_ERROR if the stream state
   was inconsistent. In the error case, msg may be set but then points to a
   static string (which must not be deallocated).}

function inflateReset(var z: z_stream): int;
  {This function is equivalent to inflateEnd followed by inflateInit,
   but does not free and reallocate all the internal decompression state.
   The stream will keep attributes that may have been set by inflateInit2.

   inflateReset returns Z_OK if success, or Z_STREAM_ERROR if the source
   stream state was inconsistent (such as zalloc or state being NULL).}


function inflate(var z: z_stream; f: int): int;
  {inflate decompresses as much data as possible, and stops when the input
   buffer becomes empty or the output buffer becomes full. It may introduce
   some output latency (reading input without producing any output)
   except when forced to flush.

   The detailed semantics are as follows. inflate performs one or both of the
   following actions:

   - Decompress more input starting at next_in and update next_in and avail_in
     accordingly. If not all input can be processed (because there is not
     enough room in the output buffer), next_in is updated and processing
     will resume at this point for the next call of inflate().

   - Provide more output starting at next_out and update next_out and avail_out
     accordingly.  inflate() provides as much output as possible, until there
     is no more input data or no more space in the output buffer (see below
     about the flush parameter).

   Before the call of inflate(), the application should ensure that at least
   one of the actions is possible, by providing more input and/or consuming
   more output, and updating the next_* and avail_* values accordingly.
   The application can consume the uncompressed output when it wants, for
   example when the output buffer is full (avail_out == 0), or after each
   call of inflate(). If inflate returns Z_OK and with zero avail_out, it
   must be called again after making room in the output buffer because there
   might be more output pending.

     If the parameter flush is set to Z_SYNC_FLUSH, inflate flushes as much
   output as possible to the output buffer. The flushing behavior of inflate is
   not specified for values of the flush parameter other than Z_SYNC_FLUSH
   and Z_FINISH, but the current implementation actually flushes as much output
   as possible anyway.

     inflate() should normally be called until it returns Z_STREAM_END or an
   error. However if all decompression is to be performed in a single step
   (a single call of inflate), the parameter flush should be set to
   Z_FINISH. In this case all pending input is processed and all pending
   output is flushed; avail_out must be large enough to hold all the
   uncompressed data. (The size of the uncompressed data may have been saved
   by the compressor for this purpose.) The next operation on this stream must
   be inflateEnd to deallocate the decompression state. The use of Z_FINISH
   is never required, but can be used to inform inflate that a faster routine
   may be used for the single inflate() call.

      If a preset dictionary is needed at this point (see inflateSetDictionary
   below), inflate sets strm-adler to the adler32 checksum of the
   dictionary chosen by the compressor and returns Z_NEED_DICT; otherwise
   it sets strm->adler to the adler32 checksum of all output produced
   so far (that is, total_out bytes) and returns Z_OK, Z_STREAM_END or
   an error code as described below. At the end of the stream, inflate()
   checks that its computed adler32 checksum is equal to that saved by the
   compressor and returns Z_STREAM_END only if the checksum is correct.

     inflate() returns Z_OK if some progress has been made (more input processed
   or more output produced), Z_STREAM_END if the end of the compressed data has
   been reached and all uncompressed output has been produced, Z_NEED_DICT if a
   preset dictionary is needed at this point, Z_DATA_ERROR if the input data was
   corrupted (input stream not conforming to the zlib format or incorrect
   adler32 checksum), Z_STREAM_ERROR if the stream structure was inconsistent
   (for example if next_in or next_out was NULL), Z_MEM_ERROR if there was not
   enough memory, Z_BUF_ERROR if no progress is possible or if there was not
   enough room in the output buffer when Z_FINISH is used. In the Z_DATA_ERROR
   case, the application may then call inflateSync to look for a good
   compression block.}


function inflateSetDictionary(var z: z_stream; dictionary: pBytef; dictLength: uInt): int;

  {Initializes the decompression dictionary from the given uncompressed byte
   sequence. This function must be called immediately after a call of inflate
   if this call returned Z_NEED_DICT. The dictionary chosen by the compressor
   can be determined from the Adler32 value returned by this call of
   inflate. The compressor and decompressor must use exactly the same
   dictionary (see deflateSetDictionary).

     inflateSetDictionary returns Z_OK if success, Z_STREAM_ERROR if a
   parameter is invalid (such as NULL dictionary) or the stream state is
   inconsistent, Z_DATA_ERROR if the given dictionary doesn't match the
   expected one (incorrect Adler32 value). inflateSetDictionary does not
   perform any decompression: this will be done by subsequent calls of
   inflate().}

function inflateSync(var z: z_stream): int;
  {Skips invalid compressed data until a full flush point (see above the
  description of deflate with Z_FULL_FLUSH) can be found, or until all
  available input is skipped. No output is provided.

    inflateSync returns Z_OK if a full flush point has been found, Z_BUF_ERROR
  if no more input was provided, Z_DATA_ERROR if no flush point has been found,
  or Z_STREAM_ERROR if the stream structure was inconsistent. In the success
  case, the application may save the current current value of total_in which
  indicates where valid compressed data was found. In the error case, the
  application may repeatedly call inflateSync, providing more input each time,
  until success or end of the input data.}


function inflateSyncPoint(var z: z_stream): int;
  {-returns true if inflate is currently at the end of a block generated
    by Z_SYNC_FLUSH or Z_FULL_FLUSH.}


implementation


{$I zconf.inc}

uses
  adler, zutil, infblock, infutil;


{---------------------------------------------------------------------------}
function inflateReset(var z: z_stream): int;
begin
  with z do begin
    if state=Z_NULL then begin
      inflateReset :=  Z_STREAM_ERROR;
      exit;
    end;
    total_out := 0;
    total_in := 0;
    msg := '';
    with pInternal_state(state)^ do begin
      if nowrap then mode := _BLOCKS else mode := _METHOD;
      inflate_blocks_reset(blocks^, z, Z_NULL);
    end;
    {$ifdef DEBUG}
      Tracev('inflate: reset'#13#10);
    {$endif}
    inflateReset := Z_OK;
 end;
end;


{---------------------------------------------------------------------------}
function inflateEnd(var z: z_stream): int;
begin
  if (z.state = Z_NULL) or not Assigned(z.zfree) then
  begin
    inflateEnd :=  Z_STREAM_ERROR;
    exit;
  end;
  with pInternal_state(z.state)^ do begin
    if blocks<>Z_NULL then inflate_blocks_free(blocks, z);
  end;
  Z_FREE(z, z.state);
  z.state := Z_NULL;
  {$ifdef DEBUG}
    Tracev('inflate: end'#13#10);
  {$endif}
  inflateEnd :=  Z_OK;
end;


{---------------------------------------------------------------------------}
function inflateInit2_(var z: z_stream; w: int; const version: str255; stream_size: int): int;
begin
  if (version='') or (version[1]<>ZLIB_VERSION[1]) or (stream_size<>sizeof(z_stream)) then begin
    inflateInit2_ := Z_VERSION_ERROR;
    exit;
  end;
  {initialize state}
  {SetLength(strm.msg, 255);}
  z.msg := '';
  if not Assigned(z.zalloc) then begin
    {$ifdef FPC_Procvar}
      z.zalloc := @zcalloc;
    {$else}
      z.zalloc := zcalloc;
    {$endif}
    z.opaque := voidpf(0);
  end;
  if not Assigned(z.zfree) then  begin
    {$ifdef FPC_Procvar}
      z.zfree := @zcfree;
    {$else}
      z.zfree := zcfree;
    {$endif}
  end;

  z.state := pInternal_state(Z_ALLOC(z,1,sizeof(internal_state)));
  if z.state=Z_NULL then begin
    inflateInit2_ := Z_MEM_ERROR;
    exit;
  end;

  with pInternal_state(z.state)^ do begin
    blocks := Z_NULL;
    {handle undocumented nowrap option (no zlib header or check)}
    nowrap := false;
    if w<0 then begin
      w := - w;
      nowrap := true;
    end;

    {set window size}
    if (w < 8) or (w > 15) then begin
      inflateEnd(z);
      inflateInit2_ := Z_STREAM_ERROR;
      exit;
    end;
    wbits := uInt(w);

    {create inflate_blocks state}
    if nowrap then blocks := inflate_blocks_new(z, nil, uInt(1) shl w)
    else begin
      {$ifdef FPC_Procvar}
        blocks := inflate_blocks_new(z, @adler32, uInt(1) shl w);
      {$else}
        blocks := inflate_blocks_new(z, adler32, uInt(1) shl w);
      {$endif}
    end;
    if blocks=Z_NULL then begin
      inflateEnd(z);
      inflateInit2_ := Z_MEM_ERROR;
      exit;
    end;
  end;
  {$ifdef DEBUG}
  Tracev('inflate: allocated'#13#10);
  {$endif}
  {reset state}
  inflateReset(z);
  inflateInit2_ :=  Z_OK;
end;


{---------------------------------------------------------------------------}
function inflateInit2(var z: z_stream; windowBits: int): int;
begin
  inflateInit2 := inflateInit2_(z, windowBits, ZLIB_VERSION, sizeof(z_stream));
end;


{---------------------------------------------------------------------------}
function inflateInit(var z: z_stream): int;
begin
  inflateInit := inflateInit2_(z, DEF_WBITS, ZLIB_VERSION, sizeof(z_stream));
end;


{---------------------------------------------------------------------------}
function inflateInit_(z: z_streamp; const version: str255; stream_size: int): int;
begin
  {initialize state}
  if z=Z_NULL then inflateInit_ := Z_STREAM_ERROR
  else inflateInit_ := inflateInit2_(z^, DEF_WBITS, version, stream_size);
end;


{---------------------------------------------------------------------------}
function inflate(var z: z_stream; f: int): int;
var
  r: int;
  b: uInt;
begin
  if (z.state=Z_NULL) or (z.next_in=Z_NULL) then begin
    inflate := Z_STREAM_ERROR;
    exit;
  end;
  if f=Z_FINISH then f := Z_BUF_ERROR else f := Z_OK;

  r := Z_BUF_ERROR;

  with pInternal_state(z.state)^ do repeat

    case mode of

      _BLOCKS: begin
                 r := inflate_blocks(blocks^, z, r);
                 if r=Z_DATA_ERROR then begin
                   mode := _BAD;
                   sub.marker := 0;       {can try inflateSync}
                   continue;            {break C-switch}
                 end;
                 if r=Z_OK then r := f;
                 if r<>Z_STREAM_END then begin
                   inflate := r;
                   exit;
                 end;
                 r := f;
                 inflate_blocks_reset(blocks^, z, @sub.check.was);
                 if nowrap then begin
                   mode := _DONE;
                   continue;       {break C-switch}
                 end;
                 mode := _CHECK4;  {falltrough}
               end;

      _CHECK4: begin
                 {NEEDBYTE}
                 if z.avail_in=0 then begin
                   inflate := r;
                   exit;
                 end;
                 r := f;
                 {z.state^.sub.check.need := uLong(NEXTBYTE(z)) shl 24;}
                 dec(z.avail_in);
                 inc(z.total_in);
                 sub.check.need := uLong(z.next_in^) shl 24;
                 inc(z.next_in);
                 mode := _CHECK3;   {falltrough}
               end;

      _CHECK3: begin
                 {NEEDBYTE}
                 if z.avail_in=0 then begin
                   inflate := r;
                   exit;
                 end;
                 r := f;
                 {inc(z.state^.sub.check.need, uLong(NEXTBYTE(z)) shl 16);}
                 dec(z.avail_in);
                 inc(z.total_in);
                 inc(sub.check.need, uLong(z.next_in^) shl 16);
                 inc(z.next_in);
                 mode := _CHECK2;   {falltrough}
               end;

      _CHECK2: begin
                 {NEEDBYTE}
                 if z.avail_in=0 then begin
                   inflate := r;
                   exit;
                 end;
                 r := f;
                 {inc(z.state^.sub.check.need, uLong(NEXTBYTE(z)) shl 8);}
                 dec(z.avail_in);
                 inc(z.total_in);
                 inc(sub.check.need, uLong(z.next_in^) shl 8);
                 inc(z.next_in);
                 mode := _CHECK1;   {falltrough}
               end;

      _CHECK1: begin
                 {NEEDBYTE}
                 if z.avail_in=0 then begin
                   inflate := r;
                   exit;
                 end;
                 r := f;
                 {inc(z.state^.sub.check.need, uLong(NEXTBYTE(z)));}
                 dec(z.avail_in);
                 inc(z.total_in);
                 inc(sub.check.need, uLong(z.next_in^));
                 inc(z.next_in);
                 if sub.check.was<>sub.check.need then begin
                   mode := _BAD;
                   z.msg := 'incorrect data check';
                   sub.marker := 5;       {can't try inflateSync}
                   continue;           {break C-switch}
                 end;
                 {$ifdef DEBUG}
                   Tracev('inflate: zlib check ok'#13#10);
                 {$endif}
                 mode := _DONE; {falltrough}
               end;

        _DONE: begin
                 inflate := Z_STREAM_END;
                 exit;
               end;

      _METHOD: begin
                 {NEEDBYTE}
                 if z.avail_in=0 then begin
                   inflate := r;
                   exit;
                 end;
                 r := f;
                 {z.state^.sub.method := NEXTBYTE(z);}
                 dec(z.avail_in);
                 inc(z.total_in);
                 sub.method := z.next_in^;
                 inc(z.next_in);
                 if sub.method and $0f <> Z_DEFLATED then begin
                   mode := _BAD;
                   z.msg := 'unknown compression method';
                   sub.marker := 5;       {can't try inflateSync}
                   continue;  {break C-switch}
                 end;
                 if (sub.method shr 4) + 8 > wbits then begin
                   mode := _BAD;
                   z.msg := 'invalid window size';
                   sub.marker := 5;       {can't try inflateSync}
                   continue; {break C-switch}
                 end;
                 mode := _FLAG;
                 {fall trough}
               end;

        _FLAG: begin
                 {NEEDBYTE}
                 if z.avail_in=0 then begin
                   inflate := r;
                   exit;
                 end;
                 r := f;
                 {b := NEXTBYTE(z);}
                 dec(z.avail_in);
                 inc(z.total_in);
                 b := z.next_in^;
                 inc(z.next_in);
                 if (((sub.method shl 8) + b) mod 31) <> 0 then begin
                   mode := _BAD;
                   z.msg := 'incorrect header check';
                   sub.marker := 5;       {can't try inflateSync}
                   continue;      {break C-switch}
                 end;
                 {$ifdef DEBUG}
                   Tracev('inflate: zlib header ok'#13#10);
                 {$endif}
                 if (b and PRESET_DICT) = 0 then begin
                   mode := _BLOCKS;
                   continue;      {break C-switch}
                 end;
                 mode := _DICT4;
                 {falltrough}
               end;
       _DICT4: begin
                 if z.avail_in=0 then begin
                   inflate := r;
                   exit;
                 end;
                 r := f;
                 {z.state^.sub.check.need := uLong(NEXTBYTE(z)) shl 24;}
                 dec(z.avail_in);
                 inc(z.total_in);
                 sub.check.need :=  uLong(z.next_in^) shl 24;
                 inc(z.next_in);
                 mode := _DICT3;        {falltrough}
               end;

       _DICT3: begin
                 if z.avail_in=0 then begin
                   inflate := r;
                   exit;
                 end;
                 r := f;
                 {inc(z.state^.sub.check.need, uLong(NEXTBYTE(z)) shl 16);}
                 dec(z.avail_in);
                 inc(z.total_in);
                 inc(sub.check.need, uLong(z.next_in^) shl 16);
                 inc(z.next_in);
                 mode := _DICT2;        {falltrough}
               end;

       _DICT2: begin
                 if z.avail_in=0 then begin
                   inflate := r;
                   exit;
                 end;
                 r := f;
                 {inc(z.state^.sub.check.need, uLong(NEXTBYTE(z)) shl 8);}
                 dec(z.avail_in);
                 inc(z.total_in);
                 inc(sub.check.need, uLong(z.next_in^) shl 8);
                 inc(z.next_in);
                 mode := _DICT1;        {falltrough}
               end;

       _DICT1: begin
                 if z.avail_in=0 then begin
                   inflate := r;
                   exit;
                 end;
                 {r := f;    ---  wird niemals benutzt}
                 {inc(z.state^.sub.check.need, uLong(NEXTBYTE(z)));}
                 dec(z.avail_in);
                 inc(z.total_in);
                 inc(sub.check.need, uLong(z.next_in^));
                 inc(z.next_in);
                 z.adler := sub.check.need;
                 mode := _DICT0;
                 inflate := Z_NEED_DICT;
                 exit;
               end;

       _DICT0: begin
                 mode := _BAD;
                 z.msg := 'need dictionary';
                 sub.marker := 0;         {can try inflateSync}
                 inflate := Z_STREAM_ERROR;
                 exit;
               end;

         _BAD: begin
                 inflate := Z_DATA_ERROR;
                 exit;
               end;

         else begin
                inflate := Z_STREAM_ERROR;
                exit;
              end;
    end;
  until false;
  {$ifdef NEED_DUMMY_result}
    result := Z_STREAM_ERROR;  {Some dumb compilers complain without this}
  {$endif}
end;



{---------------------------------------------------------------------------}
function inflateSetDictionary(var z: z_stream; dictionary: pBytef; dictLength: uInt): int;
var
  length: uInt;
begin
  length := dictLength;

  if (z.state=Z_NULL) or (pInternal_state(z.state)^.mode<>_DICT0) then begin
    inflateSetDictionary := Z_STREAM_ERROR;
    exit;
  end;
  if (adler32(1, dictionary, dictLength) <> z.adler) then begin
    inflateSetDictionary := Z_DATA_ERROR;
    exit;
  end;
  z.adler := 1;

  with pInternal_state(z.state)^ do begin
    if length >= (uInt(1) shl wbits) then begin
      length := (uInt(1) shl wbits)-1;
      inc(dictionary, dictLength - length);
    end;
    inflate_set_dictionary(blocks^, dictionary^, length);
    mode := _BLOCKS;
  end;
  inflateSetDictionary := Z_OK;
end;


{---------------------------------------------------------------------------}
function inflateSync(var z: z_stream): int;
const
  mark: packed array[0..3] of byte = (0, 0, $ff, $ff);
var
  n: uInt;       {number of bytes to look at}
  p: pBytef;     {pointer to bytes}
  m: uInt;       {number of marker bytes found in a row}
  r, w: uLong;   {temporaries to save total_in and total_out}
begin
  {set up}
  if z.state=Z_NULL then begin
    inflateSync := Z_STREAM_ERROR;
    exit;
  end;

  with pInternal_state(z.state)^ do begin
    if mode<>_BAD then begin
      mode := _BAD;
      sub.marker := 0;
    end;
    n := z.avail_in;
    if n=0 then begin
      inflateSync := Z_BUF_ERROR;
      exit;
    end;
    p := z.next_in;
    m := sub.marker;

    {search}
    while (n <> 0) and (m < 4) do begin
      if (p^ = mark[m]) then inc(m)
      else if (p^ <> 0) then m := 0
      else m := 4 - m;
      inc(p);
      dec(n);
    end;

    {restore}
    inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
    z.next_in := p;
    z.avail_in := n;
    sub.marker := m;

    {return no joy or set up to restart on a new block}
    if m<>4 then begin
      inflateSync := Z_DATA_ERROR;
      exit;
    end;
    r := z.total_in;
    w := z.total_out;
    inflateReset(z);
    z.total_in := r;
    z.total_out := w;
    mode := _BLOCKS;
  end;
  inflateSync := Z_OK;
end;



{---------------------------------------------------------------------------}
function inflateSyncPoint(var z: z_stream): int;
  {returns true if inflate is currently at the end of a block generated
   by Z_SYNC_FLUSH or Z_FULL_FLUSH. This function is used by one PPP
   implementation to provide an additional safety check. PPP uses Z_SYNC_FLUSH
   but removes the length bytes of the resulting empty stored block. When
   decompressing, PPP checks that at the end of input packet, inflate is
   waiting for these length bytes.}
begin
  if (z.state=Z_NULL) or (pInternal_state(z.state)^.blocks=Z_NULL) then begin
    inflateSyncPoint := Z_STREAM_ERROR;
    exit;
  end;
  inflateSyncPoint := inflate_blocks_sync_point(pInternal_state(z.state)^.blocks^);
end;

end.
