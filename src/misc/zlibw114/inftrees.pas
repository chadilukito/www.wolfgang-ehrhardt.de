unit InfTrees;

(************************************************************************
  inftrees.h -- header to use inftrees.c
  inftrees.c -- generate Huffman trees for efficient decoding
  Copyright (C) 1995-2002 Mark Adler

  WARNING: this file should *not* be used by applications. It is
   part of the implementation of the compression library and is
   subject to change.

  Pascal translation
  Copyright (C) 1998 by Jacques Nomssi Nzali
  For conditions of distribution and use, see copyright notice in readme.txt

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:

  Aug 2000
    - ZLIB 113 changes
    - Pascal version of inffixed.h: table for decoding fixed codes
  Feb 2002
    - Source code reformating/reordering
  Mar 2002
    - ZLIB 114 changes
  Apr 2004
    - D4Plus instead of Delphi5Up
  Mar 2005
    - Code cleanup for WWW upload
  May 2005
    - make BUILDFIXED work and verify equivalence to fixed tables
  ------------------------------------------------------------------------

*************************************************************************)


interface

{$I zconf.inc}

uses
  zlibh, InfUtil;


{Maximum size of dynamic tree.  The maximum found in a long but non-
 exhaustive search was 1004 huft structures (850 for length/literals
 and 154 for distances, the latter actually the result of an
 exhaustive search).  The actual maximum is not known, but the
 value below is more than safe.}

const
  MANY = 1440;


function inflate_trees_bits(
              var  c: array of uIntf;        {19 code lengths}
              var bb: uIntf;                 {bits tree desired/actual depth}
              var tb: pinflate_huft;         {bits tree result}
              var hp: array of Inflate_huft; {space for trees}
              var  z: z_stream               {for messages}
         ): int;

function inflate_trees_dynamic(
                 nl: uInt;                   {number of literal/length codes}
                 nd: uInt;                   {number of distance codes}
             var  c: array of uIntf;         {that many (total) code lengths}
             var bl: uIntf;                  {literal desired/actual bit depth}
             var bd: uIntf;                  {distance desired/actual bit depth}
             var tl: pInflate_huft;          {literal/length tree result}
             var td: pInflate_huft;          {distance tree result}
             var hp: array of Inflate_huft;  {space for trees}
             var  z: z_stream                {for messages}
        ): int;

function inflate_trees_fixed (
             var bl: uInt;                   {literal desired/actual bit depth}
             var bd: uInt;                   {distance desired/actual bit depth}
             var tl: pInflate_huft;          {literal/length tree result}
             var td: pInflate_huft;          {distance tree result}
             var  z: z_stream                 {for memory allocation}
        ): int;


implementation


uses
  zutil;


const
  {Tables for deflate from PKZIP's appnote.txt.}
  cplens: array[0..30] of uInt  {Copy lengths for literal codes 257..285}
     = (3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0);
        {actually lengths - 2; also see note #13 above about 258}

  invalid_code = 112;

  cplext: array[0..30] of uInt  {Extra bits for literal codes 257..285}
     = (0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, invalid_code, invalid_code);

  cpdist: array[0..29] of uInt {Copy offsets for distance codes 0..29}
     = (1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
        8193, 12289, 16385, 24577);

  cpdext: array[0..29] of uInt {Extra bits for distance codes}
     = (0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
        12, 12, 13, 13);

 {Huffman code decoding is performed using a multi-level table lookup.
 The fastest way to decode is to simply build a lookup table whose
 size is determined by the longest code.  However, the time it takes
 to build this table can also be a factor if the data being decoded
 is not very long.  The most common codes are necessarily the
 shortest codes, so those codes dominate the decoding time, and hence
 the speed.  The idea is you can have a shorter table that decodes the
 shorter, more probable codes, and then point to subsidiary tables for
 the longer codes.  The time it costs to decode the longer codes is
 then traded against the time it takes to make longer tables.

 This results of this trade are in the variables lbits and dbits
 below.  lbits is the number of bits the first level table for literal/
 length codes can decode in one step, and dbits is the same thing for
 the distance codes.  Subsequent tables are also less than or equal to
 those sizes.  These values may be adjusted either when all of the
 codes are shorter than that, in which case the longest code length in
 bits is used, or when the shortest code is *longer* than the requested
 table size, in which case the length of the shortest code in bits is
 used.

 There are two different values for the two tables, since they code a
 different number of possibilities each.  The literal/length table
 codes 286 possible values, or in a flat code, a little over eight
 bits.  The distance table codes 30 possible values, or a little less
 than five bits, flat.  The optimum values for speed end up being
 about one bit more than those, so lbits is 8+1 and dbits is 5+1.
 The optimum values may differ though from machine to machine, and
 possibly even between compilers.  Your mileage may vary.}


 {If BMAX needs to be larger than 16, then h and x[] should be uLong.}
const
  BMAX = 15;         {maximum bit length of any code}


{$define USE_PTR}

{---------------------------------------------------------------------------}
function huft_build(
            var b: array of uIntf;        {code lengths in bits (all assumed <= BMAX)}
                n: uInt;                  {number of codes (assumed <= N_MAX)}
                s: uInt;                  {number of simple-valued codes (0..s-1)}
          const d: array of uIntf;        {list of base values for non-simple codes}
          const e: array of uIntf;        {list of extra bits for non-simple codes}
                t: ppInflate_huft;        {result: starting table}
            var m: uIntf;                 {maximum lookup bits, returns actual}
           var hp: array of inflate_huft; {space for trees}
           var hn: uInt;                  {hufts used in space}
            var v: array of uIntf         {working area: values in order of bit length}
         ): int;
 {Given a list of code lengths and a maximum table size, make a set of
 tables to decode that set of codes.  Return Z_OK on success, Z_BUF_ERROR
 if the given code set is incomplete (the tables are still built in this
 case), or Z_DATA_ERROR if the input is invalid}

var
  a: uInt;                     {counter for codes of length k}
  c: array[0..BMAX] of uInt;   {bit length count table}
  f: uInt;                     {i repeats in table every f entries}
  g: int;                      {maximum code length}
  h: int;                      {table level}
  i: uInt;  {register}         {counter, current code}
  j: uInt;  {register}         {counter}
  k: int;   {register}         {number of bits in current code}
  l: int;                      {bits per table (returned in m)}
  mask: uInt;                  {(1 shl w) - 1, to avoid cc -O bug on HP}
  p: ^uIntf; {register}        {pointer into c[], b[], or v[]}
  q: pInflate_huft;            {points to current table}
  r: inflate_huft;             {table entry for structure assignment}
  u: array[0..BMAX-1] of pInflate_huft; {table stack}
  w: int;   {register}         {bits before this table = (l*h)}
  x: array[0..BMAX] of uInt;   {bit offsets, then code stack}
  {$ifdef USE_PTR}
    xp: puIntf;                {pointer into x}
  {$else}
    xp: uInt;
  {$endif}
  y: int;                      {number of dummy codes added}
  z: uInt;                     {number of entries in current table}
begin
  {Generate counts for each bit length}
  fillchar(c,sizeof(c),0);             {clear c[]}

  for i := 0 to n-1 do inc (c[b[i]]);   {assume all entries <= BMAX}

  if (c[0] = n) then begin              {null input--all zero length codes}
    t^ := pInflate_huft(nil);
    m := 0;
    huft_build := Z_OK;
    exit;
  end;

  {Find minimum and maximum length, bound [m] by those}
  l := m;
  for j:=1 to BMAX do begin
    if c[j]<>0 then break;
  end;
  k := j;                      {minimum code length}

  if uInt(l)<j then l := j;
  for i := BMAX downto 1 do begin
    if c[i]<>0 then break;
  end;
  g := i;                      {maximum code length}

  if uInt(l)>i then l := i;
  m := l;

  {Adjust last length count to fill out codes, if needed}
  y := 1 shl j;
  while j<i do begin
    dec(y, c[j]);
    if y<0 then begin
      huft_build := Z_DATA_ERROR;   {bad input: more codes than bits}
      exit;
    end;
    inc(j);
    y := y shl 1
  end;
  dec(y, c[i]);

  if y<0 then begin
    huft_build := Z_DATA_ERROR;     {bad input: more codes than bits}
    exit;
  end;
  inc(c[i], y);

  {Generate starting offsets into the value table FOR each length}
  {$ifdef USE_PTR}
    x[1] := 0;
    j := 0;
    p := @c[1];
    xp := @x[2];
    dec(i);               {note that i = g from above}
    while i>0 do begin
      inc(j, p^);
      xp^ := j;
      inc(p);
      inc(xp);
      dec(i);
    end;
  {$else}
    x[1] := 0;
    j := 0;
    for i := 1 to g do begin
      x[i] := j;
      inc(j, c[i]);
    end;
  {$endif}

  {Make a table of values in order of bit lengths}
  for i := 0 to n-1 do begin
    j := b[i];
    if j<>0 then begin
      v[ x[j] ] := i;
      inc(x[j]);
    end;
  end;
  n := x[g];                     {set n to length of v}

  {Generate the Huffman codes and for each, make the table entries}
  i := 0;
  x[0] := 0;                   {first Huffman code is zero}
  p := addr(v);                {grab values in bit order}
  h := -1;                     {no tables yet--level -1}
  w := -l;                     {bits decoded = (l*h)}

  u[0] := pInflate_huft(nil);  {just to keep compilers happy}
  q := pInflate_huft(nil);     {ditto}
  z := 0;                      {ditto}

  {go through the bit lengths (k already is bits in shortest code)}
  while k<=g do begin
    a := c[k];
    while a<>0 do begin
      dec (a);
      {here i is the Huffman code of length k bits for value p^}
      {make tables up to required level}
      while k > w+l do begin
        inc (h);
        inc (w, l);              {add bits already decoded}
                                 {previous table always l bits}
        {compute minimum size table less than or equal to l bits}

        {table size upper limit}
        z := g - w;
        if z>uInt(l) then z := l;

        {try a k-w bit table}
        j := k - w;
        f := 1 shl j;
        if f>a+1 then begin       {too few codes for k-w bit table}
          dec(f, a+1);           {deduct codes from patterns left}
          {$ifdef USE_PTR}
            xp := addr(c[k]);
            if j<z then begin
              inc(j);
              while j<z do begin
                {try smaller tables up to z bits}
                f := f shl 1;
                inc (xp);
                if f<=xp^ then break;  {enough codes to use up j bits}
                dec(f, xp^);           {else deduct codes from patterns}
                inc(j);
              end;
            end;
          {$else}
            xp := k;
            if j<z then begin
              inc (j);
              while j<z do begin
                {try smaller tables up to z bits}
                f := f * 2;
                inc (xp);
                if f<=c[xp] then break; {enough codes to use up j bits}
                dec (f, c[xp]);         {else deduct codes from patterns}
                inc (j);
              end;
            end;
          {$endif}
        end;

        z := 1 shl j;            {table entries for j-bit table}

        {allocate new table}
        if hn+z > MANY then begin
          {(note: doesn't matter for fixed)}
          huft_build := Z_DATA_ERROR;   {overflow of MANY}  {*we 114}
          exit;
        end;

        q := @hp[hn];
        u[h] := q;
        inc(hn, z);

        {connect to last table, if there is one}
        if h<>0 then begin
          x[h] := i;             {save pattern for backing up}
          r.bits := byte(l);     {bits to dump before this table}
          r.exop := byte(j);     {bits in this table}
          j := i shr (w - l);
          {r.base := uInt(q - u[h-1] -j);}   {offset to this table}
          r.base := (ptr2int(q) - ptr2int(u[h-1])) div sizeof(q^) - j;
          huft_Ptr(u[h-1])^[j] := r;  {connect to last table}
        end
        else t^ := q;             {first table is returned result}
      end;

      {set up table entry in r}
      r.bits := byte(k - w);

      {C-code: if (p >= v + n) - see ZUTIL.PAS for comments}

      if ptr2int(p)>=ptr2int(@(v[n])) then begin {also works under DPMI ??}
        r.exop := 128 + 64                  {out of values--invalid code}
      end
      else begin
        if p^<s then begin
          if p^<256 then r.exop := 0 {256 is end-of-block code}
          else r.exop := 32 + 64;    {EOB_code;}
          r.base := p^;              {simple code is just the value}
          inc(p);
        end
        else begin
          r.exop := byte(e[p^-s] + 16 + 64);  {non-simple--look up in lists}
          r.base := d[p^-s];
          inc (p);
        end;
      end;
      {fill code-like entries with r}
      f := 1 shl (k - w);
      j := i shr w;
      while j<z do begin
        huft_Ptr(q)^[j] := r;
        inc(j, f);
      end;

      {backwards increment the k-bit code i}
      j := 1 shl (k-1);
      while (i and j)<>0 do begin
        i := i xor j;         {bitwise exclusive or}
        j := j shr 1
      end;
      i := i xor j;

      {backup over finished tables}
      mask := (1 shl w) - 1;   {needed on HP, cc -O bug}
      while (i and mask) <> x[h] do begin
        dec(h);                {don't need to update q}
        dec(w, l);
        mask := (1 shl w) - 1;
      end;

    end;

    inc(k);
  end;

  {Return Z_BUF_ERROR if we were given an incomplete table}
  if (y<>0) and (g<>1) then huft_build := Z_BUF_ERROR
  else huft_build := Z_OK;
end; {huft_build}


{---------------------------------------------------------------------------}
function inflate_trees_bits(
              var  c: array of uIntf;        {19 code lengths}
              var bb: uIntf;                 {bits tree desired/actual depth}
              var tb: pinflate_huft;         {bits tree result}
              var hp: array of Inflate_huft; {space for trees}
              var  z: z_stream               {for messages}
         ): int;
var
  r: int;
  v: PuIntArray;     {work area for huft_build}
  hn: uInt;          {hufts used in space}
begin
  hn := 0;
  v := PuIntArray(Z_ALLOC(z, 19, sizeof(uInt)));
  if v=Z_NULL then begin
    inflate_trees_bits := Z_MEM_ERROR;
    exit;
  end;

  r := huft_build(c, 19, 19, cplens, cplext, @tb, bb, hp, hn, v^);
  if r=Z_DATA_ERROR then z.msg := 'oversubscribed dynamic bit lengths tree'
  else begin
    if (r=Z_BUF_ERROR) or (bb=0) then begin
      z.msg := 'incomplete dynamic bit lengths tree';
      r := Z_DATA_ERROR;
    end;
  end;
  Z_FREE(z, v);
  inflate_trees_bits := r;
end;


{---------------------------------------------------------------------------}
function inflate_trees_dynamic(
                 nl: uInt;                   {number of literal/length codes}
                 nd: uInt;                   {number of distance codes}
             var  c: array of uIntf;         {that many (total) code lengths}
             var bl: uIntf;                  {literal desired/actual bit depth}
             var bd: uIntf;                  {distance desired/actual bit depth}
             var tl: pInflate_huft;          {literal/length tree result}
             var td: pInflate_huft;          {distance tree result}
             var hp: array of Inflate_huft;  {space for trees}
             var  z: z_stream                {for messages}
        ): int;
var
  r: int;
  v: PuIntArray;     {work area for huft_build}
  hn: uInt;          {hufts used in space}
begin
  hn := 0;
  {allocate work area}
  v := PuIntArray(Z_ALLOC(z, 288, sizeof(uInt)));
  if v=Z_NULL then begin
    inflate_trees_dynamic := Z_MEM_ERROR;
    exit;
  end;

  {build literal/length tree}
  r := huft_build(c, nl, 257, cplens, cplext, @tl, bl, hp, hn, v^);
  if (r<>Z_OK) or (bl=0) then begin
    if r=Z_DATA_ERROR then z.msg := 'oversubscribed literal/length tree'
    else begin
      if r<>Z_MEM_ERROR then begin
        z.msg := 'incomplete literal/length tree';
        r := Z_DATA_ERROR;
      end;
    end;
    Z_FREE(z, v);
    inflate_trees_dynamic := r;
    exit;
  end;

  {build distance tree}
  r := huft_build(puIntArray(@c[nl])^, nd, 0, cpdist, cpdext, @td, bd, hp, hn, v^);
  if (r<>Z_OK) or ((bd=0) and (nl>257)) then begin
    if r=Z_DATA_ERROR then z.msg := 'oversubscribed literal/length tree'
    else begin
      {$ifdef PKZIP_BUG_WORKAROUND}
        if r=Z_BUF_ERROR then r := Z_OK;
      {$else}
        if r=Z_BUF_ERROR then begin
          z.msg := 'incomplete literal/length tree';
          r := Z_DATA_ERROR;
        end
        else if r<>Z_MEM_ERROR then begin
          z.msg := 'empty distance tree with lengths';
          r := Z_DATA_ERROR;
        end;
        Z_FREE(z, v);
        inflate_trees_dynamic := r;
        exit;
      {$endif}
    end;
  end;

  {done}
  Z_FREE(z, v);
  inflate_trees_dynamic := Z_OK;
end;


{$ifdef BUILDFIXED}               {*we W0800}
  {build fixed tables only once--keep them here}
  {$ifdef D4Plus}
    var
      fixed_built: boolean = false;
  {$else}
    const
      fixed_built: boolean = false;
  {$endif}
  const
    FIXEDH = 544;      {number of hufts used by fixed tables}
  var
    fixed_mem: array[0..FIXEDH-1] of inflate_huft;
    fixed_bl : uInt;
    fixed_bd : uInt;
    fixed_tl : pInflate_huft;
    fixed_td : pInflate_huft;
{$else}
  {$i inffixed.inc} {*we W0800}
{$endif}

{---------------------------------------------------------------------------}
function inflate_trees_fixed (
             var bl: uInt;                   {literal desired/actual bit depth}
             var bd: uInt;                   {distance desired/actual bit depth}
             var tl: pInflate_huft;          {literal/length tree result}
             var td: pInflate_huft;          {distance tree result}
             var  z: z_stream                {for memory allocation}
        ): int;

{$ifdef BUILDFIXED}               {*we W0800}
type
  pFixed_table = ^fixed_table;
  fixed_table = array[0..288-1] of uIntf;
var
  k: int;                   {temporary variable}
  c: pFixed_table;          {length list for huft_build}
  v: PuIntArray;            {work area for huft_build}
var
  f: uInt;                  {number of hufts used in fixed_mem}
{$endif}

begin

{$ifdef BUILDFIXED}               {*we W0800}
  {build fixed tables if not already (multiple overlapped executions ok)}
  if not fixed_built then begin
    f := 0;
    {allocate memory}
    c := pFixed_table(Z_ALLOC(z, 288, sizeof(uInt)));
    if c=Z_NULL then begin
      inflate_trees_fixed := Z_MEM_ERROR;
      exit;
    end;
    v := PuIntArray(Z_ALLOC(z, 288, sizeof(uInt)));
    if v=Z_NULL then begin
      Z_FREE(z, c);
      inflate_trees_fixed := Z_MEM_ERROR;
      exit;
    end;

    {literal table}
    for k :=   0 to pred(144) do c^[k] := 8;
    for k := 144 to pred(256) do c^[k] := 9;
    for k := 256 to pred(280) do c^[k] := 7;
    for k := 280 to pred(288) do c^[k] := 8;
    fixed_bl := 9;
    {*we05.2005: k := ..}
    k := huft_build(c^, 288, 257, cplens, cplext, @fixed_tl, fixed_bl, fixed_mem, f, v^);

    {distance table}
    for k := 0 to pred(30) do c^[k] := 5;
    fixed_bd := 5;

    {k will be Z_BUF_ERROR (same as in original C), should be ignored}
    {*we05.2005: k := ..}
    k := huft_build(c^, 30, 0, cpdist, cpdext, @fixed_td, fixed_bd, fixed_mem, f, v^);

    {done}
    Z_FREE(z, v);
    Z_FREE(z, c);
    fixed_built := true;
  end;

  tl := fixed_tl;
  td := fixed_td;

{$else}
  tl := @fixed_tl[0];      {*we W0800}
  td := @fixed_td[0];      {*we W0800}
{$endif}  {*we W0800}

  bl := fixed_bl;
  bd := fixed_bd;
  inflate_trees_fixed := Z_OK;
end; {inflate_trees_fixed}


end.
