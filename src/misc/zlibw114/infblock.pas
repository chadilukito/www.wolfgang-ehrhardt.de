unit InfBlock;

(************************************************************************

  infblock.h and
  infblock.c -- interpret and process block types to last block
  Copyright (C) 1995-2002 Mark Adler

  Pascal translation
  Copyright (C) 1998 by Jacques Nomssi Nzali
  For conditions of distribution and use, see copyright notice in readme.txt

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:

  Aug 2000
    - ZLIB 113 changes
  Feb 2002
    - Source code reformating/reordering
  Mar 2002
    - ZLIB 114 changes
  Mar 2005
    - Code cleanup for WWW upload
  May 2005
    - Trace: use #13#10 like C original
  ------------------------------------------------------------------------

*************************************************************************)


interface

{$x+}


uses
  zlibh, infutil;

function inflate_blocks_new(var z: z_stream;
                                c: check_func;  {check function}
                                w: uInt     {window size}
                           ): pInflate_blocks_state;

function inflate_blocks(var s: inflate_blocks_state;
                        var z: z_stream;
                            r: int             {initial return code}
                       ): int;

procedure inflate_blocks_reset(var s: inflate_blocks_state; var z: z_stream; c: puLong);


function inflate_blocks_free(s: pInflate_blocks_state; var z: z_stream): int;

procedure inflate_set_dictionary(  var s: inflate_blocks_state;
                                 const d: array of byte;  {dictionary}
                                       n: uInt);         {dictionary length}

function inflate_blocks_sync_point(var s: inflate_blocks_state): int;


implementation

{$I zconf.inc}

uses
  zutil, infcodes, inftrees;

{Tables for deflate from PKZIP's appnote.txt.}
const
  border: array [0..18] of word  {Order of the bit length code lengths}
    = (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15);

{Notes beyond the 1.93a appnote.txt:

   1. Distance pointers never point before the beginning of the output
      stream.
   2. Distance pointers can point back across blocks, up to 32k away.
   3. There is an implied maximum of 7 bits for the bit length table and
      15 bits for the actual data.
   4. If only one code exists, then it is encoded using one bit.  (Zero
      would be more efficient, but perhaps a little confusing.)  If two
      codes exist, they are coded using one bit each (0 and 1).
   5. There is no way of sending zero distance codes--a dummy must be
      sent if there are none.  (History: a pre 2.0 version of PKZIP would
      store blocks with no distance codes, but this was discovered to be
      too harsh a criterion.)  Valid only for 1.93a.  2.04c does allow
      zero distance codes, which is sent as one code of zero bits in
      length.
   6. There are up to 286 literal/length codes.  Code 256 represents the
      end-of-block.  Note however that the static length tree defines
      288 codes just to fill out the Huffman codes.  Codes 286 and 287
      cannot be used though, since there is no length base or extra bits
      defined for them.  Similarily, there are up to 30 distance codes.
      However, static trees define 32 codes (all 5 bits) to fill out the
      Huffman codes, but the last two had better not show up in the data.
   7. Unzip can check dynamic Huffman blocks for complete code sets.
      The exception is that a single code would not be complete (see #4).
   8. The five bits following the block type is really the number of
      literal codes sent minus 257.
   9. Length codes 8,16,16 are interpreted as 13 length codes of 8 bits
      (1+6+6).  Therefore, to output three times the length, you output
      three codes (1+1+1), whereas to output four times the same length,
      you only need two codes (1+3).  Hmm.
  10. In the tree reconstruction algorithm, Code = Code + Increment
      only if BitLength(i) is not zero.  (Pretty obvious.)
  11. Correction: 4 Bits: # of Bit Length codes - 4     (4 - 19)
  12. Note: length code 284 can represent 227-258, but length code 285
      really is 258.  The last length deserves its own, short code
      since it gets used a lot in very redundant files.  The length
      258 is special since 258 - 3 (the min match length) is 255.
  13. The literal/length and distance code bit lengths are read as a
      single stream of lengths.  It is possible (and advantageous) for
      a repeat code (16, 17, or 18) to go across the boundary between
      the two sets of lengths.}


{---------------------------------------------------------------------------}
procedure inflate_blocks_reset(var s: inflate_blocks_state; var z: z_stream; c: puLong);
  {c: check value on output}
begin
  with s do begin
    if c<>Z_NULL then c^ := check;
    if (mode=_BTREE) or (mode=_DTREE) then Z_FREE(z, sub.trees.blens);
    if (mode=_CODES) then inflate_codes_free(sub.decode.codes, z);

    mode := _ZTYPE;
    bitk := 0;
    bitb := 0;

    write := window;
    read := window;
    if Assigned(checkfn) then begin
      check := checkfn(uLong(0), pBytef(nil), 0);
      z.adler := check;
    end;
    {$ifdef DEBUG}
      Tracev('inflate:   blocks reset'#13#10);
    {$endif}
  end;
end;


{---------------------------------------------------------------------------}
function inflate_blocks_new(var z: z_stream;
                                c: check_func;  {check function}
                                w: uInt         {window size}
                                ): pInflate_blocks_state;
var
  s: pInflate_blocks_state;

begin
  s := pInflate_blocks_state(Z_ALLOC(z,1, sizeof(inflate_blocks_state)));

  if s=Z_NULL then begin
    inflate_blocks_new := s;
    exit;
  end;

  with s^ do begin
    hufts := huft_ptr(Z_ALLOC(z, sizeof(inflate_huft), MANY));
    if hufts=Z_NULL then begin
      Z_FREE(z, s);
      inflate_blocks_new := Z_NULL;
      exit;
    end;

    window := pBytef(Z_ALLOC(z, 1, w));
    if window=Z_NULL then begin
      Z_FREE(z, hufts);
      Z_FREE(z, s);
      inflate_blocks_new := Z_NULL;
      exit;
    end;

    zend := window;
    inc(zend, w);
    checkfn := c;
    mode := _ZTYPE;
    {$ifdef DEBUG}
      Tracev('inflate:   blocks allocated'#13#10);
    {$endif}
  end;
  inflate_blocks_reset(s^, z, Z_NULL);
  inflate_blocks_new := s;
end;


{---------------------------------------------------------------------------}
function inflate_blocks(var s: inflate_blocks_state;
                        var z: z_stream;
                            r: int): int;           {initial return code}
label
  start_btree, start_dtree,
  start_blkdone, start_dry,
  start_codes;

var
  t: uInt;               {temporary storage}
  b: uLong;              {bit buffer}
  k: uInt;               {bits in bit buffer}
  p: pBytef;             {input data pointer}
  n: uInt;               {bytes available there}
  q: pBytef;             {output window write pointer}
  m: uInt;               {bytes to end of window or read pointer}

{fixed code blocks}
var
  bl, bd: uInt;
  tl, td: pInflate_huft;
var
  h: pInflate_huft;
  i, j, c: uInt;
var
  cs: pInflate_codes_state;

begin
  {copy input/output information to locals}
  p := z.next_in;
  n := z.avail_in;
  b := s.bitb;
  k := s.bitk;
  q := s.write;

  if ptr2int(q)<ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
  else m := uInt(ptr2int(s.zend)-ptr2int(q));

  {decompress an inflated block}
  {process input based on current state}

  while true do begin

    case s.mode of

  _ZTYPE: begin
            {NEEDBITS(3);}
            while (k < 3) do begin
              {NEEDBYTE;}
              if n<>0 then r :=Z_OK
              else begin
                {UPDATE}
                s.bitb := b;
                s.bitk := k;
                z.avail_in := n;
                inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
                z.next_in := p;
                s.write := q;
                inflate_blocks := inflate_flush(s,z,r);
                exit;
              end;
              dec(n);
              b := b or (uLong(p^) shl k);
              inc(p);
              inc(k, 8);
            end;

            t := uInt(b) and 7;
            s.last := boolean(t and 1);

            case t shr 1 of

              0:  begin {stored}
                    {$ifdef DEBUG}
                      if s.last then Tracev('inflate:     stored block (last)'#13#10)
                                else Tracev('inflate:     stored block'#13#10);
                    {$endif}
                    {DUMPBITS(3);}
                    b := b shr 3;
                    dec(k, 3);
                    t := k and 7;        {go to byte boundary}
                    {DUMPBITS(t);}
                    b := b shr t;
                    dec(k, t);
                    s.mode := _LENS;      {get length of stored block}
                  end;

              1:  begin {fixed}
                    {$ifdef DEBUG}
                      if s.last then Tracev('inflate:     fixed codes blocks (last)'#13#10)
                                else Tracev('inflate:     fixed codes blocks'#13#10);
                    {$endif}
                    inflate_trees_fixed(bl, bd, tl, td, z);
                    s.sub.decode.codes := inflate_codes_new(bl, bd, tl, td, z);
                    if s.sub.decode.codes=Z_NULL then begin
                      r := Z_MEM_ERROR;
                      {update pointers and return}
                      s.bitb := b;
                      s.bitk := k;
                      z.avail_in := n;
                      inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
                      z.next_in := p;
                      s.write := q;
                      inflate_blocks := inflate_flush(s,z,r);
                      exit;
                    end;
                    {DUMPBITS(3);}
                    b := b shr 3;
                    dec(k, 3);
                    s.mode := _CODES;
                  end;

              2:  begin {dynamic}
                    {$ifdef DEBUG}
                      if s.last then Tracev('inflate:     dynamic codes block (last)'#13#10)
                      else Tracev('inflate:     dynamic codes block'#13#10);
                    {$endif}
                    {DUMPBITS(3);}
                    b := b shr 3;
                    dec(k, 3);
                    s.mode := _TABLE;
                  end;
              3:  begin {illegal}
                    {DUMPBITS(3);}
                    b := b shr 3;
                    dec(k, 3);

                    s.mode := _BLKBAD;
                    z.msg := 'invalid block type';
                    r := Z_DATA_ERROR;
                    {update pointers and return}
                    s.bitb := b;
                    s.bitk := k;
                    z.avail_in := n;
                    inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
                    z.next_in := p;
                    s.write := q;
                    inflate_blocks := inflate_flush(s,z,r);
                    exit;
                  end;
            end; {case}
          end;

   _LENS: begin
            {NEEDBITS(32);}
            while k<32 do begin
              {NEEDBYTE;}
              if n<>0 then r :=Z_OK
              else begin
                {UPDATE}
                s.bitb := b;
                s.bitk := k;
                z.avail_in := n;
                inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
                z.next_in := p;
                s.write := q;
                inflate_blocks := inflate_flush(s,z,r);
                exit;
              end;
              dec(n);
              b := b or (uLong(p^) shl k);
              inc(p);
              inc(k, 8);
            end;

            if (((not b) shr 16) and $ffff) <> (b and $ffff) then begin
              s.mode := _BLKBAD;
              z.msg := 'invalid stored block lengths';
              r := Z_DATA_ERROR;
              {update pointers and return}
              s.bitb := b;
              s.bitk := k;
              z.avail_in := n;
              inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
              z.next_in := p;
              s.write := q;
              inflate_blocks := inflate_flush(s,z,r);
              exit;
            end;
            s.sub.left := uInt(b) and $ffff;
            k := 0;
            b := 0;                      {dump bits}
            {$ifdef DEBUG}
              Tracev('inflate:       stored length '+IntToStr(s.sub.left)+#13#10);
            {$endif}
            if s.sub.left <> 0 then s.mode := _STORED
            else if s.last then s.mode := _DRY
            else s.mode := _ZTYPE;
          end;

 _STORED: begin
            if n=0 then begin
              {update pointers and return}
              s.bitb := b;
              s.bitk := k;
              z.avail_in := n;
              inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
              z.next_in := p;
              s.write := q;
              inflate_blocks := inflate_flush(s,z,r);
              exit;
            end;
            {NEEDOUT}
            if m=0 then begin
              {WRAP}
              if (q = s.zend) and (s.read <> s.window) then begin
                q := s.window;
                if ptr2int(q)<ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
                else m := uInt(ptr2int(s.zend)-ptr2int(q));
              end;
              if m=0 then begin
                {FLUSH}
                s.write := q;
                r := inflate_flush(s,z,r);
                q := s.write;
                if ptr2int(q)<ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
                else m := uInt(ptr2int(s.zend)-ptr2int(q));

                {WRAP}
                if (q = s.zend) and (s.read <> s.window) then begin
                  q := s.window;
                  if ptr2int(q) < ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
                  else m := uInt(ptr2int(s.zend)-ptr2int(q));
                end;

                if m=0 then begin
                  {UPDATE}
                  s.bitb := b;
                  s.bitk := k;
                  z.avail_in := n;
                  inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
                  z.next_in := p;
                  s.write := q;
                  inflate_blocks := inflate_flush(s,z,r);
                  exit;
                end;
              end;
            end;
            r := Z_OK;
            t := s.sub.left;
            if t>n then t := n;
            if t>m then t := m;
            zmemcpy(q, p, t);
            inc(p, t);
            dec(n, t);
            inc(q, t);
            dec(m, t);
            dec(s.sub.left, t);
            if s.sub.left=0 then begin
              {$ifdef DEBUG}
                if (ptr2int(q) >= ptr2int(s.read)) then begin
                  Tracev('inflate:       stored end '+
                      IntToStr(z.total_out + ptr2int(q) - ptr2int(s.read)) + ' total out'#13#10)
                end
                else begin
                  Tracev('inflate:       stored end '+
                          IntToStr(z.total_out + ptr2int(s.zend) - ptr2int(s.read) +
                          ptr2int(q) - ptr2int(s.window)) +  ' total out'#13#10);
                end;
              {$endif}
              if s.last then s.mode := _DRY
              else s.mode := _ZTYPE;
            end;
          end;

  _TABLE: begin
            {NEEDBITS(14);}
            while k<14 do begin
              {NEEDBYTE;}
              if n<>0 then r :=Z_OK
              else begin
                {UPDATE}
                s.bitb := b;
                s.bitk := k;
                z.avail_in := n;
                inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
                z.next_in := p;
                s.write := q;
                inflate_blocks := inflate_flush(s,z,r);
                exit;
              end;
              dec(n);
              b := b or (uLong(p^) shl k);
              inc(p);
              inc(k, 8);
            end;

            t := uInt(b) and $3fff;
            s.sub.trees.table := t;
            {$ifndef PKZIP_BUG_WORKAROUND}
              if ((t and $1f) > 29) or (((t shr 5) and $1f) > 29) then begin
                s.mode := _BLKBAD;
                z.msg := 'too many length or distance symbols';
                r := Z_DATA_ERROR;
                {update pointers and return}
                s.bitb := b;
                s.bitk := k;
                z.avail_in := n;
                inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
                z.next_in := p;
                s.write := q;
                inflate_blocks := inflate_flush(s,z,r);
                exit;
              end;
            {$endif}
            t := 258 + (t and $1f) + ((t shr 5) and $1f);
            s.sub.trees.blens := puIntArray(Z_ALLOC(z, t, sizeof(uInt)));
            if s.sub.trees.blens=Z_NULL then begin
              r := Z_MEM_ERROR;
              {update pointers and return}
              s.bitb := b;
              s.bitk := k;
              z.avail_in := n;
              inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
              z.next_in := p;
              s.write := q;
              inflate_blocks := inflate_flush(s,z,r);
              exit;
            end;
            {DUMPBITS(14);}
            b := b shr 14;
            dec(k, 14);

            s.sub.trees.index := 0;
            {$ifdef DEBUG}
              Tracev('inflate:       table sizes ok'#13#10);
            {$endif}
            s.mode := _BTREE;
            {fall trough case is handled by the while}
            {try goto for speed - Nomssi}
            goto start_btree;
          end;

  _BTREE: begin
            start_btree:
            while s.sub.trees.index < 4 + (s.sub.trees.table shr 10) do begin
              {NEEDBITS(3);}
              while k<3 do begin
                {NEEDBYTE;}
                if n<>0 then r :=Z_OK
                else begin
                  {UPDATE}
                  s.bitb := b;
                  s.bitk := k;
                  z.avail_in := n;
                  inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
                  z.next_in := p;
                  s.write := q;
                  inflate_blocks := inflate_flush(s,z,r);
                  exit;
                end;
                dec(n);
                b := b or (uLong(p^) shl k);
                inc(p);
                inc(k, 8);
              end;

              s.sub.trees.blens^[border[s.sub.trees.index]] := uInt(b) and 7;
              inc(s.sub.trees.index);
              {DUMPBITS(3);}
              b := b shr 3;
              dec(k, 3);
            end;
            while s.sub.trees.index<19 do begin
              s.sub.trees.blens^[border[s.sub.trees.index]] := 0;
              inc(s.sub.trees.index);
            end;
            s.sub.trees.bb := 7;
            t := inflate_trees_bits(s.sub.trees.blens^, s.sub.trees.bb, s.sub.trees.tb, s.hufts^, z);
            if t<>Z_OK then begin
              {*we 114, move Z_FREE in Z_DATA_ERROR if block}
              r := t;
              if r=Z_DATA_ERROR then begin
                Z_FREE(z, s.sub.trees.blens);
                s.mode := _BLKBAD;
              end;
              {update pointers and return}
              s.bitb := b;
              s.bitk := k;
              z.avail_in := n;
              inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
              z.next_in := p;
              s.write := q;
              inflate_blocks := inflate_flush(s,z,r);
              exit;
            end;
            s.sub.trees.index := 0;
            {$ifdef DEBUG}
              Tracev('inflate:       bits tree ok'#13#10);
            {$endif}
            s.mode := _DTREE;
            {fall through again}
            goto start_dtree;
          end;

  _DTREE: begin
            start_dtree:
            while true do begin
              t := s.sub.trees.table;
              if not (s.sub.trees.index < 258 + (t and $1f) + ((t shr 5) and $1f)) then break;
              t := s.sub.trees.bb;
              {NEEDBITS(t);}
              while k<t do begin
                {NEEDBYTE;}
                if n<>0 then r :=Z_OK
                else begin
                  {UPDATE}
                  s.bitb := b;
                  s.bitk := k;
                  z.avail_in := n;
                  inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
                  z.next_in := p;
                  s.write := q;
                  inflate_blocks := inflate_flush(s,z,r);
                  exit;
                end;
                dec(n);
                b := b or (uLong(p^) shl k);
                inc(p);
                inc(k, 8);
              end;

              h := s.sub.trees.tb;
              inc(h, uInt(b) and inflate_mask[t]);
              t := h^.Bits;
              c := h^.Base;

              if c<16 then begin
                {DUMPBITS(t);}
                b := b shr t;
                dec(k, t);
                s.sub.trees.blens^[s.sub.trees.index] := c;
                inc(s.sub.trees.index);
              end
              else begin
                {c=16..18}
                if c=18 then begin
                  i := 7;
                  j := 11;
                end
                else begin
                  i := c - 14;
                  j := 3;
                end;
                {NEEDBITS(t + i);}
                while k<t+i do begin
                  {NEEDBYTE;}
                  if n<>0 then r :=Z_OK
                  else begin
                    {UPDATE}
                    s.bitb := b;
                    s.bitk := k;
                    z.avail_in := n;
                    inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
                    z.next_in := p;
                    s.write := q;
                    inflate_blocks := inflate_flush(s,z,r);
                    exit;
                  end;
                  dec(n);
                  b := b or (uLong(p^) shl k);
                  inc(p);
                  inc(k, 8);
                end;

                {DUMPBITS(t);}
                b := b shr t;
                dec(k, t);

                inc(j, uInt(b) and inflate_mask[i]);
                {DUMPBITS(i);}
                b := b shr i;
                dec(k, i);

                i := s.sub.trees.index;
                t := s.sub.trees.table;
                if (i + j > 258 + (t and $1f) + ((t shr 5) and $1f)) or ((c = 16) and (i < 1)) then begin
                  Z_FREE(z, s.sub.trees.blens);
                  s.mode := _BLKBAD;
                  z.msg := 'invalid bit length repeat';
                  r := Z_DATA_ERROR;
                  {update pointers and return}
                  s.bitb := b;
                  s.bitk := k;
                  z.avail_in := n;
                  inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
                  z.next_in := p;
                  s.write := q;
                  inflate_blocks := inflate_flush(s,z,r);
                  exit;
                end;
                if c = 16 then c := s.sub.trees.blens^[i - 1]
                else c := 0;

                repeat
                  s.sub.trees.blens^[i] := c;
                  inc(i);
                  dec(j);
                until j=0;
                s.sub.trees.index := i;
              end;
            end; {while}
            s.sub.trees.tb := Z_NULL;

            bl := 9;         {must be <= 9 for lookahead assumptions}
            bd := 6;         {must be <= 9 for lookahead assumptions}
            t := s.sub.trees.table;
            t := inflate_trees_dynamic(257 + (t and $1f),
                    1 + ((t shr 5) and $1f),
                    s.sub.trees.blens^, bl, bd, tl, td, s.hufts^, z);
            if t<>Z_OK then begin
              if t=uInt(Z_DATA_ERROR) then begin
                {*we 114}
                Z_FREE(z, s.sub.trees.blens);
                s.mode := _BLKBAD;
              end;
              r := t;
              {update pointers and return}
              s.bitb := b;
              s.bitk := k;
              z.avail_in := n;
              inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
              z.next_in := p;
              s.write := q;
              inflate_blocks := inflate_flush(s,z,r);
              exit;
            end;
            {$ifdef DEBUG}
              Tracev('inflate:       trees ok'#13#10);
            {$endif}
            {c renamed to cs}
            cs := inflate_codes_new(bl, bd, tl, td, z);
            if cs=Z_NULL then begin
              r := Z_MEM_ERROR;
              {update pointers and return}
              s.bitb := b;
              s.bitk := k;
              z.avail_in := n;
              inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
              z.next_in := p;
              s.write := q;
              inflate_blocks := inflate_flush(s,z,r);
              exit;
            end;
            {*we 114}
            Z_FREE(z, s.sub.trees.blens);
            {*we Apr.2004: Assignent after Z_FREE}
            s.sub.decode.codes := cs;
            s.mode := _CODES;
            {yet another falltrough}
            goto start_codes;
          end;

  _CODES: begin
            start_codes:
            {update pointers}
            s.bitb := b;
            s.bitk := k;
            z.avail_in := n;
            inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
            z.next_in := p;
            s.write := q;

            r := inflate_codes(s, z, r);
            if r<>Z_STREAM_END then begin
              inflate_blocks := inflate_flush(s, z, r);
              exit;
            end;
            r := Z_OK;
            inflate_codes_free(s.sub.decode.codes, z);
            {load local pointers}
            p := z.next_in;
            n := z.avail_in;
            b := s.bitb;
            k := s.bitk;
            q := s.write;
            if ptr2int(q)<ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
            else m := uInt(ptr2int(s.zend)-ptr2int(q));
            {$ifdef DEBUG}
              if (ptr2int(q) >= ptr2int(s.read)) then begin
                Tracev('inflate:       codes end '+ IntToStr(z.total_out + ptr2int(q) - ptr2int(s.read)) + ' total out'#13#10)
              end
              else begin
                Tracev('inflate:       codes end '+
                        IntToStr(z.total_out + ptr2int(s.zend) - ptr2int(s.read) +
                        ptr2int(q) - ptr2int(s.window)) +  ' total out'#13#10);
              end;
            {$endif}
            if not s.last then begin
              s.mode := _ZTYPE;
              continue; {break for switch statement in C-code}
            end;
            {*we 113: Code delete (patch112)}
            s.mode := _DRY;
            {another falltrough}
            goto start_dry;
          end;

    _DRY: begin
            start_dry:
            {FLUSH}
            s.write := q;
            r := inflate_flush(s,z,r);
            q := s.write;

            {not needed anymore, we are done:
            if ptr2int(q) < ptr2int(s.read) then
              m := uInt(ptr2int(s.read)-ptr2int(q)-1)
            else
              m := uInt(ptr2int(s.zend)-ptr2int(q));}

            if s.read<>s.write then begin
              {update pointers and return}
              s.bitb := b;
              s.bitk := k;
              z.avail_in := n;
              inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
              z.next_in := p;
              s.write := q;
              inflate_blocks := inflate_flush(s,z,r);
              exit;
            end;
            s.mode := _BLKDONE;
            goto start_blkdone;
          end;

_BLKDONE: begin
            start_blkdone:
            r := Z_STREAM_END;
            {update pointers and return}
            s.bitb := b;
            s.bitk := k;
            z.avail_in := n;
            inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
            z.next_in := p;
            s.write := q;
            inflate_blocks := inflate_flush(s,z,r);
            exit;
          end;

 _BLKBAD: begin
            r := Z_DATA_ERROR;
            {update pointers and return}
            s.bitb := b;
            s.bitk := k;
            z.avail_in := n;
            inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
            z.next_in := p;
            s.write := q;
            inflate_blocks := inflate_flush(s,z,r);
            exit;
          end;
    else  begin
            r := Z_STREAM_ERROR;
            {update pointers and return}
            s.bitb := b;
            s.bitk := k;
            z.avail_in := n;
            inc(z.total_in, ptr2int(p) - ptr2int(z.next_in));
            z.next_in := p;
            s.write := q;
            inflate_blocks := inflate_flush(s,z,r);
            exit;
          end;
    end; {case s.mode of}
  end; {while true}
end;


{---------------------------------------------------------------------------}
function inflate_blocks_free(s: pInflate_blocks_state; var z: z_stream): int;
begin
  inflate_blocks_reset(s^, z, Z_NULL);
  Z_FREE(z, s^.window);
  Z_FREE(z, s^.hufts);
  Z_FREE(z, s);
  {$ifdef DEBUG}
    Trace('inflate:   blocks freed'#13#10);
  {$endif}
  inflate_blocks_free := Z_OK;
end;


{---------------------------------------------------------------------------}
procedure inflate_set_dictionary(  var s: inflate_blocks_state;
                                 const d: array of byte; {dictionary}
                                       n: uInt);         {dictionary length}
begin
  zmemcpy(s.window, pBytef(@d), n);
  s.write := s.window;
  inc(s.write, n);
  s.read := s.write;
end;



{---------------------------------------------------------------------------}
function inflate_blocks_sync_point(var s: inflate_blocks_state): int;
  {Returns true if inflate is currently at the end of a block generated
   by Z_SYNC_FLUSH or Z_FULL_FLUSH.
   IN assertion: s <> Z_NULL}
begin
  inflate_blocks_sync_point := int(s.mode=_LENS);
end;

end.
