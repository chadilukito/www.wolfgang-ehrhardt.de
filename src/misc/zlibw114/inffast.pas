unit InfFast;

(************************************************************************
  inffast.h and
  inffast.c -- process literals and length/distance pairs fast
  Copyright (C) 1995-2002 Mark Adler

  Pascal translation
  Copyright (C) 1998 by Jacques Nomssi Nzali
  For conditions of distribution and use, see copyright notice in readme.txt

  ------------------------------------------------------------------------
  Modifications by W.Ehrhardt:

  Feb 2002
    - Source code reformating/reordering
  Mar 2002
    - ZLIB 114 changes
    - Patches by Mark Adler (pers. comm.)
  Mar 2005
    - Code cleanup for WWW upload
  Apr 2005
    - uses zutil if debug
  May 2005
    - Trace: use #13#10 like C original
  Jul 2009
    - D12 fixes
  ------------------------------------------------------------------------

*************************************************************************)


interface


uses
  zlibh, infutil;

function inflate_fast(bl, bd: uInt; tl, td: pInflate_huft; var s: inflate_blocks_state; var z: z_stream): int;


implementation

{$ifdef debug}
uses zutil;
{$endif}

{$I zconf.inc}

{---------------------------------------------------------------------------}
function inflate_fast(bl, bd: uInt; tl, td: pInflate_huft; var s: inflate_blocks_state; var z: z_stream): int;
  {-Called with number of bytes left to write in window at least 258
  (the maximum string length) and number of input bytes available
  at least ten.  The ten bytes are six bytes for the longest length/
  distance pair plus four bytes for overloading the bit buffer.}
var
  t : pInflate_huft;      {temporary pointer}
  e : uInt;               {extra bits or operation}
  b : uLong;              {bit buffer}
  k : uInt;               {bits in bit buffer}
  p : pBytef;             {input data pointer}
  n : uInt;               {bytes available there}
  q : pBytef;             {output window write pointer}
  m : uInt;               {bytes to end of window or read pointer}
  ml: uInt;               {mask for literal/length tree}
  md: uInt;               {mask for distance tree}
  c : uInt;               {bytes to copy}
  d : uInt;               {distance back to copy from}
  r : pBytef;             {copy source pointer}
begin
  {load input, output, bit values (macro LOAD)}
  p := z.next_in;
  n := z.avail_in;
  b := s.bitb;
  k := s.bitk;
  q := s.write;
  if ptr2int(q) < ptr2int(s.read) then m := uInt(ptr2int(s.read)-ptr2int(q)-1)
  else m := uInt(ptr2int(s.zend)-ptr2int(q));

  {initialize masks}
  ml := inflate_mask[bl];
  md := inflate_mask[bd];

  {do until not enough input or output space for fast loop}
  repeat                      {assume called with (m >= 258) and (n >= 10)}
    {get literal/length code}
    {GRABBITS(20);}             {max bits for literal/length code}
    while k<20 do begin
      dec(n);
      b := b or (uLong(p^) shl k);
      inc(p);
      inc(k, 8);
    end;

    t := @(huft_ptr(tl)^[uInt(b) and ml]);

    e := t^.exop;
    if e=0 then begin
      {DUMPBITS(t^.bits);}
      b := b shr t^.bits;
      dec(k, t^.bits);
      {$ifdef DEBUG}
        if (t^.base >= $20) and (t^.base < $7f) then
          Tracevv({$ifdef unicode}str255{$endif}('inflate:         * literal '+char8(t^.base)+#13#10))
        else
          Tracevv('inflate:         * literal '+ IntToStr(t^.base)+#13#10);
      {$endif}
      q^ := byte(t^.base);
      inc(q);
      dec(m);
      continue;
    end;
    repeat
      {DUMPBITS(t^.bits);}
      b := b shr t^.bits;
      dec(k, t^.bits);
      if e and 16 <> 0 then begin
        {get extra bits for length}
        e := e and 15;
        c := t^.base + (uInt(b) and inflate_mask[e]);
        {DUMPBITS(e);}
        b := b shr e;
        dec(k, e);
        {$ifdef DEBUG}
          Tracevv('inflate:         * length ' + IntToStr(c)+#13#10);
        {$endif}
        {decode distance base of block to copy}
        {GRABBITS(15);}           {max bits for distance code}
        while k<15 do begin
          dec(n);
          b := b or (uLong(p^) shl k);
          inc(p);
          inc(k, 8);
        end;

        t := @huft_ptr(td)^[uInt(b) and md];
        e := t^.exop;
        repeat
          {DUMPBITS(t^.bits);}
          b := b shr t^.bits;
          dec(k, t^.bits);

          if e and 16 <> 0 then begin
            {get extra bits to add to distance base}
            e := e and 15;
            {GRABBITS(e);}         {get extra bits (up to 13)}
            while k<e do begin
              dec(n);
              b := b or (uLong(p^) shl k);
              inc(p);
              inc(k, 8);
            end;

            d := t^.base + (uInt(b) and inflate_mask[e]);
            {DUMPBITS(e);}
            b := b shr e;
            dec(k, e);

            {$ifdef DEBUG}
              Tracevv('inflate:         * distance '+IntToStr(d)+#13#10);
            {$endif}

            {do the copy}    {*we 114}
            dec(m,c);
            r := q; dec(r,d);

            {wrap if needed}

            {*we: partial unroll of copy loop is not used thus}
            {     only one copy loop is need outside all "if"s}
            {*we 114MA: Mark Adler Patch}

            if uint(ptr2int(q) - ptr2int(s.window)) < d then begin
              repeat
                inc(r, ptr2int(s.zend)-ptr2int(s.window));   {force pointer in window}
              until (ptr2int(r) >= ptr2int(s.window)) and (ptr2int(r) < ptr2int(s.zend));
              e := ptr2int(s.zend) - ptr2int(r);
              if c>e then begin
                dec(c,e);             {wrapped copy}
                repeat
                  q^ := r^;
                  inc(q);
                  inc(r);
                  dec(e);
                until e=0;
                r := s.window;
              end;
            end;
            repeat
              q^ := r^;
              inc(q);
              inc(r);
              dec(c);
            until (c = 0);
            break;
          end
          else if e and 64 = 0 then begin
            inc(t, t^.base + (uInt(b) and inflate_mask[e]));
            e := t^.exop;
          end
          else begin
            z.msg := 'invalid distance code';
            {UNGRAB}
            c := z.avail_in-n;
            if (k shr 3) < c then c := k shr 3;
            inc(n, c);
            dec(p, c);
            dec(k, c shl 3);
            {UPDATE}
            s.bitb := b;
            s.bitk := k;
            z.avail_in := n;
            inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
            z.next_in := p;
            s.write := q;

            inflate_fast := Z_DATA_ERROR;
            exit;
          end;
        until false;
        break;
      end;
      if e and 64 = 0 then begin
         {t += t->base;
          e = (t += ((uInt)b & inflate_mask[e]))->exop;}
        inc(t, t^.base + (uInt(b) and inflate_mask[e]));
        e := t^.exop;
        if e=0 then begin
          {DUMPBITS(t^.bits);}
          b := b shr t^.bits;
          dec(k, t^.bits);
          {$ifdef DEBUG}
            if (t^.base >= $20) and (t^.base < $7f) then
              Tracevv({$ifdef unicode}str255{$endif}('inflate:         * literal '+char8(t^.base)+#13#10))
            else
              Tracevv('inflate:         * literal '+IntToStr(t^.base)+#13#10);
          {$endif}
          q^ := byte(t^.base);
          inc(q);
          dec(m);
          break;
        end;
      end
      else
        if e and 32 <> 0 then begin
          {$ifdef DEBUG}
            Tracevv('inflate:         * end of block'#13#10);
          {$endif}
          {UNGRAB}
          c := z.avail_in-n;
          if (k shr 3) < c then c := k shr 3;
          inc(n, c);
          dec(p, c);
          dec(k, c shl 3);
          {UPDATE}
          s.bitb := b;
          s.bitk := k;
          z.avail_in := n;
          inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
          z.next_in := p;
          s.write := q;
          inflate_fast := Z_STREAM_END;
          exit;
        end
        else begin
          z.msg := 'invalid literal/length code';
          {UNGRAB}
          c := z.avail_in-n;
          if (k shr 3) < c then c := k shr 3;
          inc(n, c);
          dec(p, c);
          dec(k, c shl 3);
          {UPDATE}
          s.bitb := b;
          s.bitk := k;
          z.avail_in := n;
          inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
          z.next_in := p;
          s.write := q;
          inflate_fast := Z_DATA_ERROR;
          exit;
        end;
    until false;
  until (m < 258) or (n < 10);

  {not enough input or output--restore pointers and return}
  {UNGRAB}
  c := z.avail_in-n;
  if (k shr 3) < c then c := k shr 3;
  inc(n, c);
  dec(p, c);
  dec(k, c shl 3);
  {UPDATE}
  s.bitb := b;
  s.bitk := k;
  z.avail_in := n;
  inc(z.total_in, ptr2int(p)-ptr2int(z.next_in));
  z.next_in := p;
  s.write := q;
  inflate_fast := Z_OK;
end;

end.
