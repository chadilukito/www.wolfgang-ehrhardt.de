{Sosemanuk include file for 16 bit BASM code (TP6/7, D1), W.Ehrhardt Apr.2009}

{sose_keysetup and sose_ivsetup reuse code from my Serpent implementation.}
{MakeStreamBlock is based on sosemanukfast.java from the eSTREAM submission.}


{---------------------------------------------------------------------------}
procedure sose_keysetup_int(var ctx: sose_ctx; key: pointer; klen: word);
  {-Sosemanuk key setup; internal. klen = key length in bytes}
var
  i: integer;
  lkey: array[0..35] of byte;
  K0: array[0..7] of longint absolute lkey;
const
  phi: longint = longint($9E3779B9);
begin

  {Use at most 256 bits}
  if klen>31 then move(key^,lkey,32)
  else begin
    fillchar(lkey, 32,0);
    move(key^,lkey,klen);
    lkey[klen] := 1;
  end;

  asm
    db $66;  mov  dx, word ptr [phi]
             push ds
             lds  di,[ctx]
             lea  di,sose_ctx[di].RndKey
    db $66;  sub  si, si                 {si=i}
    db $66;  mov  ax, word ptr K0[4*7]

    {RotL(K0[0] xor K0[3] xor K0[5] xor t xor phi xor longint(0), 11);}
    db $66;  xor  ax, word ptr K0[0*4]
    db $66;  xor  ax, word ptr K0[3*4]
    db $66;  xor  ax, word ptr K0[5*4]
    db $66;  xor  ax, dx
    db $66;  xor  ax, si
    db $66;  rol  ax, 11
    db $66;  mov  word ptr K0[0*4], ax
    db $66;  mov  [di], ax
             inc  si

    {RotL(K0[1] xor K0[4] xor K0[6] xor t xor phi xor longint(1), 11);}
    db $66;  xor  ax, word ptr K0[1*4]
    db $66;  xor  ax, word ptr K0[4*4]
    db $66;  xor  ax, word ptr K0[6*4]
    db $66;  xor  ax, dx
    db $66;  xor  ax, si
    db $66;  rol  ax, 11
    db $66;  mov  word ptr K0[1*4], ax
    db $66;  mov  [di+4], ax
             inc  si

    {RotL(K0[2] xor K0[5] xor K0[7] xor t xor phi xor longint(2), 11);}
    db $66;  xor  ax, word ptr K0[2*4]
    db $66;  xor  ax, word ptr K0[5*4]
    db $66;  xor  ax, word ptr K0[7*4]
    db $66;  xor  ax, dx
    db $66;  xor  ax, si
    db $66;  rol  ax, 11
    db $66;  mov  word ptr K0[2*4], ax
    db $66;  mov  [di+2*4], ax
             inc  si

    {RotL(K0[3] xor K0[6] xor K0[0] xor t xor phi xor longint(3), 11);}
    db $66;  xor  ax, word ptr K0[3*4]
    db $66;  xor  ax, word ptr K0[6*4]
    db $66;  xor  ax, word ptr K0[0*4]
    db $66;  xor  ax, dx
    db $66;  xor  ax, si
    db $66;  rol  ax, 11
    db $66;  mov  word ptr K0[3*4], ax
    db $66;  mov  [di+3*4], ax
             inc  si

    {RotL(K0[4] xor K0[7] xor K0[1] xor t xor phi xor longint(4), 11);}
    db $66;  xor  ax, word ptr K0[4*4]
    db $66;  xor  ax, word ptr K0[7*4]
    db $66;  xor  ax, word ptr K0[1*4]
    db $66;  xor  ax, dx
    db $66;  xor  ax, si
    db $66;  rol  ax, 11
    db $66;  mov  word ptr K0[4*4], ax
    db $66;  mov  [di+4*4], ax
             inc  si

    {RotL(K0[5] xor K0[0] xor K0[2] xor t xor phi xor longint(5), 11);}
    db $66;  xor  ax, word ptr K0[5*4]
    db $66;  xor  ax, word ptr K0[0*4]
    db $66;  xor  ax, word ptr K0[2*4]
    db $66;  xor  ax, dx
    db $66;  xor  ax, si
    db $66;  rol  ax, 11
    db $66;  mov  word ptr K0[5*4], ax
    db $66;  mov  [di+5*4], ax
             inc  si

    {RotL(K0[6] xor K0[1] xor K0[3] xor t xor phi xor longint(6), 11);}
    db $66;  xor  ax, word ptr K0[6*4]
    db $66;  xor  ax, word ptr K0[1*4]
    db $66;  xor  ax, word ptr K0[3*4]
    db $66;  xor  ax, dx
    db $66;  xor  ax, si
    db $66;  rol  ax, 11
    db $66;  mov  word ptr K0[6*4], ax
    db $66;  mov  [di+6*4], ax
             inc  si

    {RotL(K0[7] xor K0[2] xor K0[4] xor t xor phi xor longint(7), 11);}
    db $66;  xor  ax, word ptr K0[7*4]
    db $66;  xor  ax, word ptr K0[2*4]
    db $66;  xor  ax, word ptr K0[4*4]
    db $66;  xor  ax, dx
    db $66;  xor  ax, si
    db $66;  rol  ax, 11
    db $66;  mov  word ptr K0[7*4], ax
    db $66;  mov  [di+7*4], ax
             inc  si

    {for i:=8 to 99 do begin
      t := RotL(RndKey[i-8] xor RndKey[i-5] xor RndKey[i-3] xor t xor phi xor longint(i), 11);
      RndKey[i] := t;
    end;}
             add  di,32
    @@1:
    db $66;  xor  ax, word ptr [di-32]
    db $66;  xor  ax, word ptr [di-20]
    db $66;  xor  ax, word ptr [di-12]
    db $66;  xor  ax, dx
    db $66;  xor  ax, si
    db $66;  rol  ax, 11
    db $66;  mov  [di], ax
             add  di,4
             inc  si
             cmp  si,100
             jnz  @@1

             mov  ax,3
             mov  [i],ax
             {let di point to Rndkey[0]}
             sub  di,4*100
   @@2:
    {RND3(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);}
    db $66;  mov  ax, word ptr [di]
    db $66;  mov  bx, word ptr [di+4]
    db $66;  mov  cx, word ptr [di+8]
    db $66;  mov  dx, word ptr [di+12]
    db $66;  mov  si,ax                {x4 := x0;       }
    db $66;  or   ax,dx                {x0 := x0 or  x3;}
    db $66;  xor  dx,bx                {x3 := x3 xor x1;}
    db $66;  and  bx,si                {x1 := x1 and x4;}
    db $66;  xor  si,cx                {x4 := x4 xor x2;}
    db $66;  xor  cx,dx                {x2 := x2 xor x3;}
    db $66;  and  dx,ax                {x3 := x3 and x0;}
    db $66;  or   si,bx                {x4 := x4 or  x1;}
    db $66;  xor  dx,si                {x3 := x3 xor x4;}
    db $66;  xor  ax,bx                {x0 := x0 xor x1;}
    db $66;  and  si,ax                {x4 := x4 and x0;}
    db $66;  xor  bx,dx                {x1 := x1 xor x3;}
    db $66;  xor  si,cx                {x4 := x4 xor x2;}
    db $66;  or   bx,ax                {x1 := x1 or  x0;}
    db $66;  xor  bx,cx                {x1 := x1 xor x2;}
    db $66;  xor  ax,dx                {x0 := x0 xor x3;}
    db $66;  mov  cx,bx                {x2 := x1;       }
    db $66;  or   bx,dx                {x1 := x1 or  x3;}
    db $66;  xor  bx,ax                {x1 := x1 xor x0;}
    db $66;  mov  word ptr [di],bx
    db $66;  mov  word ptr [di+4],cx
    db $66;  mov  word ptr [di+8],dx
    db $66;  mov  word ptr [di+12],si
             add  di,16
    {RND2(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);}
    db $66;  mov  ax, word ptr [di]
    db $66;  mov  bx, word ptr [di+4]
    db $66;  mov  cx, word ptr [di+8]
    db $66;  mov  dx, word ptr [di+12]
    db $66;  mov  si,ax                {x4 := x0;         }
    db $66;  and  ax,cx                {x0 := x0 and x2;  }
    db $66;  xor  ax,dx                {x0 := x0 xor x3;  }
    db $66;  xor  cx,bx                {x2 := x2 xor x1;  }
    db $66;  xor  cx,ax                {x2 := x2 xor x0;  }
    db $66;  or   dx,si                {x3 := x3 or  x4;  }
    db $66;  xor  dx,bx                {x3 := x3 xor x1;  }
    db $66;  xor  si,cx                {x4 := x4 xor x2;  }
    db $66;  mov  bx,dx                {x1 := x3;         }
    db $66;  or   dx,si                {x3 := x3 or  x4;  }
    db $66;  xor  dx,ax                {x3 := x3 xor x0;  }
    db $66;  and  ax,bx                {x0 := x0 and x1;  }
    db $66;  xor  si,ax                {x4 := x4 xor x0;  }
    db $66;  xor  bx,dx                {x1 := x1 xor x3;  }
    db $66;  xor  bx,si                {x1 := x1 xor x4;  }
    db $66;  not  si                   {x4 := not x4;     }
    db $66;  mov  word ptr [di],cx
    db $66;  mov  word ptr [di+4],dx
    db $66;  mov  word ptr [di+8],bx
    db $66;  mov  word ptr [di+12],si
             add  di,16
    {RND1(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);}
    db $66;  mov  ax, word ptr [di]
    db $66;  mov  bx, word ptr [di+4]
    db $66;  mov  cx, word ptr [di+8]
    db $66;  mov  dx, word ptr [di+12]
    db $66;  not  ax                   {x0 := not x0;    }
    db $66;  not  cx                   {x2 := not x2;    }
    db $66;  mov  si,ax                {x4 := x0;        }
    db $66;  and  ax,bx                {x0 := x0 and x1; }
    db $66;  xor  cx,ax                {x2 := x2 xor x0; }
    db $66;  or   ax,dx                {x0 := x0 or  x3; }
    db $66;  xor  dx,cx                {x3 := x3 xor x2; }
    db $66;  xor  bx,ax                {x1 := x1 xor x0; }
    db $66;  xor  ax,si                {x0 := x0 xor x4; }
    db $66;  or   si,bx                {x4 := x4 or  x1; }
    db $66;  xor  bx,dx                {x1 := x1 xor x3; }
    db $66;  or   cx,ax                {x2 := x2 or  x0; }
    db $66;  and  cx,si                {x2 := x2 and x4; }
    db $66;  xor  ax,bx                {x0 := x0 xor x1; }
    db $66;  and  bx,cx                {x1 := x1 and x2; }
    db $66;  xor  bx,ax                {x1 := x1 xor x0; }
    db $66;  and  ax,cx                {x0 := x0 and x2; }
    db $66;  xor  ax,si                {x0 := x0 xor x4; }
    db $66;  mov  word ptr es:[di],cx
    db $66;  mov  word ptr es:[di+4],ax
    db $66;  mov  word ptr es:[di+8],dx
    db $66;  mov  word ptr es:[di+12],bx
             add  di,16
    {RND0(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);}
    db $66;  mov  ax, word ptr [di]
    db $66;  mov  bx, word ptr [di+4]
    db $66;  mov  cx, word ptr [di+8]
    db $66;  mov  dx, word ptr [di+12]
    db $66;  xor  dx,ax                {x3 := x3 xor x0; }
    db $66;  mov  si,bx                {x4 :=        x1; }
    db $66;  and  bx,dx                {x1 := x1 and x3; }
    db $66;  xor  si,cx                {x4 := x4 xor x2; }
    db $66;  xor  bx,ax                {x1 := x1 xor x0; }
    db $66;  or   ax,dx                {x0 := x0 or  x3; }
    db $66;  xor  ax,si                {x0 := x0 xor x4; }
    db $66;  xor  si,dx                {x4 := x4 xor x3; }
    db $66;  xor  dx,cx                {x3 := x3 xor x2; }
    db $66;  or   cx,bx                {x2 := x2 or  x1; }
    db $66;  xor  cx,si                {x2 := x2 xor x4; }
    db $66;  not  si                   {x4 :=    not x4; }
    db $66;  or   si,bx                {x4 := x4 or  x1; }
    db $66;  xor  bx,dx                {x1 := x1 xor x3; }
    db $66;  xor  bx,si                {x1 := x1 xor x4; }
    db $66;  or   dx,ax                {x3 := x3 or  x0; }
    db $66;  xor  bx,dx                {x1 := x1 xor x3; }
    db $66;  xor  si,dx                {x4 := x4 xor x3; }
    db $66;  mov  word ptr [di],bx
    db $66;  mov  word ptr [di+4],si
    db $66;  mov  word ptr [di+8],cx
    db $66;  mov  word ptr [di+12],ax
             add  di,16
    {RND7(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);}
    db $66;  mov  ax, word ptr [di]
    db $66;  mov  bx, word ptr [di+4]
    db $66;  mov  cx, word ptr [di+8]
    db $66;  mov  dx, word ptr [di+12]
    db $66;  mov  si,bx                {x4 :=        x1;}
    db $66;  or   bx,cx                {x1 := x1 or  x2;}
    db $66;  xor  bx,dx                {x1 := x1 xor x3;}
    db $66;  xor  si,cx                {x4 := x4 xor x2;}
    db $66;  xor  cx,bx                {x2 := x2 xor x1;}
    db $66;  or   dx,si                {x3 := x3 or  x4;}
    db $66;  and  dx,ax                {x3 := x3 and x0;}
    db $66;  xor  si,cx                {x4 := x4 xor x2;}
    db $66;  xor  dx,bx                {x3 := x3 xor x1;}
    db $66;  or   bx,si                {x1 := x1 or  x4;}
    db $66;  xor  bx,ax                {x1 := x1 xor x0;}
    db $66;  or   ax,si                {x0 := x0 or  x4;}
    db $66;  xor  ax,cx                {x0 := x0 xor x2;}
    db $66;  xor  bx,si                {x1 := x1 xor x4;}
    db $66;  xor  cx,bx                {x2 := x2 xor x1;}
    db $66;  and  bx,ax                {x1 := x1 and x0;}
    db $66;  xor  bx,si                {x1 := x1 xor x4;}
    db $66;  not  cx                   {x2 :=    not x2;}
    db $66;  or   cx,ax                {x2 := x2 or  x0;}
    db $66;  xor  si,cx                {x4 := x4 xor x2;}
    db $66;  mov  word ptr [di],si
    db $66;  mov  word ptr [di+4],dx
    db $66;  mov  word ptr [di+8],bx
    db $66;  mov  word ptr [di+12],ax
             add  di,16
    {RND6(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);}
    db $66;  mov  ax, word ptr [di]
    db $66;  mov  bx, word ptr [di+4]
    db $66;  mov  cx, word ptr [di+8]
    db $66;  mov  dx, word ptr [di+12]
    db $66;  not  cx                   {x2 :=    not x2;}
    db $66;  mov  si,dx                {x4 :=        x3;}
    db $66;  and  dx,ax                {x3 := x3 and x0;}
    db $66;  xor  ax,si                {x0 := x0 xor x4;}
    db $66;  xor  dx,cx                {x3 := x3 xor x2;}
    db $66;  or   cx,si                {x2 := x2 or  x4;}
    db $66;  xor  bx,dx                {x1 := x1 xor x3;}
    db $66;  xor  cx,ax                {x2 := x2 xor x0;}
    db $66;  or   ax,bx                {x0 := x0 or  x1;}
    db $66;  xor  cx,bx                {x2 := x2 xor x1;}
    db $66;  xor  si,ax                {x4 := x4 xor x0;}
    db $66;  or   ax,dx                {x0 := x0 or  x3;}
    db $66;  xor  ax,cx                {x0 := x0 xor x2;}
    db $66;  xor  si,dx                {x4 := x4 xor x3;}
    db $66;  xor  si,ax                {x4 := x4 xor x0;}
    db $66;  not  dx                   {x3 :=    not x3;}
    db $66;  and  cx,si                {x2 := x2 and x4;}
    db $66;  xor  cx,dx                {x2 := x2 xor x3;}
    db $66;  mov  word ptr [di],ax
    db $66;  mov  word ptr [di+4],bx
    db $66;  mov  word ptr [di+8],si
    db $66;  mov  word ptr [di+12],cx
             add  di,16
    {RND5(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);}
    db $66;  mov  ax, word ptr [di]
    db $66;  mov  bx, word ptr [di+4]
    db $66;  mov  cx, word ptr [di+8]
    db $66;  mov  dx, word ptr [di+12]
    db $66;  xor  ax,bx                {x0 := x0 xor x1;}
    db $66;  xor  bx,dx                {x1 := x1 xor x3;}
    db $66;  not  dx                   {x3 :=    not x3;}
    db $66;  mov  si,bx                {x4 :=        x1;}
    db $66;  and  bx,ax                {x1 := x1 and x0;}
    db $66;  xor  cx,dx                {x2 := x2 xor x3;}
    db $66;  xor  bx,cx                {x1 := x1 xor x2;}
    db $66;  or   cx,si                {x2 := x2 or  x4;}
    db $66;  xor  si,dx                {x4 := x4 xor x3;}
    db $66;  and  dx,bx                {x3 := x3 and x1;}
    db $66;  xor  dx,ax                {x3 := x3 xor x0;}
    db $66;  xor  si,bx                {x4 := x4 xor x1;}
    db $66;  xor  si,cx                {x4 := x4 xor x2;}
    db $66;  xor  cx,ax                {x2 := x2 xor x0;}
    db $66;  and  ax,dx                {x0 := x0 and x3;}
    db $66;  not  cx                   {x2 :=    not x2;}
    db $66;  xor  ax,si                {x0 := x0 xor x4;}
    db $66;  or   si,dx                {x4 := x4 or  x3;}
    db $66;  xor  cx,si                {x2 := x2 xor x4;}
    db $66;  mov  word ptr [di],bx
    db $66;  mov  word ptr [di+4],dx
    db $66;  mov  word ptr [di+8],ax
    db $66;  mov  word ptr [di+12],cx
             add  di,16
    {RND4(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);}
    db $66;  mov  ax, word ptr [di]
    db $66;  mov  bx, word ptr [di+4]
    db $66;  mov  cx, word ptr [di+8]
    db $66;  mov  dx, word ptr [di+12]
    db $66;  xor  bx,dx                {x1 := x1 xor x3;}
    db $66;  not  dx                   {x3 :=    not x3;}
    db $66;  xor  cx,dx                {x2 := x2 xor x3;}
    db $66;  xor  dx,ax                {x3 := x3 xor x0;}
    db $66;  mov  si,bx                {x4 :=        x1;}
    db $66;  and  bx,dx                {x1 := x1 and x3;}
    db $66;  xor  bx,cx                {x1 := x1 xor x2;}
    db $66;  xor  si,dx                {x4 := x4 xor x3;}
    db $66;  xor  ax,si                {x0 := x0 xor x4;}
    db $66;  and  cx,si                {x2 := x2 and x4;}
    db $66;  xor  cx,ax                {x2 := x2 xor x0;}
    db $66;  and  ax,bx                {x0 := x0 and x1;}
    db $66;  xor  dx,ax                {x3 := x3 xor x0;}
    db $66;  or   si,bx                {x4 := x4 or  x1;}
    db $66;  xor  si,ax                {x4 := x4 xor x0;}
    db $66;  or   ax,dx                {x0 := x0 or  x3;}
    db $66;  xor  ax,cx                {x0 := x0 xor x2;}
    db $66;  and  cx,dx                {x2 := x2 and x3;}
    db $66;  not  ax                   {x0 :=    not x0;}
    db $66;  xor  si,cx                {x4 := x4 xor x2;}
    db $66;  mov  word ptr [di],bx
    db $66;  mov  word ptr [di+4],si
    db $66;  mov  word ptr [di+8],ax
    db $66;  mov  word ptr [di+12],dx
             add  di,16

             dec  [i]
             jnz  @@2

    {RND3(RndKey[i], RndKey[i+1], RndKey[i+2], RndKey[i+3]); inc(i,4);}
    db $66;  mov  ax, word ptr [di]
    db $66;  mov  bx, word ptr [di+4]
    db $66;  mov  cx, word ptr [di+8]
    db $66;  mov  dx, word ptr [di+12]
    db $66;  mov  si,ax                {x4 := x0;       }
    db $66;  or   ax,dx                {x0 := x0 or  x3;}
    db $66;  xor  dx,bx                {x3 := x3 xor x1;}
    db $66;  and  bx,si                {x1 := x1 and x4;}
    db $66;  xor  si,cx                {x4 := x4 xor x2;}
    db $66;  xor  cx,dx                {x2 := x2 xor x3;}
    db $66;  and  dx,ax                {x3 := x3 and x0;}
    db $66;  or   si,bx                {x4 := x4 or  x1;}
    db $66;  xor  dx,si                {x3 := x3 xor x4;}
    db $66;  xor  ax,bx                {x0 := x0 xor x1;}
    db $66;  and  si,ax                {x4 := x4 and x0;}
    db $66;  xor  bx,dx                {x1 := x1 xor x3;}
    db $66;  xor  si,cx                {x4 := x4 xor x2;}
    db $66;  or   bx,ax                {x1 := x1 or  x0;}
    db $66;  xor  bx,cx                {x1 := x1 xor x2;}
    db $66;  xor  ax,dx                {x0 := x0 xor x3;}
    db $66;  mov  cx,bx                {x2 := x1;       }
    db $66;  or   bx,dx                {x1 := x1 or  x3;}
    db $66;  xor  bx,ax                {x1 := x1 xor x0;}
    db $66;  mov  word ptr [di],bx
    db $66;  mov  word ptr [di+4],cx
    db $66;  mov  word ptr [di+8],dx
    db $66;  mov  word ptr [di+12],si

             pop  ds
  end;
end;



{---------------------------------------------------------------------------}
function sose_keysetup(var ctx: sose_ctx; key: pointer; keybits: word): integer;
  {-Sosemanuk key setup}
begin
  {$ifdef CHECK_KEY_BITS}
    if KeyBits<128 then begin
      sose_keysetup := -1;
      exit;
    end;
  {$endif}
  sose_keysetup := 0;
  {dword align K0 in sose_keysetup_int}
  if sptr and 3 = 2 then asm push ax end;
  sose_keysetup_int(ctx,key,KeyBits div 8);
end;



{---------------------------------------------------------------------------}
procedure sose_ivsetup(var ctx: sose_ctx; IV: pointer);
  {-IV setup, 128 bits of IV^ are used. It is the user's responsibility to }
  { supply least 128 accessible IV bits. After having called sose_keysetup,}
  { the user is allowed to call sose_ivsetup different times in order to   }
  { encrypt/decrypt different messages with the same key but different IV's}
begin
  with ctx do begin
    asm
               push ds
               lds  si,[IV]
      db $66;  mov  ax, word ptr [si]
      db $66;  mov  bx, word ptr [si+4]
      db $66;  mov  cx, word ptr [si+8]
      db $66;  mov  dx, word ptr [si+12]

               lds  di,[ctx]
      db $66;  xor  ax, word ptr [di].RndKey[0*4]
      db $66;  xor  bx, word ptr [di].RndKey[1*4]
      db $66;  xor  cx, word ptr [di].RndKey[2*4]
      db $66;  xor  dx, word ptr [di].RndKey[3*4]

      db $66;  xor  dx,ax                {x3 := x3 xor x0; }
      db $66;  mov  si,bx                {x4 :=        x1; }
      db $66;  and  bx,dx                {x1 := x1 and x3; }
      db $66;  xor  si,cx                {x4 := x4 xor x2; }
      db $66;  xor  bx,ax                {x1 := x1 xor x0; }
      db $66;  or   ax,dx                {x0 := x0 or  x3; }
      db $66;  xor  ax,si                {x0 := x0 xor x4; }
      db $66;  xor  si,dx                {x4 := x4 xor x3; }
      db $66;  xor  dx,cx                {x3 := x3 xor x2; }
      db $66;  or   cx,bx                {x2 := x2 or  x1; }
      db $66;  xor  cx,si                {x2 := x2 xor x4; }
      db $66;  not  si                   {x4 :=    not x4; }
      db $66;  or   si,bx                {x4 := x4 or  x1; }
      db $66;  xor  bx,dx                {x1 := x1 xor x3; }
      db $66;  xor  bx,si                {x1 := x1 xor x4; }
      db $66;  or   dx,ax                {x3 := x3 or  x0; }
      db $66;  xor  bx,dx                {x1 := x1 xor x3; }
      db $66;  xor  si,dx                {x4 := x4 xor x3; }
      {here x0=ebx, x1=esi, x2=ecx, x3=eax}
      db $66;  mov  dx,ax
      db $66;  mov  ax,bx
      db $66;  mov  bx,si

      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[4*4]
      db $66;  xor  bx, word ptr [di].RndKey[5*4]
      db $66;  xor  cx, word ptr [di].RndKey[6*4]
      db $66;  xor  dx, word ptr [di].RndKey[7*4]

      {RND1(x0,x1,x2,x3);}
      db $66;  not  ax                   {x0 := not x0;    }
      db $66;  not  cx                   {x2 := not x2;    }
      db $66;  mov  si,ax                {x4 := x0;        }
      db $66;  and  ax,bx                {x0 := x0 and x1; }
      db $66;  xor  cx,ax                {x2 := x2 xor x0; }
      db $66;  or   ax,dx                {x0 := x0 or  x3; }
      db $66;  xor  dx,cx                {x3 := x3 xor x2; }
      db $66;  xor  bx,ax                {x1 := x1 xor x0; }
      db $66;  xor  ax,si                {x0 := x0 xor x4; }
      db $66;  or   si,bx                {x4 := x4 or  x1; }
      db $66;  xor  bx,dx                {x1 := x1 xor x3; }
      db $66;  or   cx,ax                {x2 := x2 or  x0; }
      db $66;  and  cx,si                {x2 := x2 and x4; }
      db $66;  xor  ax,bx                {x0 := x0 xor x1; }
      db $66;  and  bx,cx                {x1 := x1 and x2; }
      db $66;  xor  bx,ax                {x1 := x1 xor x0; }
      db $66;  and  ax,cx                {x0 := x0 and x2; }
      db $66;  xor  ax,si                {x0 := x0 xor x4; }
      {here x0=ecx, x1=eax, x2=edx, x3=ebx}
      db $66;  mov  si,ax
      db $66;  mov  ax,cx
      db $66;  mov  cx,dx
      db $66;  mov  dx,bx
      db $66;  mov  bx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[8*4]
      db $66;  xor  bx, word ptr [di].RndKey[9*4]
      db $66;  xor  cx, word ptr [di].RndKey[10*4]
      db $66;  xor  dx, word ptr [di].RndKey[11*4]

      {RND2(x0,x1,x2,x3);}
      db $66;  mov  si,ax                {x4 := x0;         }
      db $66;  and  ax,cx                {x0 := x0 and x2;  }
      db $66;  xor  ax,dx                {x0 := x0 xor x3;  }
      db $66;  xor  cx,bx                {x2 := x2 xor x1;  }
      db $66;  xor  cx,ax                {x2 := x2 xor x0;  }
      db $66;  or   dx,si                {x3 := x3 or  x4;  }
      db $66;  xor  dx,bx                {x3 := x3 xor x1;  }
      db $66;  xor  si,cx                {x4 := x4 xor x2;  }
      db $66;  mov  bx,dx                {x1 := x3;         }
      db $66;  or   dx,si                {x3 := x3 or  x4;  }
      db $66;  xor  dx,ax                {x3 := x3 xor x0;  }
      db $66;  and  ax,bx                {x0 := x0 and x1;  }
      db $66;  xor  si,ax                {x4 := x4 xor x0;  }
      db $66;  xor  bx,dx                {x1 := x1 xor x3;  }
      db $66;  xor  bx,si                {x1 := x1 xor x4;  }
      db $66;  not  si                   {x4 := not x4;     }
      {here x0=ecx, x1=edx, x2=ebx, x3=esi}
      db $66;  mov  ax,cx
      db $66;  mov  cx,bx
      db $66;  mov  bx,dx
      db $66;  mov  dx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[12*4]
      db $66;  xor  bx, word ptr [di].RndKey[13*4]
      db $66;  xor  cx, word ptr [di].RndKey[14*4]
      db $66;  xor  dx, word ptr [di].RndKey[15*4]

      {RND3(x0,x1,x2,x3);}
      db $66;  mov  si,ax                {x4 := x0;       }
      db $66;  or   ax,dx                {x0 := x0 or  x3;}
      db $66;  xor  dx,bx                {x3 := x3 xor x1;}
      db $66;  and  bx,si                {x1 := x1 and x4;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  xor  cx,dx                {x2 := x2 xor x3;}
      db $66;  and  dx,ax                {x3 := x3 and x0;}
      db $66;  or   si,bx                {x4 := x4 or  x1;}
      db $66;  xor  dx,si                {x3 := x3 xor x4;}
      db $66;  xor  ax,bx                {x0 := x0 xor x1;}
      db $66;  and  si,ax                {x4 := x4 and x0;}
      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  or   bx,ax                {x1 := x1 or  x0;}
      db $66;  xor  bx,cx                {x1 := x1 xor x2;}
      db $66;  xor  ax,dx                {x0 := x0 xor x3;}
      db $66;  mov  cx,bx                {x2 := x1;       }
      db $66;  or   bx,dx                {x1 := x1 or  x3;}
      db $66;  xor  bx,ax                {x1 := x1 xor x0;}
      {here x0=ebx, x1=ecx, x2=edx, x3=esi}
      db $66;  mov  ax,bx
      db $66;  mov  bx,cx
      db $66;  mov  cx,dx
      db $66;  mov  dx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[16*4]
      db $66;  xor  bx, word ptr [di].RndKey[17*4]
      db $66;  xor  cx, word ptr [di].RndKey[18*4]
      db $66;  xor  dx, word ptr [di].RndKey[19*4]

      {RND4(x0,x1,x2,x3);}
      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  not  dx                   {x3 :=    not x3;}
      db $66;  xor  cx,dx                {x2 := x2 xor x3;}
      db $66;  xor  dx,ax                {x3 := x3 xor x0;}
      db $66;  mov  si,bx                {x4 :=        x1;}
      db $66;  and  bx,dx                {x1 := x1 and x3;}
      db $66;  xor  bx,cx                {x1 := x1 xor x2;}
      db $66;  xor  si,dx                {x4 := x4 xor x3;}
      db $66;  xor  ax,si                {x0 := x0 xor x4;}
      db $66;  and  cx,si                {x2 := x2 and x4;}
      db $66;  xor  cx,ax                {x2 := x2 xor x0;}
      db $66;  and  ax,bx                {x0 := x0 and x1;}
      db $66;  xor  dx,ax                {x3 := x3 xor x0;}
      db $66;  or   si,bx                {x4 := x4 or  x1;}
      db $66;  xor  si,ax                {x4 := x4 xor x0;}
      db $66;  or   ax,dx                {x0 := x0 or  x3;}
      db $66;  xor  ax,cx                {x0 := x0 xor x2;}
      db $66;  and  cx,dx                {x2 := x2 and x3;}
      db $66;  not  ax                   {x0 :=    not x0;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      {here x0=ebx, x1=esi, x2=eax, x3=edx}
      db $66;  mov  cx,ax
      db $66;  mov  ax,bx
      db $66;  mov  bx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[20*4]
      db $66;  xor  bx, word ptr [di].RndKey[21*4]
      db $66;  xor  cx, word ptr [di].RndKey[22*4]
      db $66;  xor  dx, word ptr [di].RndKey[23*4]

      {RND5(x0,x1,x2,x3);}
      db $66;  xor  ax,bx                {x0 := x0 xor x1;}
      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  not  dx                   {x3 :=    not x3;}
      db $66;  mov  si,bx                {x4 :=        x1;}
      db $66;  and  bx,ax                {x1 := x1 and x0;}
      db $66;  xor  cx,dx                {x2 := x2 xor x3;}
      db $66;  xor  bx,cx                {x1 := x1 xor x2;}
      db $66;  or   cx,si                {x2 := x2 or  x4;}
      db $66;  xor  si,dx                {x4 := x4 xor x3;}
      db $66;  and  dx,bx                {x3 := x3 and x1;}
      db $66;  xor  dx,ax                {x3 := x3 xor x0;}
      db $66;  xor  si,bx                {x4 := x4 xor x1;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  xor  cx,ax                {x2 := x2 xor x0;}
      db $66;  and  ax,dx                {x0 := x0 and x3;}
      db $66;  not  cx                   {x2 :=    not x2;}
      db $66;  xor  ax,si                {x0 := x0 xor x4;}
      db $66;  or   si,dx                {x4 := x4 or  x3;}
      db $66;  xor  cx,si                {x2 := x2 xor x4;}
      {here x0=ebx, x1=edx, x2=eax, x3=ecx}
      db $66;  mov  si,ax
      db $66;  mov  ax,bx
      db $66;  mov  bx,dx
      db $66;  mov  dx,cx
      db $66;  mov  cx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[24*4]
      db $66;  xor  bx, word ptr [di].RndKey[25*4]
      db $66;  xor  cx, word ptr [di].RndKey[26*4]
      db $66;  xor  dx, word ptr [di].RndKey[27*4]

      {RND6(x0,x1,x2,x3);}
      db $66;  not  cx                   {x2 :=    not x2;}
      db $66;  mov  si,dx                {x4 :=        x3;}
      db $66;  and  dx,ax                {x3 := x3 and x0;}
      db $66;  xor  ax,si                {x0 := x0 xor x4;}
      db $66;  xor  dx,cx                {x3 := x3 xor x2;}
      db $66;  or   cx,si                {x2 := x2 or  x4;}
      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  xor  cx,ax                {x2 := x2 xor x0;}
      db $66;  or   ax,bx                {x0 := x0 or  x1;}
      db $66;  xor  cx,bx                {x2 := x2 xor x1;}
      db $66;  xor  si,ax                {x4 := x4 xor x0;}
      db $66;  or   ax,dx                {x0 := x0 or  x3;}
      db $66;  xor  ax,cx                {x0 := x0 xor x2;}
      db $66;  xor  si,dx                {x4 := x4 xor x3;}
      db $66;  xor  si,ax                {x4 := x4 xor x0;}
      db $66;  not  dx                   {x3 :=    not x3;}
      db $66;  and  cx,si                {x2 := x2 and x4;}
      db $66;  xor  cx,dx                {x2 := x2 xor x3;}
      {here x0=eax, x1=ebx, x2=esi, x3=ecx}
      db $66;  mov  dx,cx
      db $66;  mov  cx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[28*4]
      db $66;  xor  bx, word ptr [di].RndKey[29*4]
      db $66;  xor  cx, word ptr [di].RndKey[30*4]
      db $66;  xor  dx, word ptr [di].RndKey[31*4]

      {RND7(x0,x1,x2,x3);}
      db $66;  mov  si,bx                {x4 :=        x1;}
      db $66;  or   bx,cx                {x1 := x1 or  x2;}
      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  xor  cx,bx                {x2 := x2 xor x1;}
      db $66;  or   dx,si                {x3 := x3 or  x4;}
      db $66;  and  dx,ax                {x3 := x3 and x0;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  xor  dx,bx                {x3 := x3 xor x1;}
      db $66;  or   bx,si                {x1 := x1 or  x4;}
      db $66;  xor  bx,ax                {x1 := x1 xor x0;}
      db $66;  or   ax,si                {x0 := x0 or  x4;}
      db $66;  xor  ax,cx                {x0 := x0 xor x2;}
      db $66;  xor  bx,si                {x1 := x1 xor x4;}
      db $66;  xor  cx,bx                {x2 := x2 xor x1;}
      db $66;  and  bx,ax                {x1 := x1 and x0;}
      db $66;  xor  bx,si                {x1 := x1 xor x4;}
      db $66;  not  cx                   {x2 :=    not x2;}
      db $66;  or   cx,ax                {x2 := x2 or  x0;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      {here x0=esi, x1=edx, x2=ebx, x3=eax}
      db $66;  mov  cx,bx
      db $66;  mov  bx,dx
      db $66;  mov  dx,ax
      db $66;  mov  ax,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[32*4]
      db $66;  xor  bx, word ptr [di].RndKey[33*4]
      db $66;  xor  cx, word ptr [di].RndKey[34*4]
      db $66;  xor  dx, word ptr [di].RndKey[35*4]

      {RND0(x0,x1,x2,x3);}
      db $66;  xor  dx,ax                {x3 := x3 xor x0; }
      db $66;  mov  si,bx                {x4 :=        x1; }
      db $66;  and  bx,dx                {x1 := x1 and x3; }
      db $66;  xor  si,cx                {x4 := x4 xor x2; }
      db $66;  xor  bx,ax                {x1 := x1 xor x0; }
      db $66;  or   ax,dx                {x0 := x0 or  x3; }
      db $66;  xor  ax,si                {x0 := x0 xor x4; }
      db $66;  xor  si,dx                {x4 := x4 xor x3; }
      db $66;  xor  dx,cx                {x3 := x3 xor x2; }
      db $66;  or   cx,bx                {x2 := x2 or  x1; }
      db $66;  xor  cx,si                {x2 := x2 xor x4; }
      db $66;  not  si                   {x4 :=    not x4; }
      db $66;  or   si,bx                {x4 := x4 or  x1; }
      db $66;  xor  bx,dx                {x1 := x1 xor x3; }
      db $66;  xor  bx,si                {x1 := x1 xor x4; }
      db $66;  or   dx,ax                {x3 := x3 or  x0; }
      db $66;  xor  bx,dx                {x1 := x1 xor x3; }
      db $66;  xor  si,dx                {x4 := x4 xor x3; }
      {here x0=ebx, x1=esi, x2=ecx, x3=eax}
      db $66;  mov  dx,ax
      db $66;  mov  ax,bx
      db $66;  mov  bx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[36*4]
      db $66;  xor  bx, word ptr [di].RndKey[37*4]
      db $66;  xor  cx, word ptr [di].RndKey[38*4]
      db $66;  xor  dx, word ptr [di].RndKey[39*4]

      {RND1(x0,x1,x2,x3);}
      db $66;  not  ax                   {x0 := not x0;    }
      db $66;  not  cx                   {x2 := not x2;    }
      db $66;  mov  si,ax                {x4 := x0;        }
      db $66;  and  ax,bx                {x0 := x0 and x1; }
      db $66;  xor  cx,ax                {x2 := x2 xor x0; }
      db $66;  or   ax,dx                {x0 := x0 or  x3; }
      db $66;  xor  dx,cx                {x3 := x3 xor x2; }
      db $66;  xor  bx,ax                {x1 := x1 xor x0; }
      db $66;  xor  ax,si                {x0 := x0 xor x4; }
      db $66;  or   si,bx                {x4 := x4 or  x1; }
      db $66;  xor  bx,dx                {x1 := x1 xor x3; }
      db $66;  or   cx,ax                {x2 := x2 or  x0; }
      db $66;  and  cx,si                {x2 := x2 and x4; }
      db $66;  xor  ax,bx                {x0 := x0 xor x1; }
      db $66;  and  bx,cx                {x1 := x1 and x2; }
      db $66;  xor  bx,ax                {x1 := x1 xor x0; }
      db $66;  and  ax,cx                {x0 := x0 and x2; }
      db $66;  xor  ax,si                {x0 := x0 xor x4; }
      {here x0=ecx, x1=eax, x2=edx, x3=ebx}
      db $66;  mov  si,ax
      db $66;  mov  ax,cx
      db $66;  mov  cx,dx
      db $66;  mov  dx,bx
      db $66;  mov  bx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[40*4]
      db $66;  xor  bx, word ptr [di].RndKey[41*4]
      db $66;  xor  cx, word ptr [di].RndKey[42*4]
      db $66;  xor  dx, word ptr [di].RndKey[43*4]

      {RND2(x0,x1,x2,x3);}
      db $66;  mov  si,ax                {x4 := x0;         }
      db $66;  and  ax,cx                {x0 := x0 and x2;  }
      db $66;  xor  ax,dx                {x0 := x0 xor x3;  }
      db $66;  xor  cx,bx                {x2 := x2 xor x1;  }
      db $66;  xor  cx,ax                {x2 := x2 xor x0;  }
      db $66;  or   dx,si                {x3 := x3 or  x4;  }
      db $66;  xor  dx,bx                {x3 := x3 xor x1;  }
      db $66;  xor  si,cx                {x4 := x4 xor x2;  }
      db $66;  mov  bx,dx                {x1 := x3;         }
      db $66;  or   dx,si                {x3 := x3 or  x4;  }
      db $66;  xor  dx,ax                {x3 := x3 xor x0;  }
      db $66;  and  ax,bx                {x0 := x0 and x1;  }
      db $66;  xor  si,ax                {x4 := x4 xor x0;  }
      db $66;  xor  bx,dx                {x1 := x1 xor x3;  }
      db $66;  xor  bx,si                {x1 := x1 xor x4;  }
      db $66;  not  si                   {x4 := not x4;     }
      {here x0=ecx, x1=edx, x2=ebx, x3=esi}
      db $66;  mov  ax,cx
      db $66;  mov  cx,bx
      db $66;  mov  bx,dx
      db $66;  mov  dx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[44*4]
      db $66;  xor  bx, word ptr [di].RndKey[45*4]
      db $66;  xor  cx, word ptr [di].RndKey[46*4]
      db $66;  xor  dx, word ptr [di].RndKey[47*4]

      {RND3(x0,x1,x2,x3);}
      db $66;  mov  si,ax                {x4 := x0;       }
      db $66;  or   ax,dx                {x0 := x0 or  x3;}
      db $66;  xor  dx,bx                {x3 := x3 xor x1;}
      db $66;  and  bx,si                {x1 := x1 and x4;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  xor  cx,dx                {x2 := x2 xor x3;}
      db $66;  and  dx,ax                {x3 := x3 and x0;}
      db $66;  or   si,bx                {x4 := x4 or  x1;}
      db $66;  xor  dx,si                {x3 := x3 xor x4;}
      db $66;  xor  ax,bx                {x0 := x0 xor x1;}
      db $66;  and  si,ax                {x4 := x4 and x0;}
      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  or   bx,ax                {x1 := x1 or  x0;}
      db $66;  xor  bx,cx                {x1 := x1 xor x2;}
      db $66;  xor  ax,dx                {x0 := x0 xor x3;}
      db $66;  mov  cx,bx                {x2 := x1;       }
      db $66;  or   bx,dx                {x1 := x1 or  x3;}
      db $66;  xor  bx,ax                {x1 := x1 xor x0;}
      {here x0=ebx, x1=ecx, x2=edx, x3=esi}
      db $66;  mov  ax,bx
      db $66;  mov  bx,cx
      db $66;  mov  cx,dx
      db $66;  mov  dx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      {lfsr[9] := x0;
       lfsr[8] := x1;
       lfsr[7] := x2;
       lfsr[6] := x3;}

      db $66;  mov  word ptr [di].lfsr[6*4],dx
      db $66;  mov  word ptr [di].lfsr[7*4],cx
      db $66;  mov  word ptr [di].lfsr[8*4],bx
      db $66;  mov  word ptr [di].lfsr[9*4],ax

      db $66;  xor  ax, word ptr [di].RndKey[48*4]
      db $66;  xor  bx, word ptr [di].RndKey[49*4]
      db $66;  xor  cx, word ptr [di].RndKey[50*4]
      db $66;  xor  dx, word ptr [di].RndKey[51*4]

      {RND4(x0,x1,x2,x3);}

      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  not  dx                   {x3 :=    not x3;}
      db $66;  xor  cx,dx                {x2 := x2 xor x3;}
      db $66;  xor  dx,ax                {x3 := x3 xor x0;}
      db $66;  mov  si,bx                {x4 :=        x1;}
      db $66;  and  bx,dx                {x1 := x1 and x3;}
      db $66;  xor  bx,cx                {x1 := x1 xor x2;}
      db $66;  xor  si,dx                {x4 := x4 xor x3;}
      db $66;  xor  ax,si                {x0 := x0 xor x4;}
      db $66;  and  cx,si                {x2 := x2 and x4;}
      db $66;  xor  cx,ax                {x2 := x2 xor x0;}
      db $66;  and  ax,bx                {x0 := x0 and x1;}
      db $66;  xor  dx,ax                {x3 := x3 xor x0;}
      db $66;  or   si,bx                {x4 := x4 or  x1;}
      db $66;  xor  si,ax                {x4 := x4 xor x0;}
      db $66;  or   ax,dx                {x0 := x0 or  x3;}
      db $66;  xor  ax,cx                {x0 := x0 xor x2;}
      db $66;  and  cx,dx                {x2 := x2 and x3;}
      db $66;  not  ax                   {x0 :=    not x0;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      {here x0=ebx, x1=esi, x2=eax, x3=edx}
      db $66;  mov  cx,ax
      db $66;  mov  ax,bx
      db $66;  mov  bx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[52*4]
      db $66;  xor  bx, word ptr [di].RndKey[53*4]
      db $66;  xor  cx, word ptr [di].RndKey[54*4]
      db $66;  xor  dx, word ptr [di].RndKey[55*4]

      {RND5(x0,x1,x2,x3);}
      db $66;  xor  ax,bx                {x0 := x0 xor x1;}
      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  not  dx                   {x3 :=    not x3;}
      db $66;  mov  si,bx                {x4 :=        x1;}
      db $66;  and  bx,ax                {x1 := x1 and x0;}
      db $66;  xor  cx,dx                {x2 := x2 xor x3;}
      db $66;  xor  bx,cx                {x1 := x1 xor x2;}
      db $66;  or   cx,si                {x2 := x2 or  x4;}
      db $66;  xor  si,dx                {x4 := x4 xor x3;}
      db $66;  and  dx,bx                {x3 := x3 and x1;}
      db $66;  xor  dx,ax                {x3 := x3 xor x0;}
      db $66;  xor  si,bx                {x4 := x4 xor x1;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  xor  cx,ax                {x2 := x2 xor x0;}
      db $66;  and  ax,dx                {x0 := x0 and x3;}
      db $66;  not  cx                   {x2 :=    not x2;}
      db $66;  xor  ax,si                {x0 := x0 xor x4;}
      db $66;  or   si,dx                {x4 := x4 or  x3;}
      db $66;  xor  cx,si                {x2 := x2 xor x4;}
      {here x0=ebx, x1=edx, x2=eax, x3=ecx}
      db $66;  mov  si,ax
      db $66;  mov  ax,bx
      db $66;  mov  bx,dx
      db $66;  mov  dx,cx
      db $66;  mov  cx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[56*4]
      db $66;  xor  bx, word ptr [di].RndKey[57*4]
      db $66;  xor  cx, word ptr [di].RndKey[58*4]
      db $66;  xor  dx, word ptr [di].RndKey[59*4]

      {RND6(x0,x1,x2,x3);}
      db $66;  not  cx                   {x2 :=    not x2;}
      db $66;  mov  si,dx                {x4 :=        x3;}
      db $66;  and  dx,ax                {x3 := x3 and x0;}
      db $66;  xor  ax,si                {x0 := x0 xor x4;}
      db $66;  xor  dx,cx                {x3 := x3 xor x2;}
      db $66;  or   cx,si                {x2 := x2 or  x4;}
      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  xor  cx,ax                {x2 := x2 xor x0;}
      db $66;  or   ax,bx                {x0 := x0 or  x1;}
      db $66;  xor  cx,bx                {x2 := x2 xor x1;}
      db $66;  xor  si,ax                {x4 := x4 xor x0;}
      db $66;  or   ax,dx                {x0 := x0 or  x3;}
      db $66;  xor  ax,cx                {x0 := x0 xor x2;}
      db $66;  xor  si,dx                {x4 := x4 xor x3;}
      db $66;  xor  si,ax                {x4 := x4 xor x0;}
      db $66;  not  dx                   {x3 :=    not x3;}
      db $66;  and  cx,si                {x2 := x2 and x4;}
      db $66;  xor  cx,dx                {x2 := x2 xor x3;}
      {here x0=eax, x1=ebx, x2=esi, x3=ecx}
      db $66;  mov  dx,cx
      db $66;  mov  cx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[60*4]
      db $66;  xor  bx, word ptr [di].RndKey[61*4]
      db $66;  xor  cx, word ptr [di].RndKey[62*4]
      db $66;  xor  dx, word ptr [di].RndKey[63*4]

      {RND7(x0,x1,x2,x3);}
      db $66;  mov  si,bx                {x4 :=        x1;}
      db $66;  or   bx,cx                {x1 := x1 or  x2;}
      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  xor  cx,bx                {x2 := x2 xor x1;}
      db $66;  or   dx,si                {x3 := x3 or  x4;}
      db $66;  and  dx,ax                {x3 := x3 and x0;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  xor  dx,bx                {x3 := x3 xor x1;}
      db $66;  or   bx,si                {x1 := x1 or  x4;}
      db $66;  xor  bx,ax                {x1 := x1 xor x0;}
      db $66;  or   ax,si                {x0 := x0 or  x4;}
      db $66;  xor  ax,cx                {x0 := x0 xor x2;}
      db $66;  xor  bx,si                {x1 := x1 xor x4;}
      db $66;  xor  cx,bx                {x2 := x2 xor x1;}
      db $66;  and  bx,ax                {x1 := x1 and x0;}
      db $66;  xor  bx,si                {x1 := x1 xor x4;}
      db $66;  not  cx                   {x2 :=    not x2;}
      db $66;  or   cx,ax                {x2 := x2 or  x0;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      {here x0=esi, x1=edx, x2=ebx, x3=eax}
      db $66;  mov  cx,bx
      db $66;  mov  bx,dx
      db $66;  mov  dx,ax
      db $66;  mov  ax,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[64*4]
      db $66;  xor  bx, word ptr [di].RndKey[65*4]
      db $66;  xor  cx, word ptr [di].RndKey[66*4]
      db $66;  xor  dx, word ptr [di].RndKey[67*4]

      {RND0(x0,x1,x2,x3);}
      db $66;  xor  dx,ax                {x3 := x3 xor x0; }
      db $66;  mov  si,bx                {x4 :=        x1; }
      db $66;  and  bx,dx                {x1 := x1 and x3; }
      db $66;  xor  si,cx                {x4 := x4 xor x2; }
      db $66;  xor  bx,ax                {x1 := x1 xor x0; }
      db $66;  or   ax,dx                {x0 := x0 or  x3; }
      db $66;  xor  ax,si                {x0 := x0 xor x4; }
      db $66;  xor  si,dx                {x4 := x4 xor x3; }
      db $66;  xor  dx,cx                {x3 := x3 xor x2; }
      db $66;  or   cx,bx                {x2 := x2 or  x1; }
      db $66;  xor  cx,si                {x2 := x2 xor x4; }
      db $66;  not  si                   {x4 :=    not x4; }
      db $66;  or   si,bx                {x4 := x4 or  x1; }
      db $66;  xor  bx,dx                {x1 := x1 xor x3; }
      db $66;  xor  bx,si                {x1 := x1 xor x4; }
      db $66;  or   dx,ax                {x3 := x3 or  x0; }
      db $66;  xor  bx,dx                {x1 := x1 xor x3; }
      db $66;  xor  si,dx                {x4 := x4 xor x3; }
      {here x0=ebx, x1=esi, x2=ecx, x3=eax}
      db $66;  mov  dx,ax
      db $66;  mov  ax,bx
      db $66;  mov  bx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[68*4]
      db $66;  xor  bx, word ptr [di].RndKey[69*4]
      db $66;  xor  cx, word ptr [di].RndKey[70*4]
      db $66;  xor  dx, word ptr [di].RndKey[71*4]

      {RND1(x0,x1,x2,x3);}
      db $66;  not  ax                   {x0 := not x0;    }
      db $66;  not  cx                   {x2 := not x2;    }
      db $66;  mov  si,ax                {x4 := x0;        }
      db $66;  and  ax,bx                {x0 := x0 and x1; }
      db $66;  xor  cx,ax                {x2 := x2 xor x0; }
      db $66;  or   ax,dx                {x0 := x0 or  x3; }
      db $66;  xor  dx,cx                {x3 := x3 xor x2; }
      db $66;  xor  bx,ax                {x1 := x1 xor x0; }
      db $66;  xor  ax,si                {x0 := x0 xor x4; }
      db $66;  or   si,bx                {x4 := x4 or  x1; }
      db $66;  xor  bx,dx                {x1 := x1 xor x3; }
      db $66;  or   cx,ax                {x2 := x2 or  x0; }
      db $66;  and  cx,si                {x2 := x2 and x4; }
      db $66;  xor  ax,bx                {x0 := x0 xor x1; }
      db $66;  and  bx,cx                {x1 := x1 and x2; }
      db $66;  xor  bx,ax                {x1 := x1 xor x0; }
      db $66;  and  ax,cx                {x0 := x0 and x2; }
      db $66;  xor  ax,si                {x0 := x0 xor x4; }
      {here x0=ecx, x1=eax, x2=edx, x3=ebx}
      db $66;  mov  si,ax
      db $66;  mov  ax,cx
      db $66;  mov  cx,dx
      db $66;  mov  dx,bx
      db $66;  mov  bx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      {fsmr[1] := x0;
       lfsr[4] := x1;
       fsmr[2] := x2;
       lfsr[5] := x3;}

      db $66;  mov  word ptr [di].lfsr[4*4],bx
      db $66;  mov  word ptr [di].lfsr[5*4],dx
      db $66;  mov  word ptr [di].fsmr[0*4],ax
      db $66;  mov  word ptr [di].fsmr[1*4],cx

      db $66;  xor  ax, word ptr [di].RndKey[72*4]
      db $66;  xor  bx, word ptr [di].RndKey[73*4]
      db $66;  xor  cx, word ptr [di].RndKey[74*4]
      db $66;  xor  dx, word ptr [di].RndKey[75*4]

      {RND2(x0,x1,x2,x3);}
      db $66;  mov  si,ax                {x4 := x0;         }
      db $66;  and  ax,cx                {x0 := x0 and x2;  }
      db $66;  xor  ax,dx                {x0 := x0 xor x3;  }
      db $66;  xor  cx,bx                {x2 := x2 xor x1;  }
      db $66;  xor  cx,ax                {x2 := x2 xor x0;  }
      db $66;  or   dx,si                {x3 := x3 or  x4;  }
      db $66;  xor  dx,bx                {x3 := x3 xor x1;  }
      db $66;  xor  si,cx                {x4 := x4 xor x2;  }
      db $66;  mov  bx,dx                {x1 := x3;         }
      db $66;  or   dx,si                {x3 := x3 or  x4;  }
      db $66;  xor  dx,ax                {x3 := x3 xor x0;  }
      db $66;  and  ax,bx                {x0 := x0 and x1;  }
      db $66;  xor  si,ax                {x4 := x4 xor x0;  }
      db $66;  xor  bx,dx                {x1 := x1 xor x3;  }
      db $66;  xor  bx,si                {x1 := x1 xor x4;  }
      db $66;  not  si                   {x4 := not x4;     }
      {here x0=ecx, x1=edx, x2=ebx, x3=esi}
      db $66;  mov  ax,cx
      db $66;  mov  cx,bx
      db $66;  mov  bx,dx
      db $66;  mov  dx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[76*4]
      db $66;  xor  bx, word ptr [di].RndKey[77*4]
      db $66;  xor  cx, word ptr [di].RndKey[78*4]
      db $66;  xor  dx, word ptr [di].RndKey[79*4]

      {RND3(x0,x1,x2,x3);}
      db $66;  mov  si,ax                {x4 := x0;       }
      db $66;  or   ax,dx                {x0 := x0 or  x3;}
      db $66;  xor  dx,bx                {x3 := x3 xor x1;}
      db $66;  and  bx,si                {x1 := x1 and x4;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  xor  cx,dx                {x2 := x2 xor x3;}
      db $66;  and  dx,ax                {x3 := x3 and x0;}
      db $66;  or   si,bx                {x4 := x4 or  x1;}
      db $66;  xor  dx,si                {x3 := x3 xor x4;}
      db $66;  xor  ax,bx                {x0 := x0 xor x1;}
      db $66;  and  si,ax                {x4 := x4 and x0;}
      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  or   bx,ax                {x1 := x1 or  x0;}
      db $66;  xor  bx,cx                {x1 := x1 xor x2;}
      db $66;  xor  ax,dx                {x0 := x0 xor x3;}
      db $66;  mov  cx,bx                {x2 := x1;       }
      db $66;  or   bx,dx                {x1 := x1 or  x3;}
      db $66;  xor  bx,ax                {x1 := x1 xor x0;}
      {here x0=ebx, x1=ecx, x2=edx, x3=esi}
      db $66;  mov  ax,bx
      db $66;  mov  bx,cx
      db $66;  mov  cx,dx
      db $66;  mov  dx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[80*4]
      db $66;  xor  bx, word ptr [di].RndKey[81*4]
      db $66;  xor  cx, word ptr [di].RndKey[82*4]
      db $66;  xor  dx, word ptr [di].RndKey[83*4]

      {RND4(x0,x1,x2,x3);}
      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  not  dx                   {x3 :=    not x3;}
      db $66;  xor  cx,dx                {x2 := x2 xor x3;}
      db $66;  xor  dx,ax                {x3 := x3 xor x0;}
      db $66;  mov  si,bx                {x4 :=        x1;}
      db $66;  and  bx,dx                {x1 := x1 and x3;}
      db $66;  xor  bx,cx                {x1 := x1 xor x2;}
      db $66;  xor  si,dx                {x4 := x4 xor x3;}
      db $66;  xor  ax,si                {x0 := x0 xor x4;}
      db $66;  and  cx,si                {x2 := x2 and x4;}
      db $66;  xor  cx,ax                {x2 := x2 xor x0;}
      db $66;  and  ax,bx                {x0 := x0 and x1;}
      db $66;  xor  dx,ax                {x3 := x3 xor x0;}
      db $66;  or   si,bx                {x4 := x4 or  x1;}
      db $66;  xor  si,ax                {x4 := x4 xor x0;}
      db $66;  or   ax,dx                {x0 := x0 or  x3;}
      db $66;  xor  ax,cx                {x0 := x0 xor x2;}
      db $66;  and  cx,dx                {x2 := x2 and x3;}
      db $66;  not  ax                   {x0 :=    not x0;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      {here x0=ebx, x1=esi, x2=eax, x3=edx}
      db $66;  mov  cx,ax
      db $66;  mov  ax,bx
      db $66;  mov  bx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[84*4]
      db $66;  xor  bx, word ptr [di].RndKey[85*4]
      db $66;  xor  cx, word ptr [di].RndKey[86*4]
      db $66;  xor  dx, word ptr [di].RndKey[87*4]

      {RND5(x0,x1,x2,x3);}
      db $66;  xor  ax,bx                {x0 := x0 xor x1;}
      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  not  dx                   {x3 :=    not x3;}
      db $66;  mov  si,bx                {x4 :=        x1;}
      db $66;  and  bx,ax                {x1 := x1 and x0;}
      db $66;  xor  cx,dx                {x2 := x2 xor x3;}
      db $66;  xor  bx,cx                {x1 := x1 xor x2;}
      db $66;  or   cx,si                {x2 := x2 or  x4;}
      db $66;  xor  si,dx                {x4 := x4 xor x3;}
      db $66;  and  dx,bx                {x3 := x3 and x1;}
      db $66;  xor  dx,ax                {x3 := x3 xor x0;}
      db $66;  xor  si,bx                {x4 := x4 xor x1;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  xor  cx,ax                {x2 := x2 xor x0;}
      db $66;  and  ax,dx                {x0 := x0 and x3;}
      db $66;  not  cx                   {x2 :=    not x2;}
      db $66;  xor  ax,si                {x0 := x0 xor x4;}
      db $66;  or   si,dx                {x4 := x4 or  x3;}
      db $66;  xor  cx,si                {x2 := x2 xor x4;}
      {here x0=ebx, x1=edx, x2=eax, x3=ecx}
      db $66;  mov  si,ax
      db $66;  mov  ax,bx
      db $66;  mov  bx,dx
      db $66;  mov  dx,cx
      db $66;  mov  cx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[88*4]
      db $66;  xor  bx, word ptr [di].RndKey[89*4]
      db $66;  xor  cx, word ptr [di].RndKey[90*4]
      db $66;  xor  dx, word ptr [di].RndKey[91*4]

      {RND6(x0,x1,x2,x3);}
      db $66;  not  cx                   {x2 :=    not x2;}
      db $66;  mov  si,dx                {x4 :=        x3;}
      db $66;  and  dx,ax                {x3 := x3 and x0;}
      db $66;  xor  ax,si                {x0 := x0 xor x4;}
      db $66;  xor  dx,cx                {x3 := x3 xor x2;}
      db $66;  or   cx,si                {x2 := x2 or  x4;}
      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  xor  cx,ax                {x2 := x2 xor x0;}
      db $66;  or   ax,bx                {x0 := x0 or  x1;}
      db $66;  xor  cx,bx                {x2 := x2 xor x1;}
      db $66;  xor  si,ax                {x4 := x4 xor x0;}
      db $66;  or   ax,dx                {x0 := x0 or  x3;}
      db $66;  xor  ax,cx                {x0 := x0 xor x2;}
      db $66;  xor  si,dx                {x4 := x4 xor x3;}
      db $66;  xor  si,ax                {x4 := x4 xor x0;}
      db $66;  not  dx                   {x3 :=    not x3;}
      db $66;  and  cx,si                {x2 := x2 and x4;}
      db $66;  xor  cx,dx                {x2 := x2 xor x3;}
      {here x0=eax, x1=ebx, x2=esi, x3=ecx}
      db $66;  mov  dx,cx
      db $66;  mov  cx,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }

      db $66;  xor  ax, word ptr [di].RndKey[92*4]
      db $66;  xor  bx, word ptr [di].RndKey[93*4]
      db $66;  xor  cx, word ptr [di].RndKey[94*4]
      db $66;  xor  dx, word ptr [di].RndKey[95*4]

      {RND7(x0,x1,x2,x3);}
      db $66;  mov  si,bx                {x4 :=        x1;}
      db $66;  or   bx,cx                {x1 := x1 or  x2;}
      db $66;  xor  bx,dx                {x1 := x1 xor x3;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  xor  cx,bx                {x2 := x2 xor x1;}
      db $66;  or   dx,si                {x3 := x3 or  x4;}
      db $66;  and  dx,ax                {x3 := x3 and x0;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      db $66;  xor  dx,bx                {x3 := x3 xor x1;}
      db $66;  or   bx,si                {x1 := x1 or  x4;}
      db $66;  xor  bx,ax                {x1 := x1 xor x0;}
      db $66;  or   ax,si                {x0 := x0 or  x4;}
      db $66;  xor  ax,cx                {x0 := x0 xor x2;}
      db $66;  xor  bx,si                {x1 := x1 xor x4;}
      db $66;  xor  cx,bx                {x2 := x2 xor x1;}
      db $66;  and  bx,ax                {x1 := x1 and x0;}
      db $66;  xor  bx,si                {x1 := x1 xor x4;}
      db $66;  not  cx                   {x2 :=    not x2;}
      db $66;  or   cx,ax                {x2 := x2 or  x0;}
      db $66;  xor  si,cx                {x4 := x4 xor x2;}
      {here x0=esi, x1=edx, x2=ebx, x3=eax}
      db $66;  mov  cx,bx
      db $66;  mov  bx,dx
      db $66;  mov  dx,ax
      db $66;  mov  ax,si
      {Transform eax=x0, ebx=x1, ecx=x2, edx=x3}
      db $66;  rol  ax,13                {x0 := RotL(x0, 13);            }
      db $66;  rol  cx,3                 {x2 := RotL(x2,  3);            }
      db $66;  xor  bx,ax                {x1 := x1 xor x0 xor x2;        }
      db $66;  xor  bx,cx
      db $66;  xor  dx,cx                {x3 := x3 xor x2 xor (x0 shl 3);}
      db $66;  mov  si,ax
      db $66;  shl  si,3
      db $66;  xor  dx,si
      db $66;  rol  bx,1                 {x1 := RotL(x1, 1);             }
      db $66;  rol  dx,7                 {x3 := RotL(x3, 7);             }
      db $66;  xor  ax,bx                {x0 := x0 xor x1 xor x3;        }
      db $66;  xor  ax,dx
      db $66;  xor  cx,dx                {x2 := x2 xor x3 xor (x1 shl 7);}
      db $66;  mov  si,bx
      db $66;  shl  si,7
      db $66;  xor  cx,si
      db $66;  rol  ax,5                 {x0 := RotL(x0,  5);            }
      db $66;  rol  cx,22                {x2 := RotL(x2, 22);            }


      {lfsr[3] := x0 xor RndKey[96];
       lfsr[2] := x1 xor RndKey[97];
       lfsr[1] := x2 xor RndKey[98];
       lfsr[0] := x3 xor RndKey[99];}

      db $66;  xor  ax, word ptr [di].RndKey[96*4]
      db $66;  xor  bx, word ptr [di].RndKey[97*4]
      db $66;  xor  cx, word ptr [di].RndKey[98*4]
      db $66;  xor  dx, word ptr [di].RndKey[99*4]

      db $66;  mov  word ptr [di].lfsr[0*4],dx
      db $66;  mov  word ptr [di].lfsr[1*4],cx
      db $66;  mov  word ptr [di].lfsr[2*4],bx
      db $66;  mov  word ptr [di].lfsr[3*4],ax

               pop  ds
    end;
  end;
end;


{$ifdef Q_OPT}
{$Q-}
{$endif}

{$R-}

{---------------------------------------------------------------------------}
procedure MakeStreamBlock(var ctx: sose_ctx; pblk: TPSMBlockW; nblk: word);
  {-Generate next nblk key stream blocks}
var
  s0,s1,s2,s3,s4,
  s5,s6,s7,s8,s9,
  r1,r2,
  f0,f1,f2,f3,f4: longint;
  v0,v1,v2,v3,tt: longint;
begin
  {$ifdef BASM16}
   {$ifdef DebugAlign}
    if ofs(s0) and 3 <> 0 then begin
      writeln('osf(s0) and 3 <> 0');
      halt;
    end;
   {$endif}
  {$endif}
  with ctx do begin
    s0 := lfsr[0];
    s1 := lfsr[1];
    s2 := lfsr[2];
    s3 := lfsr[3];
    s4 := lfsr[4];
    s5 := lfsr[5];
    s6 := lfsr[6];
    s7 := lfsr[7];
    s8 := lfsr[8];
    s9 := lfsr[9];
    r1 := fsmr[1];
    r2 := fsmr[2];
    while nblk>0 do begin
      asm
        (*
        tt := r1;
        r1 := r2 + (s1 xor (sig[r1 and 1] and s8));
        r2 := RotL(tt * $54655307,7);
        v0 := s0;
        s0 := (SHL8(s0) xor mulAlpha[TBA4(s0)[3]]) xor (SHR8(s3) xor divAlpha[byte(s3)]) xor s9;
        f0 := (s9 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s8]
        db $66;  xor ax,word ptr [s1]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s0]
        db $66;  mov word ptr [v0],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s3]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s9]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s0],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f0],cx


        (*
        tt := r1;
        r1 := r2 + (s2 xor (sig[r1 and 1] and s9));
        r2 := RotL(tt * $54655307,7);
        v1 := s1;
        s1 := (SHL8(s1) xor mulAlpha[TBA4(s1)[3]]) xor (SHR8(s4) xor divAlpha[byte(s4)]) xor s0;
        f1 := (s0 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s9]
        db $66;  xor ax,word ptr [s2]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s1]
        db $66;  mov word ptr [v1],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s4]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s0]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s1],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f1],cx


        (*
        tt := r1;
        r1 := r2 + (s3 xor (sig[r1 and 1] and s0));
        r2 := RotL(tt * $54655307,7);
        v2 := s2;
        s2 := (SHL8(s2) xor mulAlpha[TBA4(s2)[3]]) xor (SHR8(s5) xor divAlpha[byte(s5)]) xor s1;
        f2 := (s1 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s0]
        db $66;  xor ax,word ptr [s3]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s2]
        db $66;  mov word ptr [v2],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s5]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s1]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s2],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f2],cx


        (*
        tt := r1;
        r1 := r2 + (s4 xor (sig[r1 and 1] and s1));
        r2 := RotL(tt * $54655307,7);
        v3 := s3;
        s3 := (SHL8(s3) xor mulAlpha[TBA4(s3)[3]]) xor (SHR8(s6) xor divAlpha[byte(s6)]) xor s2;
        f3 := (s2 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s1]
        db $66;  xor ax,word ptr [s4]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s3]
        db $66;  mov word ptr [v3],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s6]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s2]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s3],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f3],cx


        db $66;  mov  ax,word ptr [f0]
        db $66;  mov  bx,word ptr [f1]
        db $66;  mov  cx,word ptr [f2]
        db $66;  mov  dx,word ptr [f3]
        db $66;  mov  si,ax              {f4 := f0;       }
        db $66;  and  ax,cx              {f0 := f0 and f2;}
        db $66;  xor  ax,dx              {f0 := f0 xor f3;}
        db $66;  xor  cx,bx              {f2 := f2 xor f1;}
        db $66;  xor  cx,ax              {f2 := f2 xor f0;}
        db $66;  or   dx,si              {f3 := f3  or f4;}
        db $66;  xor  dx,bx              {f3 := f3 xor f1;}
        db $66;  xor  si,cx              {f4 := f4 xor f2;}
        db $66;  mov  bx,dx              {f1 := f3;       }
        db $66;  or   dx,si              {f3 := f3  or f4;}
        db $66;  xor  dx,ax              {f3 := f3 xor f0;}
        db $66;  and  ax,bx              {f0 := f0 and f1;}
        db $66;  xor  si,ax              {f4 := f4 xor f0;}
        db $66;  xor  bx,dx              {f1 := f1 xor f3;}
        db $66;  xor  bx,si              {f1 := f1 xor f4;}
        db $66;  not  si                 {f4 := not f4;   }
                 les  di,[pblk]
        db $66;  xor  cx,word ptr [v0]
        db $66;  mov  word ptr es:[di],cx        {pblk^[0] := f2 xor v0;}
        db $66;  xor  dx,word ptr [v1]
        db $66;  mov  word ptr es:[di+4*1],dx    {pblk^[1] := f3 xor v1;}
        db $66;  xor  bx,word ptr [v2]
        db $66;  mov  word ptr es:[di+4*2],bx    {pblk^[2] := f1 xor v2;}
        db $66;  xor  si,word ptr [v3]
        db $66;  mov  word ptr es:[di+4*3],si    {pblk^[3] := f4 xor v3;}


        (*
        tt := r1;
        r1 := r2 + (s5 xor (sig[r1 and 1] and s2));
        r2 := RotL(tt * $54655307,7);
        v0 := s4;
        s4 := (SHL8(s4) xor mulAlpha[TBA4(s4)[3]]) xor (SHR8(s7) xor divAlpha[byte(s7)]) xor s3;
        f0 := (s3 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s2]
        db $66;  xor ax,word ptr [s5]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s4]
        db $66;  mov word ptr [v0],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s7]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s3]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s4],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f0],cx


        (*
        tt := r1;
        r1 := r2 + (s6 xor (sig[r1 and 1] and s3));
        r2 := RotL(tt * $54655307,7);
        v1 := s5;
        s5 := (SHL8(s5) xor mulAlpha[TBA4(s5)[3]]) xor (SHR8(s8) xor divAlpha[byte(s8)]) xor s4;
        f1 := (s4 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s3]
        db $66;  xor ax,word ptr [s6]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s5]
        db $66;  mov word ptr [v1],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s8]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s4]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s5],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f1],cx


        (*
        tt := r1;
        r1 := r2 + (s7 xor (sig[r1 and 1] and s4));
        r2 := RotL(tt * $54655307,7);
        v2 := s6;
        s6 := (SHL8(s6) xor mulAlpha[TBA4(s6)[3]]) xor (SHR8(s9) xor divAlpha[byte(s9)]) xor s5;
        f2 := (s5 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s4]
        db $66;  xor ax,word ptr [s7]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s6]
        db $66;  mov word ptr [v2],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s9]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s5]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s6],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f2],cx

        (*
        tt := r1;
        r1 := r2 + (s8 xor (sig[r1 and 1] and s5));
        r2 := RotL(tt * $54655307,7);
        v3 := s7;
        s7 := (SHL8(s7) xor mulAlpha[TBA4(s7)[3]]) xor (SHR8(s0) xor divAlpha[byte(s0)]) xor s6;
        f3 := (s6 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s5]
        db $66;  xor ax,word ptr [s8]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s7]
        db $66;  mov word ptr [v3],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s0]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s6]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s7],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f3],cx


        db $66;  mov  ax,word ptr [f0]
        db $66;  mov  bx,word ptr [f1]
        db $66;  mov  cx,word ptr [f2]
        db $66;  mov  dx,word ptr [f3]
        db $66;  mov  si,ax              {f4 := f0;       }
        db $66;  and  ax,cx              {f0 := f0 and f2;}
        db $66;  xor  ax,dx              {f0 := f0 xor f3;}
        db $66;  xor  cx,bx              {f2 := f2 xor f1;}
        db $66;  xor  cx,ax              {f2 := f2 xor f0;}
        db $66;  or   dx,si              {f3 := f3  or f4;}
        db $66;  xor  dx,bx              {f3 := f3 xor f1;}
        db $66;  xor  si,cx              {f4 := f4 xor f2;}
        db $66;  mov  bx,dx              {f1 := f3;       }
        db $66;  or   dx,si              {f3 := f3  or f4;}
        db $66;  xor  dx,ax              {f3 := f3 xor f0;}
        db $66;  and  ax,bx              {f0 := f0 and f1;}
        db $66;  xor  si,ax              {f4 := f4 xor f0;}
        db $66;  xor  bx,dx              {f1 := f1 xor f3;}
        db $66;  xor  bx,si              {f1 := f1 xor f4;}
        db $66;  not  si                 {f4 := not f4;   }
                 les  di,[pblk]
        db $66;  xor  cx,word ptr [v0]
        db $66;  mov  word ptr es:[di+4*4],cx    {pblk^[4] := f2 xor v0;}
        db $66;  xor  dx,word ptr [v1]
        db $66;  mov  word ptr es:[di+4*5],dx    {pblk^[5] := f3 xor v1;}
        db $66;  xor  bx,word ptr [v2]
        db $66;  mov  word ptr es:[di+4*6],bx    {pblk^[6] := f1 xor v2;}
        db $66;  xor  si,word ptr [v3]
        db $66;  mov  word ptr es:[di+4*7],si    {pblk^[7] := f4 xor v3;}


        (*
        tt := r1;
        r1 := r2 + (s9 xor (sig[r1 and 1] and s6));
        r2 := RotL(tt * $54655307,7);
        v0 := s8;
        s8 := (SHL8(s8) xor mulAlpha[TBA4(s8)[3]]) xor (SHR8(s1) xor divAlpha[byte(s1)]) xor s7;
        f0 := (s7 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s6]
        db $66;  xor ax,word ptr [s9]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s8]
        db $66;  mov word ptr [v0],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s1]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s7]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s8],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f0],cx


        (*
        tt := r1;
        r1 := r2 + (s0 xor (sig[r1 and 1] and s7));
        r2 := RotL(tt * $54655307,7);
        v1 := s9;
        s9 := (SHL8(s9) xor mulAlpha[TBA4(s9)[3]]) xor (SHR8(s2) xor divAlpha[byte(s2)]) xor s8;
        f1 := (s8 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s7]
        db $66;  xor ax,word ptr [s0]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s9]
        db $66;  mov word ptr [v1],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s2]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s8]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s9],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f1],cx


        (*
        tt := r1;
        r1 := r2 + (s1 xor (sig[r1 and 1] and s8));
        r2 := RotL(tt * $54655307,7);
        v2 := s0;
        s0 := (SHL8(s0) xor mulAlpha[TBA4(s0)[3]]) xor (SHR8(s3) xor divAlpha[byte(s3)]) xor s9;
        f2 := (s9 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s8]
        db $66;  xor ax,word ptr [s1]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s0]
        db $66;  mov word ptr [v2],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s3]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s9]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s0],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f2],cx


        (*
        tt := r1;
        r1 := r2 + (s2 xor (sig[r1 and 1] and s9));
        r2 := RotL(tt * $54655307,7);
        v3 := s1;
        s1 := (SHL8(s1) xor mulAlpha[TBA4(s1)[3]]) xor (SHR8(s4) xor divAlpha[byte(s4)]) xor s0;
        f3 := (s0 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s9]
        db $66;  xor ax,word ptr [s2]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s1]
        db $66;  mov word ptr [v3],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s4]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s0]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s1],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f3],cx

        db $66;  mov  ax,word ptr [f0]
        db $66;  mov  bx,word ptr [f1]
        db $66;  mov  cx,word ptr [f2]
        db $66;  mov  dx,word ptr [f3]
        db $66;  mov  si,ax              {f4 := f0;       }
        db $66;  and  ax,cx              {f0 := f0 and f2;}
        db $66;  xor  ax,dx              {f0 := f0 xor f3;}
        db $66;  xor  cx,bx              {f2 := f2 xor f1;}
        db $66;  xor  cx,ax              {f2 := f2 xor f0;}
        db $66;  or   dx,si              {f3 := f3  or f4;}
        db $66;  xor  dx,bx              {f3 := f3 xor f1;}
        db $66;  xor  si,cx              {f4 := f4 xor f2;}
        db $66;  mov  bx,dx              {f1 := f3;       }
        db $66;  or   dx,si              {f3 := f3  or f4;}
        db $66;  xor  dx,ax              {f3 := f3 xor f0;}
        db $66;  and  ax,bx              {f0 := f0 and f1;}
        db $66;  xor  si,ax              {f4 := f4 xor f0;}
        db $66;  xor  bx,dx              {f1 := f1 xor f3;}
        db $66;  xor  bx,si              {f1 := f1 xor f4;}
        db $66;  not  si                 {f4 := not f4;   }
                 les  di,[pblk]
        db $66;  xor  cx,word ptr [v0]
        db $66;  mov  word ptr es:[di+4*8],cx    {pblk^[ 8] := f2 xor v0;}
        db $66;  xor  dx,word ptr [v1]
        db $66;  mov  word ptr es:[di+4*9],dx    {pblk^[ 9] := f3 xor v1;}
        db $66;  xor  bx,word ptr [v2]
        db $66;  mov  word ptr es:[di+4*10],bx   {pblk^[10] := f1 xor v2;}
        db $66;  xor  si,word ptr [v3]
        db $66;  mov  word ptr es:[di+4*11],si   {pblk^[11] := f4 xor v3;}


        (*
        tt := r1;
        r1 := r2 + (s3 xor (sig[r1 and 1] and s0));
        r2 := RotL(tt * $54655307,7);
        v0 := s2;
        s2 := (SHL8(s2) xor mulAlpha[TBA4(s2)[3]]) xor (SHR8(s5) xor divAlpha[byte(s5)]) xor s1;
        f0 := (s1 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s0]
        db $66;  xor ax,word ptr [s3]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s2]
        db $66;  mov word ptr [v0],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s5]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s1]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s2],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f0],cx

        (*
        tt := r1;
        r1 := r2 + (s4 xor (sig[r1 and 1] and s1));
        r2 := RotL(tt * $54655307,7);
        v1 := s3;
        s3 := (SHL8(s3) xor mulAlpha[TBA4(s3)[3]]) xor (SHR8(s6) xor divAlpha[byte(s6)]) xor s2;
        f1 := (s2 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s1]
        db $66;  xor ax,word ptr [s4]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s3]
        db $66;  mov word ptr [v1],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s6]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s2]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s3],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f1],cx


        (*
        tt := r1;
        r1 := r2 + (s5 xor (sig[r1 and 1] and s2));
        r2 := RotL(tt * $54655307,7);
        v2 := s4;
        s4 := (SHL8(s4) xor mulAlpha[TBA4(s4)[3]]) xor (SHR8(s7) xor divAlpha[byte(s7)]) xor s3;
        f2 := (s3 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s2]
        db $66;  xor ax,word ptr [s5]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s4]
        db $66;  mov word ptr [v2],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s7]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s3]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s4],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f2],cx


        (*
        tt := r1;
        r1 := r2 + (s6 xor (sig[r1 and 1] and s3));
        r2 := RotL(tt * $54655307,7);
        v3 := s5;
        s5 := (SHL8(s5) xor mulAlpha[TBA4(s5)[3]]) xor (SHR8(s8) xor divAlpha[byte(s8)]) xor s4;
        f3 := (s4 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s3]
        db $66;  xor ax,word ptr [s6]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s5]
        db $66;  mov word ptr [v3],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s8]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s4]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s5],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f3],cx

        db $66;  mov  ax,word ptr [f0]
        db $66;  mov  bx,word ptr [f1]
        db $66;  mov  cx,word ptr [f2]
        db $66;  mov  dx,word ptr [f3]
        db $66;  mov  si,ax              {f4 := f0;       }
        db $66;  and  ax,cx              {f0 := f0 and f2;}
        db $66;  xor  ax,dx              {f0 := f0 xor f3;}
        db $66;  xor  cx,bx              {f2 := f2 xor f1;}
        db $66;  xor  cx,ax              {f2 := f2 xor f0;}
        db $66;  or   dx,si              {f3 := f3  or f4;}
        db $66;  xor  dx,bx              {f3 := f3 xor f1;}
        db $66;  xor  si,cx              {f4 := f4 xor f2;}
        db $66;  mov  bx,dx              {f1 := f3;       }
        db $66;  or   dx,si              {f3 := f3  or f4;}
        db $66;  xor  dx,ax              {f3 := f3 xor f0;}
        db $66;  and  ax,bx              {f0 := f0 and f1;}
        db $66;  xor  si,ax              {f4 := f4 xor f0;}
        db $66;  xor  bx,dx              {f1 := f1 xor f3;}
        db $66;  xor  bx,si              {f1 := f1 xor f4;}
        db $66;  not  si                 {f4 := not f4;   }
                 les  di,[pblk]
        db $66;  xor  cx,word ptr [v0]
        db $66;  mov  word ptr es:[di+4*12],cx    {pblk^[12] := f2 xor v0;}
        db $66;  xor  dx,word ptr [v1]
        db $66;  mov  word ptr es:[di+4*13],dx    {pblk^[13] := f3 xor v1;}
        db $66;  xor  bx,word ptr [v2]
        db $66;  mov  word ptr es:[di+4*14],bx    {pblk^[14] := f1 xor v2;}
        db $66;  xor  si,word ptr [v3]
        db $66;  mov  word ptr es:[di+4*15],si    {pblk^[15] := f4 xor v3;}


        (*
        tt := r1;
        r1 := r2 + (s7 xor (sig[r1 and 1] and s4));
        r2 := RotL(tt * $54655307,7);
        v0 := s6;
        s6 := (SHL8(s6) xor mulAlpha[TBA4(s6)[3]]) xor (SHR8(s9) xor divAlpha[byte(s9)]) xor s5;
        f0 := (s5 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s4]
        db $66;  xor ax,word ptr [s7]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s6]
        db $66;  mov word ptr [v0],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s9]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s5]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s6],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f0],cx


        (*
        tt := r1;
        r1 := r2 + (s8 xor (sig[r1 and 1] and s5));
        r2 := RotL(tt * $54655307,7);
        v1 := s7;
        s7 := (SHL8(s7) xor mulAlpha[TBA4(s7)[3]]) xor (SHR8(s0) xor divAlpha[byte(s0)]) xor s6;
        f1 := (s6 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s5]
        db $66;  xor ax,word ptr [s8]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s7]
        db $66;  mov word ptr [v1],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s0]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s6]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s7],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f1],cx


        (*
        tt := r1;
        r1 := r2 + (s9 xor (sig[r1 and 1] and s6));
        r2 := RotL(tt * $54655307,7);
        v2 := s8;
        s8 := (SHL8(s8) xor mulAlpha[TBA4(s8)[3]]) xor (SHR8(s1) xor divAlpha[byte(s1)]) xor s7;
        f2 := (s7 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s6]
        db $66;  xor ax,word ptr [s9]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s8]
        db $66;  mov word ptr [v2],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s1]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s7]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s8],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f2],cx

        (*
        tt := r1;
        r1 := r2 + (s0 xor (sig[r1 and 1] and s7));
        r2 := RotL(tt * $54655307,7);
        v3 := s9;
        s9 := (SHL8(s9) xor mulAlpha[TBA4(s9)[3]]) xor (SHR8(s2) xor divAlpha[byte(s2)]) xor s8;
        f3 := (s8 + r1) xor r2;
        *)
        db $66;  mov ax,word ptr [r1]
        db $66;  mov cx,ax
                 shr ax,1
        db $66;  sbb ax,ax
        db $66;  and ax,word ptr [s7]
        db $66;  xor ax,word ptr [s0]
        db $66;  add ax,word ptr [r2]
        db $66;  mov word ptr [r1],ax
        db $66;  mov ax,$5307; dw $5465;
        db $66;  mul cx
        db $66;  rol ax,7
        db $66;  mov word ptr [r2],ax
        db $66;  mov ax,word ptr [s9]
        db $66;  mov word ptr [v3],ax

        db $66;  mov bx,ax
        db $66;  shr bx,24
                 shl bx,2
        db $66;  shl ax,8
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr mulAlpha[bx]
     {$else}
                 mov cx,word ptr mulAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr mulAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s2]
        db $66;  mov bx,cx
                 sub bh,bh
                 shl bx,2
        db $66;  shr cx,8
        db $66;  xor ax,cx
     {$ifdef Alpha32}
        db $66;  mov cx,word ptr divAlpha[bx]
     {$else}
                 mov cx,word ptr divAlpha[bx+2]
        db $66;  shl cx,16;
                 mov cx,word ptr divAlpha[bx]
     {$endif}
        db $66;  xor ax,cx
        db $66;  mov cx,word ptr [s8]
        db $66;  xor ax,cx
        db $66;  mov word ptr [s9],ax
        db $66;  add cx, word ptr [r1]
        db $66;  xor cx, word ptr [r2]
        db $66;  mov word ptr [f3],cx


        db $66;  mov  ax,word ptr [f0]
        db $66;  mov  bx,word ptr [f1]
        db $66;  mov  cx,word ptr [f2]
        db $66;  mov  dx,word ptr [f3]
        db $66;  mov  si,ax              {f4 := f0;       }
        db $66;  and  ax,cx              {f0 := f0 and f2;}
        db $66;  xor  ax,dx              {f0 := f0 xor f3;}
        db $66;  xor  cx,bx              {f2 := f2 xor f1;}
        db $66;  xor  cx,ax              {f2 := f2 xor f0;}
        db $66;  or   dx,si              {f3 := f3  or f4;}
        db $66;  xor  dx,bx              {f3 := f3 xor f1;}
        db $66;  xor  si,cx              {f4 := f4 xor f2;}
        db $66;  mov  bx,dx              {f1 := f3;       }
        db $66;  or   dx,si              {f3 := f3  or f4;}
        db $66;  xor  dx,ax              {f3 := f3 xor f0;}
        db $66;  and  ax,bx              {f0 := f0 and f1;}
        db $66;  xor  si,ax              {f4 := f4 xor f0;}
        db $66;  xor  bx,dx              {f1 := f1 xor f3;}
        db $66;  xor  bx,si              {f1 := f1 xor f4;}
        db $66;  not  si                 {f4 := not f4;   }
                 les  di,[pblk]
        db $66;  xor  cx,word ptr [v0]
        db $66;  mov  word ptr es:[di+4*16],cx    {pblk^[16] := f2 xor v0;}
        db $66;  xor  dx,word ptr [v1]
        db $66;  mov  word ptr es:[di+4*17],dx    {pblk^[17] := f3 xor v1;}
        db $66;  xor  bx,word ptr [v2]
        db $66;  mov  word ptr es:[di+4*18],bx    {pblk^[18] := f1 xor v2;}
        db $66;  xor  si,word ptr [v3]
        db $66;  mov  word ptr es:[di+4*19],si    {pblk^[19] := f4 xor v3;}
      end;

      dec(nblk);
      inc(Ptr2Inc(pblk),sizeof(TSMBlockW));
    end;
    lfsr[0] := s0;
    lfsr[1] := s1;
    lfsr[2] := s2;
    lfsr[3] := s3;
    lfsr[4] := s4;
    lfsr[5] := s5;
    lfsr[6] := s6;
    lfsr[7] := s7;
    lfsr[8] := s8;
    lfsr[9] := s9;
    fsmr[1] := r1;
    fsmr[2] := r2;
  end;
end;


{$ifdef Q_OPT}
  {$ifdef OverflowChecks_on}
    {$Q+}
  {$endif}
{$endif}

{$ifdef RangeChecks_on}
  {$R+}
{$endif}
