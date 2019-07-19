{Test cases for XSalsa20 stream cipher,   (c) 2009 W.Ehrhardt}

program T_S20_ST;

{$i std.inc}

{$ifdef APPCONS}
  {$apptype console}
{$endif}

{$ifndef FPC}
  {$N+}
{$endif}

uses
  {$ifdef WINCRT}
    WinCRT,
  {$endif}
  salsa20,mem_util;


type
  trec = record
           key: string[64];
           IV : string[48];
           pt : string[240];
           ct : string[240];
         end;

{Test case from Wei Dai's Crypto++ 5.60}
const
  test: array[1..10] of trec = (
    (key:'3154d3f5bb56b00b34a255425057e99ed9effd1cb0168d16157fd769ddc665ba';
     IV :'f7f9f18f9648f6dc06ac643ea77f1493a9fea3390a98bb0c';
     pt :'80a488703cf316be904ac8394437ea02ae2c027b7880ebec58416429ea060db543839d781d82a0fa209077e4b1';
     ct :'a07abc8ef3641cf33179296ca401bb291a9547d3e6d1b0886ac31d26d2f3281a6a568cc042593132a3cc1082be'),

    (key:'7066fe1125429407b653fd090262bed2a3f7f3be2fa8f160f3344f327b1e53da';
     IV :'beec3787c335739fa5d7ad15b85b7e3e7c9438367434872a';
     pt :'9dad7f5ca1';
     ct :'014a1f27cc'),

    (key:'81426f03ae1578d8ec1407827db18640d9d90d2bb773971f4ef14f859bc19e06';
     IV :'479961f75954ed4f8024108cdb149ca3fd53e6a239a01e86';
     pt :'9cd08cf58e13e94e02c9a40269875392251353223f5329412e2a5e34328ea18c414d4c730b4e1c0bc140953f4ecf4ffc8aec963e59305d4d';
     ct :'db3ea5b5fdc9671ec56b3f1cecbb2a552b0ea4ce9be508863f3dfb3238d4fb91b896727357fe454a08114200ea7226787fd2ab154d53eac8'),

    (key:'ad1a5c47688874e6663a0f3fa16fa7efb7ecadc175c468e5432914bdb480ffc6';
     IV :'e489eed440f1aae1fac8fb7a9825635454f8f8f1f52e2fcc';
     pt :'aa6c1e53580f03a9abb73bfdadedfecada4c6b0ebe020ef10db745e54ba861caf65f0e40dfc520203bb54d29e0a8f78f16b3f1aa525d6bfa'+
         '33c54726e59988cfbec78056';
     ct :'02fe84ce81e178e7aabdd3ba925a766c3c24756eefae33942af75e8b464556b5997e616f3f2dfc7fce91848afd79912d9fb55201b5813a5a'+
         '074d2c0d4292c1fd441807c5'),

    (key:'053a02bedd6368c1fb8afc7a1b199f7f7ea2220c9a4b642a6850091c9d20ab9c';
     IV :'c713eea5c26dad75ad3f52451e003a9cb0d649f917c89dde';
     pt :'8f0a8a164760426567e388840276de3f95cb5e3fadc6ed3f3e4fe8bc169d9388804dcb94b6587dbb66cb0bd5f87b8e98b52af37ba290629b'+
         '858e0e2aa7378047a26602';
     ct :'516710e59843e6fbd4f25d0d8ca0ec0d47d39d125e9dad987e0518d49107014cb0ae405e30c2eb3794750bca142ce95e290cf95abe15e822'+
         '823e2e7d3ab21bc8fbd445'),

    (key:'b3c260036b79cd3345e04cbee474dfea3a7c773db2ccb29d4c36a1b8c8b252e7';
     IV :'1277840fe82046c024e6f4f53b4ff761c7c9bd1fea6c855a';
     pt :'6a6dac1bc93b9b5c0dde0d1e6a534914dc2a6d51e6f8af3e9d42b88bedc2173782a2314b33f795cc2e4536829871d77186168f5461d18130'+
         '581664586256';
     ct :'ff5e71022c6522998a2d10843fda170796a70d186e5fca2afcf529c6d075c5212c793fb322c1675d0bd3cc6b18f2715678812e81a8727a2d'+
         '6ac1158eacf6'),

    (key:'ea060c72f6e0080fd4a9a2131c9d684902415cab34fce4e52d62273e3c385f37';
     IV :'5826043957a27509423fdd82f34935928a4b23a84ede72c8';
     pt :'20ae58dbf5c20225c35518711a86a19a61d5ba47ab17e8c5fa9658333d40ed31bffb79cde927c36baf61ed8df37acac330f64471bd91d90b'+
         'fafa72dc8cdb6ed95ec6610cd6e8f2859255216a3eb4b573410d5644a40e4f0fa785d556304489c0023a1991eb0d01b5';
     ct :'6025c4d5bcc769cc3e67b88340b4101690eb283654c761f8a0af360926313129f16d1c9358ecbaf66acd85787c7c1f52a953bc05e91d43bf'+
         '3d94d341bffc5913435fb3a8e6264ccd1c355472929a140fe30a22689b055082c70395e0b070a3f0967ab36848cdf3d9'),

    (key:'0f2850f98634181f49e53bf49d2f822fbf75e5f77c6cd7487541c514a4101ce7';
     IV :'d6defb4e74c327d89123bdc1d1c6d2fce6b745079bc2c9ef';
     pt :'a064bd9bdab0ee26530c2d26be556cd67295180bca445dfc87954bc51b28a21b606a229cf5a41fa104c51c3f32003a65064ff73e66691e4d'+
         '2b1a22d236232be18677d54aba7ad49edcc9284897a7f88945513460166e5dfd7650959c05328abc0a7e95c352dbc227ca17';
     ct :'51de41664070aec657612a57641c0c83ae14f5b3b25b25d916e0cdfae1c1bd21f7b47d9ab02b6841e115394cad58a568c1d7c2559a1d3fcd'+
         '9cb4b25529d26e475ae313e6487538d16376a6b24e5cf27d2dbf4c83bd18996594f60549f34a8683b04d05198893a816adbb'),

    (key:'5cf680e8a11eb005d03fdc3d4ec0e129e6aceb47262dee6c452a5b8b0ef1b450';
     IV :'6a6920ddba39b5a2640976ca10c97bf308a8cdd70ea98260';
     pt :'1f322b31f5f577a596b0fbe567864c7ce2973b41f924205defe08e2866b7fb5c1814d664d33957614e91668bb15d9848ffb93dc08c1f74c5'+
         'f5e1f88148d1a1a7ad47395b75834de4988adfbf7e58a38157544c2be5b913152c1d00';
     ct :'64d6c9ca4db201d95afc0dce28f6e47d51c2856ccbbc8f4c2e2bd2d834aca165dedd117b0be9a7dcd21eb22b508f4ecd0236075b064a0ced'+
         '23e324b18b2bf2cda1c4416f78c740e51ce687cd37842be368fc4e6ba7cb312d89ea7a'),

    (key:'0f2850f98634181f49e53bf49d2f822fbf75e5f77c6cd7487541c514a4101ce7';
     IV :'d6defb4e74c327d89123bdc1d1c6d2fce6b745079bc2c9ef';
     pt :'a064bd9bdab0ee26530c2d26be556cd67295180bca445dfc87954bc51b28a21b606a229cf5a41fa104c51c3f32003a65064ff73e66691e4d'+
         '2b1a22d236232be18677d54aba7ad49edcc9284897a7f88945513460166e5dfd7650959c05328abc0a7e95c352dbc227ca17';
     ct :'51de41664070aec657612a57641c0c83ae14f5b3b25b25d916e0cdfae1c1bd21f7b47d9ab02b6841e115394cad58a568c1d7c2559a1d3fcd'+
         '9cb4b25529d26e475ae313e6487538d16376a6b24e5cf27d2dbf4c83bd18996594f60549f34a8683b04d05198893a816adbb')
   );

var
  ptb, ctb, tmp: array[0..123] of byte;
  k256: array[0..31] of byte;
  n192: array[0..23] of byte;
  ctx:  salsa_ctx;
  i: integer;
  sl, mlen: word;
begin
  writeln('Test cases for XSalsa20 stream cipher   (c) 2009 W.Ehrhardt');
  writeln('XSalsa20 selftest: ', xsalsa_selftest);
  for i:=1 to 10 do begin
    with test[i] do begin
      write('Test',i:3, ' - ');
      Hex2Mem(key, @k256, sizeof(k256), sl);
      if sl<>sizeof(k256) then begin
        writeln('Invalid key size or conversion error');
        halt;
      end;
      Hex2Mem(IV,  @n192, sizeof(n192), sl);
      if sl<>sizeof(n192) then begin
        writeln('Invalid IV size or conversion error');
        halt;
      end;
      Hex2Mem(pt,  @ptb,  sizeof(ptb) , sl);
      Hex2Mem(ct,  @ctb,  sizeof(ctb) , mlen);
      if mlen<>sl then begin
        writeln('different sizes of plaintext and ciphertext or conversion error');
        halt;
      end;
      xsalsa_setup(ctx, @k256, @n192);
      xsalsa_encrypt_bytes(ctx, @ptb, @tmp, mlen);
      write('EncBuf:', compmem(@ctb, @tmp, mlen):5);
      xsalsa_setup(ctx, @k256, @n192);
      xsalsa_decrypt_bytes(ctx, @ctb, @tmp, mlen);
      write(',   DecBuf:', compmem(@ptb, @tmp, mlen):5);
      xsalsa_encrypt_packet(@k256, @n192, @ptb, @tmp, mlen);
      write(',   EncPack:', compmem(@ctb, @tmp, mlen):5);
      xsalsa_decrypt_packet(@k256, @n192, @ctb, @tmp, mlen);
      write(',   DecPack:', compmem(@ptb, @tmp, mlen):5);
      writeln;
    end;
  end;

end.
