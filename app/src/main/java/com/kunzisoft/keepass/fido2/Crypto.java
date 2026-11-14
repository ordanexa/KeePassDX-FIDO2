package com.kunzisoft.keepass.fido2;
// Adapted from pascalep/fidoparole-android-reader, fa29cd0670265980c3935c9a510b48715d7380b9.
// Original contributions by Pascal Seiler; distributed here under GPL-3.0-or-later.

import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.math.BigInteger;
import java.util.*;
import java.util.zip.*;
import javax.crypto.*;
import javax.crypto.spec.*;

final class Crypto {
    static final SecureRandom RNG=new SecureRandom();
    static byte[] utf8(String s){return s.getBytes(StandardCharsets.UTF_8);}
    static byte[] random(int n){byte[] b=new byte[n];RNG.nextBytes(b);return b;}
    static void wipe(byte[] b){if(b!=null)Arrays.fill(b,(byte)0);}
    static byte[] cat(byte[]... arrays){int n=0;for(byte[] a:arrays)n+=a.length;byte[] b=new byte[n];int p=0;for(byte[] a:arrays){System.arraycopy(a,0,b,p,a.length);p+=a.length;}return b;}
    static byte[] sha(byte[] b)throws GeneralSecurityException{return MessageDigest.getInstance("SHA-256").digest(b);}
    static byte[] hmac(byte[] key,byte[] b)throws GeneralSecurityException{Mac m=Mac.getInstance("HmacSHA256");m.init(new SecretKeySpec(key,"HmacSHA256"));return m.doFinal(b);}
    static byte[] hkdf(byte[] ikm,byte[] salt,String info)throws GeneralSecurityException{byte[] prk=hmac(salt,ikm);try{return hmac(prk,cat(utf8(info),new byte[]{1}));}finally{wipe(prk);}}
    static byte[] gcm(byte[] key,byte[] iv,byte[] aad,byte[] ct)throws GeneralSecurityException{
        if(key.length!=32||iv.length!=12)throw new GeneralSecurityException("Invalid AES-GCM parameters");
        Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,iv));c.updateAAD(aad);return c.doFinal(ct);
    }
    static final class Agreement implements AutoCloseable {
        final int version;final Map<Object,Object> publicKey;byte[] shared;
        Agreement(int version,Object peer)throws Exception{
            this.version=version;
            if(Cbor.number(Cbor.get(peer,1))!=2||Cbor.number(Cbor.get(peer,-1))!=1)throw new IOException("Unsupported key agreement curve");
            KeyPairGenerator gen=KeyPairGenerator.getInstance("EC");gen.initialize(new ECGenParameterSpec("secp256r1"));KeyPair pair=gen.generateKeyPair();
            ECPublicKey pub=(ECPublicKey)pair.getPublic();byte[] x=Cbor.bytes(Cbor.get(peer,-2)),y=Cbor.bytes(Cbor.get(peer,-3));
            if(x.length!=32||y.length!=32)throw new IOException("Invalid P-256 point");
            PublicKey other=KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(new BigInteger(1,x),new BigInteger(1,y)),pub.getParams()));
            KeyAgreement ka=KeyAgreement.getInstance("ECDH");ka.init(pair.getPrivate());ka.doPhase(other,true);byte[] z=ka.generateSecret();
            try{shared=version==1?sha(z):cat(hkdf(z,new byte[32],"CTAP2 HMAC key"),hkdf(z,new byte[32],"CTAP2 AES key"));}finally{wipe(z);}
            publicKey=Cbor.map(1,2,3,-25,-1,1,-2,fixed(pub.getW().getAffineX()),-3,fixed(pub.getW().getAffineY()));
        }
        static byte[] fixed(BigInteger n){byte[] b=n.toByteArray(),out=new byte[32];System.arraycopy(b,Math.max(0,b.length-32),out,Math.max(0,32-b.length),Math.min(32,b.length));return out;}
        byte[] encrypt(byte[] plain)throws Exception{return crypt(plain,true);}
        byte[] decrypt(byte[] ct)throws Exception{return crypt(ct,false);}
        byte[] crypt(byte[] data,boolean encrypt)throws Exception{
            byte[] key=version==1?shared.clone():Arrays.copyOfRange(shared,32,64);
            byte[] iv=version==1?new byte[16]:encrypt?random(16):Arrays.copyOf(data,16);
            byte[] input=version==2&&!encrypt?Arrays.copyOfRange(data,16,data.length):data;
            try{Cipher c=Cipher.getInstance("AES/CBC/NoPadding");c.init(encrypt?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new IvParameterSpec(iv));byte[] out=c.doFinal(input);return version==2&&encrypt?cat(iv,out):out;}finally{wipe(key);}
        }
        byte[] authenticate(byte[] message)throws Exception{byte[] key=version==1?shared.clone():Arrays.copyOf(shared,32);try{byte[] mac=hmac(key,message);return version==1?Arrays.copyOf(mac,16):mac;}finally{wipe(key);}}
        public void close(){wipe(shared);}
    }
}

