package com.kunzisoft.keepass.fido2;

import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Versioned authenticated envelope. No database changes or PIN persistence. */
final class UnlockRecord {
    final FidoToken.Credential credential;
    final byte[] salt, nonce, ciphertext;
    final String database;
    UnlockRecord(String database, FidoToken.Credential credential, byte[] salt, byte[] nonce, byte[] ciphertext) {
        this.database=database; this.credential=credential; this.salt=salt; this.nonce=nonce; this.ciphertext=ciphertext;
    }
    byte[] aad() throws IOException {
        return Cbor.encode(Cbor.map(1,1,2,FidoToken.RP,3,database,4,credential.id,5,credential.publicKey,6,salt));
    }
    static byte[] encodeChars(char[] chars) throws CharacterCodingException {
        ByteBuffer buffer=StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(chars));
        byte[] result=new byte[buffer.remaining()];buffer.get(result);
        if(buffer.hasArray())Arrays.fill(buffer.array(),(byte)0);
        return result;
    }
    static char[] decodeChars(byte[] bytes) throws CharacterCodingException {
        CharBuffer buffer=StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes));
        char[] result=new char[buffer.remaining()];buffer.get(result);
        if(buffer.hasArray())Arrays.fill(buffer.array(),'\0');
        return result;
    }
    static UnlockRecord seal(String db,FidoToken.Credential credential,byte[] salt,byte[] secret,char[] password) throws Exception {
        byte[] nonce=Crypto.random(12),key=null,plain=null;
        try {
            if(secret.length!=32||salt.length!=32||password.length==0||password.length>4096)throw new IOException("Invalid enrollment input");
            key=Crypto.hkdf(secret,salt,"KeePassDX FIDO2 local password v1");
            plain=encodeChars(password);
            UnlockRecord meta=new UnlockRecord(db,credential,salt,nonce,new byte[0]);
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(key,"AES"),new GCMParameterSpec(128,nonce));
            cipher.updateAAD(meta.aad());
            return new UnlockRecord(db,credential,salt,nonce,cipher.doFinal(plain));
        }finally{Crypto.wipe(key);Crypto.wipe(plain);}
    }
    char[] open(byte[] secret) throws Exception {
        byte[] key=null,plain=null;
        try {
            if(secret.length!=32)throw new IOException("Invalid token secret");
            key=Crypto.hkdf(secret,salt,"KeePassDX FIDO2 local password v1");
            plain=Crypto.gcm(key,nonce,aad(),ciphertext);
            return decodeChars(plain);
        }finally{Crypto.wipe(key);Crypto.wipe(plain);}
    }
    byte[] encode() throws Exception {return Cbor.encode(Cbor.map(1,1,2,database,3,credential.id,4,credential.publicKey,5,salt,6,nonce,7,ciphertext));}
    static UnlockRecord decode(String db,byte[] bytes) throws Exception {
        if(bytes.length>32768)throw new IOException("Enrollment record too large");
        Object map=Cbor.decode(bytes);
        if(Cbor.number(Cbor.get(map,1))!=1||!db.equals(Cbor.get(map,2)))throw new IOException("Enrollment does not match this database");
        byte[] id=Cbor.bytes(Cbor.get(map,3)),pk=Cbor.bytes(Cbor.get(map,4)),salt=Cbor.bytes(Cbor.get(map,5)),nonce=Cbor.bytes(Cbor.get(map,6)),ct=Cbor.bytes(Cbor.get(map,7));
        if(id.length<1||id.length>4096||pk.length>256||salt.length!=32||nonce.length!=12||ct.length<17||ct.length>16400)throw new IOException("Invalid enrollment record");
        return new UnlockRecord(db,new FidoToken.Credential(id,pk),salt,nonce,ct);
    }
}
