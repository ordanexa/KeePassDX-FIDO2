package com.kunzisoft.keepass.fido2;

import android.util.AtomicFile;
import java.io.*;
import java.security.MessageDigest;

/** Durable encrypted enrollment storage, separate from database attachment cache. */
final class EnrollmentStorage {
    static AtomicFile file(android.content.Context context,String db)throws Exception{
        byte[] hash=MessageDigest.getInstance("SHA-256").digest(db.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        StringBuilder name=new StringBuilder();for(byte b:hash)name.append(String.format("%02x",b&255));
        // KeePassDX recursively clears noBackupFilesDir as its attachment cache.
        // FIDO2 backup rules explicitly exclude this persistent file directory.
        File directory=new File(context.getFilesDir(),"fido2-v1");
        if(!directory.isDirectory()&&!directory.mkdirs())throw new IOException("Cannot create private enrollment storage");
        return new AtomicFile(new File(directory,name+".cbor"));
    }
}
