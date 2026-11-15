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
    static synchronized EnrollmentSet read(android.content.Context context,String db)throws Exception{
        try(InputStream in=file(context,db).openRead();ByteArrayOutputStream out=new ByteArrayOutputStream()){
            byte[] buffer=new byte[4096];int count;
            while((count=in.read(buffer))!=-1){
                if(out.size()+count>EnrollmentSet.MAX_BYTES)throw new IOException("Enrollment storage too large");
                out.write(buffer,0,count);
            }
            return EnrollmentSet.decode(db,out.toByteArray());
        }catch(FileNotFoundException missing){
            File base=file(context,db).getBaseFile();
            if(base.exists()||new File(base.getPath()+".bak").exists())throw missing;
            return new EnrollmentSet(db,java.util.Collections.emptyList());
        }
    }
    /** Compare-and-write prevents stale activities or late callbacks from replacing a newer set. */
    static synchronized void replace(android.content.Context context,EnrollmentSet expected,EnrollmentSet next)throws Exception{
        if(!expected.database.equals(next.database)||!MessageDigest.isEqual(read(context,expected.database).encode(),expected.encode()))
            throw new IOException("Enrollment changed. Please try again.");
        byte[] encoded=next.encode();EnrollmentSet.decode(next.database,encoded);
        AtomicFile storage=file(context,next.database);FileOutputStream stream=null;
        try{stream=storage.startWrite();stream.write(encoded);storage.finishWrite(stream);}
        catch(Exception e){if(stream!=null)storage.failWrite(stream);throw e;}
        if(!MessageDigest.isEqual(read(context,next.database).encode(),encoded))throw new IOException("Enrollment write verification failed");
    }
}
