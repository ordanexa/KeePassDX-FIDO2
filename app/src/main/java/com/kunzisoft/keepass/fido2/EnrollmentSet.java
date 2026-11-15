package com.kunzisoft.keepass.fido2;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.*;

/** Up to five independent encrypted envelopes. Names are local, non-secret labels. */
final class EnrollmentSet {
    static final int MAX_TOKENS=5, MAX_BYTES=170000;
    static final class Entry {
        final String name;
        final UnlockRecord record;
        Entry(String name,UnlockRecord record)throws IOException {
            this.name=validateName(name);this.record=record;
        }
    }
    final String database;
    final List<Entry> entries;
    EnrollmentSet(String database,List<Entry> entries)throws IOException {
        this.database=database;this.entries=Collections.unmodifiableList(new ArrayList<>(entries));
        if(entries.size()>MAX_TOKENS)throw new IOException("Maximum of 5 tokens reached.");
        for(int i=0;i<entries.size();i++){
            Entry e=entries.get(i);
            if(!database.equals(e.record.database))throw new IOException("Enrollment database mismatch");
            if(!Arrays.equals(entries.get(0).record.salt,e.record.salt))throw new IOException("Enrollment salt mismatch");
            for(int j=0;j<i;j++){
                Entry other=entries.get(j);
                if(other.name.equalsIgnoreCase(e.name))throw new IOException("Choose a different token name.");
                if(MessageDigest.isEqual(other.record.credential.id,e.record.credential.id))throw new IOException("Token already enrolled.");
            }
        }
    }
    static String validateName(String name)throws IOException {
        if(name==null||name.trim().isEmpty()||name.trim().length()>40)throw new IOException("Token name must contain 1–40 characters.");
        String clean=name.trim();
        for(int i=0;i<clean.length();i++)if(Character.isISOControl(clean.charAt(i)))throw new IOException("Invalid token name.");
        return clean;
    }
    void checkAddition(String name)throws IOException {
        if(entries.size()>=MAX_TOKENS)throw new IOException("Maximum of 5 tokens reached. Remove one first.");
        String clean=validateName(name);
        for(Entry e:entries)if(e.name.equalsIgnoreCase(clean))throw new IOException("Choose a different token name.");
    }
    EnrollmentSet add(String name,UnlockRecord record)throws IOException {
        checkAddition(name);List<Entry> all=new ArrayList<>(entries);all.add(new Entry(name,record));return new EnrollmentSet(database,all);
    }
    EnrollmentSet remove(byte[] id)throws IOException {
        List<Entry> remaining=new ArrayList<>(entries);
        if(!remaining.removeIf(e->MessageDigest.isEqual(e.record.credential.id,id)))throw new IOException("Enrollment changed; reopen the token list.");
        return new EnrollmentSet(database,remaining);
    }
    List<FidoToken.Credential> credentials(){
        List<FidoToken.Credential> result=new ArrayList<>();for(Entry e:entries)result.add(e.record.credential);return result;
    }
    Entry find(byte[] id)throws IOException {
        for(Entry e:entries)if(MessageDigest.isEqual(e.record.credential.id,id))return e;
        throw new IOException("Unexpected credential");
    }
    byte[] encode()throws Exception {
        List<Object> all=new ArrayList<>();for(Entry e:entries)all.add(Cbor.map(1,e.name,2,e.record.encode()));
        return Cbor.encode(Cbor.map(1,2,2,database,3,all));
    }
    static EnrollmentSet decode(String db,byte[] bytes)throws Exception {
        if(bytes.length>MAX_BYTES)throw new IOException("Enrollment storage too large");
        Object map=Cbor.decode(bytes);long version=Cbor.number(Cbor.get(map,1));
        if(version==1)return new EnrollmentSet(db,Collections.singletonList(new Entry("Bisheriger Token",UnlockRecord.decode(db,bytes))));
        if(version!=2||!db.equals(Cbor.get(map,2)))throw new IOException("Enrollment does not match this database");
        Object values=Cbor.get(map,3);
        if(!(values instanceof List)||((List<?>)values).size()>MAX_TOKENS)throw new IOException("Invalid token list");
        List<Entry> all=new ArrayList<>();
        for(Object v:(List<?>)values){
            Object name=Cbor.get(v,1);if(!(name instanceof String))throw new IOException("Invalid token name");
            all.add(new Entry((String)name,UnlockRecord.decode(db,Cbor.bytes(Cbor.get(v,2)))));
        }
        return new EnrollmentSet(db,all);
    }
}
