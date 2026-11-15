package com.kunzisoft.keepass.fido2;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.net.Uri;
import android.util.AtomicFile;
import androidx.test.core.app.ApplicationProvider;
import java.io.*;
import java.lang.reflect.Field;
import java.util.*;
import org.junit.*;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(sdk=33,application=Application.class)
public class EnrollmentSetTest {
    private final Context context=ApplicationProvider.getApplicationContext();
    private final String db="content://test/multiple-tokens.kdbx";
    private final byte[] salt=new byte[32];
    private final char[] password="Synthetic database password".toCharArray();
    private UnlockRecord record(int id)throws Exception {
        byte[] secret=new byte[32];Arrays.fill(secret,(byte)id);
        return UnlockRecord.seal(db,new FidoToken.Credential(new byte[]{(byte)id},new byte[]{1}),salt.clone(),secret,password);
    }
    private void write(byte[] bytes)throws Exception {
        AtomicFile f=EnrollmentStorage.file(context,db);FileOutputStream out=f.startWrite();out.write(bytes);f.finishWrite(out);
    }
    @After public void cleanup()throws Exception{EnrollmentStorage.file(context,db).delete();}
    @Test public void legacyReadDoesNotWriteAndAdditionPreservesOldEnvelope()throws Exception {
        UnlockRecord old=record(1);byte[] legacy=old.encode();write(legacy);
        EnrollmentSet loaded=EnrollmentStorage.read(context,db);
        assertEquals("Bisheriger Token",loaded.entries.get(0).name);
        assertArrayEquals(legacy,EnrollmentStorage.file(context,db).readFully());
        EnrollmentStorage.replace(context,loaded,loaded.add("Backup",record(2)));
        EnrollmentSet reopened=EnrollmentStorage.read(context,db);
        assertEquals(2,reopened.entries.size());assertArrayEquals(legacy,reopened.entries.get(0).record.encode());
        for(int i=1;i<=2;i++){byte[] secret=new byte[32];Arrays.fill(secret,(byte)i);assertArrayEquals(password,reopened.entries.get(i-1).record.open(secret));}
    }
    @Test public void fiveIndependentTokensAndIndividualRemoval()throws Exception {
        EnrollmentSet set=EnrollmentStorage.read(context,db);
        for(int i=1;i<=5;i++)set=set.add("Token "+i,record(i));
        final EnrollmentSet full=set;
        assertThrows(IOException.class,()->full.add("Sixth",record(6)));
        EnrollmentStorage.replace(context,EnrollmentStorage.read(context,db),set);
        EnrollmentSet reduced=set.remove(new byte[]{3});EnrollmentStorage.replace(context,set,reduced);
        EnrollmentSet read=EnrollmentStorage.read(context,db);assertEquals(4,read.entries.size());
        assertThrows(IOException.class,()->read.find(new byte[]{3}));
        for(int id:new int[]{1,2,4,5}){byte[] secret=new byte[32];Arrays.fill(secret,(byte)id);assertArrayEquals(password,read.find(new byte[]{(byte)id}).record.open(secret));}
    }
    @Test public void duplicateCredentialNamesWrongDatabaseAndSaltRejected()throws Exception {
        EnrollmentSet one=new EnrollmentSet(db,Collections.emptyList()).add("Daily",record(1));
        assertThrows(IOException.class,()->one.add("Other name",record(1)));
        assertThrows(IOException.class,()->one.add(" daily ",record(2)));
        assertThrows(IOException.class,()->one.add("  ",record(2)));
        assertThrows(IOException.class,()->EnrollmentSet.decode("content://wrong",one.encode()));
        UnlockRecord altered=record(2);altered.salt[0]=1;
        assertThrows(IOException.class,()->one.add("Backup",altered));
    }
    @Test public void staleWriterCannotResurrectRemovedTokenOrLoseNewToken()throws Exception {
        EnrollmentSet empty=EnrollmentStorage.read(context,db),one=empty.add("Daily",record(1));
        EnrollmentStorage.replace(context,empty,one);
        assertThrows(IOException.class,()->EnrollmentStorage.replace(context,empty,empty.add("Backup",record(2))));
        EnrollmentSet none=one.remove(new byte[]{1});EnrollmentStorage.replace(context,one,none);
        assertThrows(IOException.class,()->EnrollmentStorage.replace(context,one,one.add("Backup",record(2))));
        assertTrue(EnrollmentStorage.read(context,db).entries.isEmpty());
    }
    @Test public void malformedOrUnsupportedStorageNeverBecomesEmptyEnrollment()throws Exception {
        for(byte[] bytes:new byte[][]{new byte[]{1,2},Cbor.encode(Cbor.map(1,99,2,db)),new byte[EnrollmentSet.MAX_BYTES+1]}){
            write(bytes);assertThrows(Exception.class,()->EnrollmentStorage.read(context,db));
            assertArrayEquals(bytes,EnrollmentStorage.file(context,db).readFully());
        }
    }
    private static void field(Object object,String name,Object value)throws Exception {
        Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);f.set(object,value);
    }
    private FidoUnlock pending(Activity activity,EnrollmentSet initial)throws Exception {
        FidoUnlock f=new FidoUnlock(activity,(p,k)->fail("No USB operation expected"));
        byte[] proofKey=new byte[32];
        field(f,"database",db);field(f,"snapshot",initial);field(f,"tokenName","Backup");
        field(f,"pending",record(2));field(f,"waitingDatabase",true);field(f,"busy",true);
        field(f,"proofKey",proofKey);field(f,"passwordProof",Crypto.hmac(proofKey,UnlockRecord.encodeChars(password)));
        return f;
    }
    @Test public void databaseSuccessCommitsAdditionButFailureMismatchAndCancelDoNot()throws Exception {
        Activity activity=Robolectric.buildActivity(Activity.class).setup().get();
        EnrollmentSet empty=EnrollmentStorage.read(context,db),one=empty.add("Daily",record(1));
        EnrollmentStorage.replace(context,empty,one);byte[] original=EnrollmentStorage.file(context,db).readFully();
        FidoUnlock f=pending(activity,one);
        f.databaseResult(Uri.parse(db),password,null,false);f.close();
        assertArrayEquals(original,EnrollmentStorage.file(context,db).readFully());
        f=pending(activity,one);f.databaseResult(Uri.parse(db),"wrong".toCharArray(),null,true);f.close();
        assertArrayEquals(original,EnrollmentStorage.file(context,db).readFully());
        f=pending(activity,one);field(f,"keyFile",Uri.parse("content://required.keyx"));
        f.databaseResult(Uri.parse(db),password,null,true);f.close();
        assertArrayEquals(original,EnrollmentStorage.file(context,db).readFully());
        f=pending(activity,one);f.cancel();f.databaseResult(Uri.parse(db),password,null,true);f.close();
        assertArrayEquals(original,EnrollmentStorage.file(context,db).readFully());
        f=pending(activity,one);f.databaseResult(Uri.parse(db),password,null,true);f.close();
        assertEquals(2,EnrollmentStorage.read(context,db).entries.size());activity.finish();
    }
}
