package com.kunzisoft.keepass.fido2;

import android.app.Application;
import android.content.Context;
import android.util.AtomicFile;
import androidx.test.core.app.ApplicationProvider;
import com.kunzisoft.keepass.database.element.Database;
import com.kunzisoft.keepass.utils.UriHelperKt;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(sdk=33, application=Application.class)
public class EnrollmentStorageTest {
    @Test public void enrollmentIsExplicitlyExcludedFromAllBackupModes() throws Exception {
        Context context=ApplicationProvider.getApplicationContext();
        java.util.Set<String> modes=new java.util.HashSet<>();
        for(int resource:new int[]{com.kunzisoft.keepass.R.xml.backup_rules,com.kunzisoft.keepass.R.xml.old_backup_rules}){
            try(android.content.res.XmlResourceParser xml=context.getResources().getXml(resource)){
                String mode="";
                for(int event=xml.next();event!=org.xmlpull.v1.XmlPullParser.END_DOCUMENT;event=xml.next()){
                    if(event!=org.xmlpull.v1.XmlPullParser.START_TAG)continue;
                    String name=xml.getName();
                    assertFalse("Exclusion-only policy must not mix includes",name.equals("include"));
                    if(name.equals("cloud-backup")||name.equals("device-transfer")||name.equals("full-backup-content"))mode=name;
                    if(name.equals("exclude")&&"file".equals(xml.getAttributeValue(null,"domain"))&&".".equals(xml.getAttributeValue(null,"path")))modes.add(mode);
                }
            }
        }
        assertEquals(new java.util.HashSet<>(java.util.Arrays.asList("cloud-backup","device-transfer","full-backup-content")),modes);
    }
    @Test public void encryptedEnrollmentSurvivesDatabaseCloseAndReopen() throws Exception {
        Context context=ApplicationProvider.getApplicationContext();
        String uri="content://synthetic/test.kdbx";
        byte[] secret=Crypto.random(32);
        char[] password="Synthetic storage regression".toCharArray();
        java.security.KeyPairGenerator gen=java.security.KeyPairGenerator.getInstance("EC");
        gen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        FidoToken.Credential credential=new FidoToken.Credential(Crypto.random(32),gen.generateKeyPair().getPublic().getEncoded());
        UnlockRecord record=UnlockRecord.seal(uri,credential,Crypto.random(32),secret,password);
        AtomicFile stored=EnrollmentStorage.file(context,uri);
        try(FileOutputStream stream=stored.startWrite()){stream.write(record.encode());stored.finishWrite(stream);}
        assertArrayEquals(password,UnlockRecord.decode(uri,stored.readFully()).open(secret));
        File attachment=new File(UriHelperKt.getBinaryDir(context),"temporary-attachment");
        Files.write(attachment.toPath(),new byte[]{1,2,3});
        File legacy=new File(context.getNoBackupFilesDir(),"fido2-v1/old.cbor");
        assertTrue(legacy.getParentFile().mkdirs() || legacy.getParentFile().isDirectory());
        Files.write(legacy.toPath(),record.encode());
        // Invoke KeePassDX's actual recursive cleanup, not a simulated deletion.
        new Database().clearAndClose(UriHelperKt.getBinaryDir(context));
        assertFalse("Old enrollment location is deleted by cleanup",legacy.exists());
        assertFalse("Temporary attachments must still be removed",attachment.exists());
        assertTrue("Enrollment must survive database lock",stored.getBaseFile().exists());
        AtomicFile reopened=EnrollmentStorage.file(context,uri);
        assertArrayEquals(password,UnlockRecord.decode(uri,reopened.readFully()).open(secret));
        assertFalse(EnrollmentStorage.file(context,"content://synthetic/other.kdbx").getBaseFile().exists());
        reopened.delete();
    }
}
