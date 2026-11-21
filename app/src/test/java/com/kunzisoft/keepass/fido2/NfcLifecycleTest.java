package com.kunzisoft.keepass.fido2;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.nfc.NfcAdapter;
import android.os.Looper;
import androidx.test.core.app.ApplicationProvider;
import java.lang.reflect.Field;
import java.time.Duration;
import org.junit.*;
import org.junit.runner.RunWith;
import org.robolectric.*;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowNfcAdapter;
import static org.junit.Assert.*;
import static org.robolectric.Shadows.shadowOf;

@RunWith(RobolectricTestRunner.class)
@Config(sdk=33,application=Application.class)
public class NfcLifecycleTest {
    private Context context;
    private Activity activity;
    private FidoUnlock unlock;
    private ShadowNfcAdapter adapter;
    private final String database="content://synthetic/nfc-lifecycle.kdbx";
    private static Object field(Object object,String name)throws Exception {
        Field field=object.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(object);
    }
    @Before public void setup()throws Exception {
        context=ApplicationProvider.getApplicationContext();
        shadowOf(context.getPackageManager()).setSystemFeature(PackageManager.FEATURE_NFC,true);
        ShadowNfcAdapter.setNfcHardwareExists(true);
        activity=Robolectric.buildActivity(Activity.class).setup().get();
        adapter=shadowOf(NfcAdapter.getDefaultAdapter(activity));adapter.setEnabled(true);
        unlock=new FidoUnlock(activity,(password,keyFile)->fail("No real NFC tag was presented"));
        EnrollmentSet empty=EnrollmentStorage.read(context,database);
        UnlockRecord record=UnlockRecord.seal(database,new FidoToken.Credential(new byte[]{1},new byte[]{1}),new byte[32],new byte[32],"Synthetic password".toCharArray());
        EnrollmentStorage.replace(context,empty,empty.add("Daily",record));
    }
    @After public void cleanup()throws Exception {unlock.close();activity.finish();EnrollmentStorage.file(context,database).delete();}
    private void awaitTag(){unlock.beginWithPin(Uri.parse(database),"123456".toCharArray(),null);}
    @Test public void scanIsOptInAndPauseDisablesReaderAndWipesPendingPin()throws Exception {
        assertFalse(adapter.isInReaderMode());assertTrue(unlock.selectNfc(true));assertFalse(adapter.isInReaderMode());
        awaitTag();assertTrue(adapter.isInReaderMode());byte[] pending=(byte[])field(unlock,"pendingPin");
        assertArrayEquals(Crypto.utf8("123456"),pending);
        unlock.pauseNfc();assertFalse(adapter.isInReaderMode());assertArrayEquals(new byte[pending.length],pending);
        assertNull(field(unlock,"pendingPin"));assertEquals(false,field(unlock,"busy"));
    }
    @Test public void delayedTagAfterCancellationCannotResumeUnlock()throws Exception {
        unlock.selectNfc(true);awaitTag();
        NfcAdapter.ReaderCallback callback=(NfcAdapter.ReaderCallback)field(adapter,"readerCallback");
        unlock.cancel();callback.onTagDiscovered(ShadowNfcAdapter.createMockTag());
        shadowOf(Looper.getMainLooper()).idle();
        assertFalse(adapter.isInReaderMode());assertEquals(false,field(unlock,"busy"));assertNull(field(unlock,"pendingPin"));
    }
    @Test public void timeoutStopsScanningAndDiscardsThePin()throws Exception {
        unlock.selectNfc(true);awaitTag();byte[] pending=(byte[])field(unlock,"pendingPin");
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofSeconds(61));
        assertFalse(adapter.isInReaderMode());assertArrayEquals(new byte[pending.length],pending);assertNull(field(unlock,"pendingPin"));
    }
    @Test public void disabledNfcDoesNotChangeUsbModeOrBeginScanning() {
        adapter.setEnabled(false);assertFalse(unlock.selectNfc(true));assertFalse(unlock.isNfcMode());assertFalse(adapter.isInReaderMode());
    }
}
