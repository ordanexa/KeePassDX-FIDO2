package com.kunzisoft.keepass.fido2;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.net.Uri;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import androidx.test.core.app.ApplicationProvider;
import java.lang.reflect.Field;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(sdk=33,application=Application.class)
public class BiometricPinTest {
    private UnlockRecord record(String database,int id)throws Exception {
        return UnlockRecord.seal(database,new FidoToken.Credential(new byte[]{(byte)id},new byte[]{1}),
                new byte[32],new byte[32],"Synthetic password".toCharArray());
    }
    @Test public void encryptionRequiresFreshStrongBiometricAndInvalidatesOnEnrollmentChange() {
        KeyGenParameterSpec spec=BiometricPin.keySpec("synthetic");
        assertTrue(spec.isUserAuthenticationRequired());
        assertEquals(0,spec.getUserAuthenticationValidityDurationSeconds());
        assertEquals(KeyProperties.AUTH_BIOMETRIC_STRONG,spec.getUserAuthenticationType());
        assertTrue(spec.isInvalidatedByBiometricEnrollment());
        assertArrayEquals(new String[]{KeyProperties.BLOCK_MODE_GCM},spec.getBlockModes());
        assertEquals(256,spec.getKeySize());
    }
    @Test public void savedPinCannotFollowAnotherDatabaseTokenOrReenrollment()throws Exception {
        UnlockRecord first=record("content://test/one",1);
        assertEquals(BiometricPin.binding(first),BiometricPin.binding(UnlockRecord.decode(first.database,first.encode())));
        assertNotEquals(BiometricPin.binding(first),BiometricPin.binding(record("content://test/two",1)));
        assertNotEquals(BiometricPin.binding(first),BiometricPin.binding(record(first.database,2)));
        assertNotEquals(BiometricPin.binding(first),BiometricPin.binding(record(first.database,1)));
    }
    @Test public void cancelWipesThePendingPinAndDropsOwnership()throws Exception {
        Activity activity=Robolectric.buildActivity(Activity.class).setup().get();
        BiometricPin store=new BiometricPin(activity);
        Field field=BiometricPin.class.getDeclaredField("pending");field.setAccessible(true);
        byte[] pin=new byte[]{4,3,2,1};field.set(store,pin);
        store.cancel();assertArrayEquals(new byte[4],pin);assertNull(field.get(store));
        activity.finish();
    }
    @Test public void savedPinWithoutUsbTokenCannotOpenDatabaseOrBeginBiometricOperation()throws Exception {
        Context context=ApplicationProvider.getApplicationContext();
        String database="content://test/biometric-no-token";
        UnlockRecord record=record(database,1);
        EnrollmentSet empty=EnrollmentStorage.read(context,database);
        EnrollmentStorage.replace(context,empty,empty.add("Daily",record));
        context.getSharedPreferences("fido2_biometric_pins",Context.MODE_PRIVATE).edit()
                .putString(BiometricPin.binding(record),"synthetic encrypted envelope").commit();
        Activity activity=Robolectric.buildActivity(Activity.class).setup().get();
        FidoUnlock unlock=new FidoUnlock(activity,(password,keyFile)->fail("Token must be required"));
        try {
            unlock.beginFingerprint(Uri.parse(database),null);
            Field busy=FidoUnlock.class.getDeclaredField("busy");busy.setAccessible(true);assertFalse(busy.getBoolean(unlock));
            Field waiting=FidoUnlock.class.getDeclaredField("waitingDatabase");waiting.setAccessible(true);assertFalse(waiting.getBoolean(unlock));
            assertArrayEquals(record.encode(),EnrollmentStorage.read(context,database).entries.get(0).record.encode());
        } finally { unlock.close();activity.finish();EnrollmentStorage.file(context,database).delete(); }
    }
}
