package com.kunzisoft.keepass.fido2;

import android.app.Application;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.hardware.usb.UsbManager;
import android.util.TypedValue;
import androidx.test.core.app.ApplicationProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.Shadows;
import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(sdk=33, application=Application.class)
public class UsbAttachActivityTest {
    @Test public void attachmentFinishesWithoutLaunchingUiOrService() {
        try (var controller=Robolectric.buildActivity(UsbAttachActivity.class,
                new Intent(UsbManager.ACTION_USB_DEVICE_ATTACHED)).create()) {
            UsbAttachActivity activity=controller.get();
            assertTrue(activity.isFinishing());
            assertNull(Shadows.shadowOf(activity).getNextStartedActivity());
            Application app=ApplicationProvider.getApplicationContext();
            assertNull(Shadows.shadowOf(app).getNextStartedService());
            TypedValue value=new TypedValue();
            assertTrue(activity.getTheme().resolveAttribute(android.R.attr.windowNoDisplay,value,true));
            assertNotEquals(0,value.data);
        }
    }
    @Test public void arbitraryExternalIntentAlsoFinishesWithoutRouting() {
        try (var controller=Robolectric.buildActivity(UsbAttachActivity.class,
                new Intent(Intent.ACTION_VIEW,android.net.Uri.parse("content://test/private.kdbx"))).create()) {
            assertTrue(controller.get().isFinishing());
            assertNull(Shadows.shadowOf(controller.get()).getNextStartedActivity());
        }
    }
    @Test public void handlerUsesSeparateTaskAndOnlyTheSupportedUsbModel() throws Exception {
        Context context=ApplicationProvider.getApplicationContext();
        ActivityInfo info=context.getPackageManager().getActivityInfo(
                new ComponentName(context,UsbAttachActivity.class),PackageManager.GET_META_DATA);
        assertTrue(info.exported);
        assertEquals(context.getPackageName()+".usb.attach",info.taskAffinity);
        assertNotEquals(0,info.flags&ActivityInfo.FLAG_NO_HISTORY);
        assertNotEquals(0,info.flags&ActivityInfo.FLAG_EXCLUDE_FROM_RECENTS);
        int resource=info.metaData.getInt(UsbManager.ACTION_USB_DEVICE_ATTACHED);
        assertNotEquals(0,resource);
        int devices=0;
        try(var xml=context.getResources().getXml(resource)) {
            for(int event=xml.next();event!=org.xmlpull.v1.XmlPullParser.END_DOCUMENT;event=xml.next()) {
                if(event==org.xmlpull.v1.XmlPullParser.START_TAG&&xml.getName().equals("usb-device")) {
                    devices++;
                    assertEquals(0x349e,xml.getAttributeIntValue(null,"vendor-id",-1));
                    assertEquals(0x0024,xml.getAttributeIntValue(null,"product-id",-1));
                }
            }
        }
        assertEquals(1,devices);
    }
}
