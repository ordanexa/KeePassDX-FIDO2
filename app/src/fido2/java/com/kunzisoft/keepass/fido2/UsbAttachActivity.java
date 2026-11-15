package com.kunzisoft.keepass.fido2;

import android.app.Activity;
import android.os.Bundle;

/**
 * USB default-handler entry point, deliberately without UI or token I/O.
 * Android grants the selected application's USB permission before launching this
 * activity. Finish immediately; a foreground browser authentication must not be
 * redirected to the database picker or have its token interface claimed here.
 */
public final class UsbAttachActivity extends Activity {
    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        finish();
    }
}
