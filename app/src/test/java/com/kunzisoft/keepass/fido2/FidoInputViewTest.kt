package com.kunzisoft.keepass.fido2

import android.app.Application
import android.content.Context
import android.view.ContextThemeWrapper
import android.view.View
import android.widget.EditText
import androidx.test.core.app.ApplicationProvider
import com.google.android.material.textfield.TextInputLayout
import com.kunzisoft.keepass.R
import com.kunzisoft.keepass.hardware.HardwareKey
import com.kunzisoft.keepass.view.MainCredentialView
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], application = Application::class)
class FidoInputViewTest {
    private fun view(): MainCredentialView {
        val context = ContextThemeWrapper(ApplicationProvider.getApplicationContext<Context>(), R.style.KeepassDXStyle_Light)
        return MainCredentialView(context).apply { configureFido2Input() }
    }
    @Test fun pinCannotBecomeDatabasePasswordOrStoredBiometricCredential() {
        val view = view()
        val edit = view.findViewById<EditText>(R.id.password_text_view)
        view.populatePasswordTextView("Synthetic master".toCharArray())
        view.setTokenPinMode(true)
        assertEquals("", edit.text.toString())
        assertEquals("Token PIN", view.findViewById<TextInputLayout>(R.id.password_input_layout).hint.toString())
        edit.setText("123456")
        assertTrue(view.isFill())
        assertNull(view.getMainCredential().password)
        assertFalse(view.conditionToStoreCredential())
        val failListener = object : MainCredentialView.CredentialStorageListener {
            override fun passwordToStore(password: CharArray?): ByteArray? = error("PIN reached password storage")
            override fun keyfileToStore(keyfile: android.net.Uri?): ByteArray? = error("PIN reached keyfile storage")
            override fun hardwareKeyToStore(): ByteArray? = error("PIN reached hardware storage")
        }
        assertNull(view.retrieveCredentialForStorage(failListener))
        assertArrayEquals("123456".toCharArray(), view.takeTokenPin())
        assertEquals("", edit.text.toString())
        assertFalse(edit.isSaveEnabled)
        assertFalse(edit.isSaveFromParentEnabled)
    }
    @Test fun recoverySwitchClearsPinAndRestoresMasterPasswordMeaning() {
        val view = view()
        val edit = view.findViewById<EditText>(R.id.password_text_view)
        view.setTokenPinMode(true)
        edit.setText("123456")
        view.setTokenPinMode(false)
        assertEquals("", edit.text.toString())
        assertEquals("Master Password", view.findViewById<TextInputLayout>(R.id.password_input_layout).hint.toString())
        view.populatePasswordTextView("Synthetic recovery".toCharArray())
        assertArrayEquals("Synthetic recovery".toCharArray(), view.getMainCredential().password)
        assertTrue(view.conditionToStoreCredential())
    }
    @Test fun hardwareFactorRemainsHiddenAndIgnoredAfterRestoration() {
        val view = view()
        view.populateHardwareKeyView(HardwareKey.values().first())
        assertEquals(View.GONE, view.findViewById<View>(R.id.container_hardware_key).visibility)
        assertNull(view.getMainCredential().hardwareKey)
        view.setTokenPinMode(true)
        view.setTokenPinMode(false)
        assertEquals(View.GONE, view.findViewById<View>(R.id.container_hardware_key).visibility)
    }
    @Test fun programmaticMasterPasswordCannotPopulatePinField() {
        val view = view()
        view.setTokenPinMode(true)
        view.populatePasswordTextView("Synthetic external password".toCharArray())
        assertEquals("", view.findViewById<EditText>(R.id.password_text_view).text.toString())
    }
}
