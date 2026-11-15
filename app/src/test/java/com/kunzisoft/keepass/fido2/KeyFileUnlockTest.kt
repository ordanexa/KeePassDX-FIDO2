package com.kunzisoft.keepass.fido2

import android.app.Application
import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import com.kunzisoft.keepass.database.MainCredential
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], application = Application::class)
class KeyFileUnlockTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test fun associationSurvivesRecreationIsIsolatedAndRemovalOverridesHistory() {
        val database = Uri.parse("content://test/first.kdbx")
        val other = Uri.parse("content://test/second.kdbx")
        val file = Uri.parse("content://test/optional.keyx")
        val associations = KeyFileAssociation(context)
        associations.assign(database, file)
        assertEquals(file, KeyFileAssociation(context).resolve(database, null))
        assertNull(associations.resolve(other, null))
        assertEquals(file, associations.resolve(other, file))
        associations.assign(database, null)
        assertNull(KeyFileAssociation(context).resolve(database, file))
        assertNull(associations.resolve(null, file))
    }

    private fun composite(password: CharArray, uri: Uri?): ByteArray {
        val credential = MainCredential(password, uri).toMasterCredential(context.contentResolver)
        return try { credential.toMasterKey(Charsets.UTF_8, null) { _, _ -> error("No hardware key factor") } }
        finally { credential.clear() }
    }

    @Test fun recoveredPasswordAndManualPasswordUseSameOptionalFileFactor() {
        val file = File(context.cacheDir, "synthetic.key").apply { writeBytes(ByteArray(32) { it.toByte() }) }
        val password = "Synthetic unit-test password".toCharArray()
        val secret = ByteArray(32) { (it + 11).toByte() }
        val credential = FidoToken.Credential(byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6))
        val sealed = UnlockRecord.seal("content://test/database", credential, ByteArray(32), secret, password)
        val recovered = sealed.open(secret)
        val uri = Uri.fromFile(file)
        val withFile = composite(password, uri)
        assertArrayEquals(withFile, composite(recovered, uri))
        assertArrayEquals(composite(password, null), composite(recovered, null))
        assertFalse(withFile.contentEquals(composite(recovered, null)))
        file.writeBytes(ByteArray(32) { (it + 1).toByte() })
        assertFalse(withFile.contentEquals(composite(recovered, uri)))
        recovered.fill('\u0000'); password.fill('\u0000'); secret.fill(0)
    }

    @Test fun missingAssignedFileFailsInsteadOfFallingBackToPasswordOnly() {
        val file = File(context.cacheDir, "missing.key")
        file.delete()
        try {
            MainCredential("Synthetic".toCharArray(), Uri.fromFile(file)).toMasterCredential(context.contentResolver)
            fail("Missing assigned file must not silently omit the factor")
        } catch (expected: IOException) {
            assertTrue(expected.message!!.contains("Key File nicht verfügbar"))
        }
    }
}
