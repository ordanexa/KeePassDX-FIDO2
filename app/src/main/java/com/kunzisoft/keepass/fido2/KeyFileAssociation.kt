package com.kunzisoft.keepass.fido2

import android.content.Context
import android.net.Uri
import java.security.MessageDigest

/** Only document references, never key file bytes. Explicit removal overrides legacy history. */
class KeyFileAssociation(context: Context) {
    private val preferences = context.getSharedPreferences("fido2_key_files", Context.MODE_PRIVATE)
    private fun key(database: Uri) = MessageDigest.getInstance("SHA-256")
        .digest(database.toString().toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    fun resolve(database: Uri?, fallback: Uri?): Uri? {
        if (database == null) return null
        val name = key(database)
        if (!preferences.contains(name)) return fallback
        return preferences.getString(name, "")?.takeIf { it.isNotEmpty() }?.let(Uri::parse)
    }

    fun assign(database: Uri, keyFile: Uri?) {
        preferences.edit().putString(key(database), keyFile?.toString() ?: "").apply()
    }
}
