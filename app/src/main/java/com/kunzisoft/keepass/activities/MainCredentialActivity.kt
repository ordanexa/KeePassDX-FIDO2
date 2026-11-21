/*
 * Copyright 2019 Jeremy Jamet / Kunzisoft.
 *
 * This file is part of KeePassDX.
 *
 *  KeePassDX is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  KeePassDX is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with KeePassDX.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package com.kunzisoft.keepass.activities

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.widget.Toolbar
import androidx.biometric.BiometricManager
import androidx.coordinatorlayout.widget.CoordinatorLayout
import androidx.core.view.isVisible
import androidx.fragment.app.commit
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.snackbar.Snackbar
import com.kunzisoft.keepass.R
import com.kunzisoft.keepass.activities.helpers.ExternalFileHelper
import com.kunzisoft.keepass.activities.helpers.ExternalFileHelper.registerOpenFile
import com.kunzisoft.keepass.activities.helpers.ExternalFileHelper.setOpenFileClickListener
import com.kunzisoft.keepass.activities.legacy.DatabaseModeActivity
import com.kunzisoft.keepass.app.database.FileDatabaseHistoryAction
import com.kunzisoft.keepass.biometric.DeviceUnlockFragment
import com.kunzisoft.keepass.biometric.DeviceUnlockManager
import com.kunzisoft.keepass.biometric.deviceUnlockError
import com.kunzisoft.keepass.credentialprovider.EntrySelectionHelper
import com.kunzisoft.keepass.credentialprovider.SpecialMode
import com.kunzisoft.keepass.credentialprovider.TypeMode
import com.kunzisoft.keepass.database.ContextualDatabase
import com.kunzisoft.keepass.database.MainCredential
import com.kunzisoft.keepass.database.element.Database.Companion.DEFAULT_PASSWORD_ENCODING
import com.kunzisoft.keepass.database.exception.DuplicateUuidDatabaseException
import com.kunzisoft.keepass.database.exception.FileNotFoundDatabaseException
import com.kunzisoft.keepass.education.PasswordActivityEducation
import com.kunzisoft.keepass.hardware.HardwareKey
import com.kunzisoft.keepass.model.CipherDecryptDatabase
import com.kunzisoft.keepass.model.CipherEncryptDatabase
import com.kunzisoft.keepass.model.CredentialStorage
import com.kunzisoft.keepass.model.DatabaseFile
import com.kunzisoft.keepass.model.RegisterInfo
import com.kunzisoft.keepass.model.SearchInfo
import com.kunzisoft.keepass.services.DatabaseTaskNotificationService.Companion.ACTION_DATABASE_LOAD_TASK
import com.kunzisoft.keepass.services.DatabaseTaskNotificationService.Companion.CIPHER_DATABASE_KEY
import com.kunzisoft.keepass.services.DatabaseTaskNotificationService.Companion.DATABASE_URI_KEY
import com.kunzisoft.keepass.services.DatabaseTaskNotificationService.Companion.MAIN_CREDENTIAL_KEY
import com.kunzisoft.keepass.services.DatabaseTaskNotificationService.Companion.READ_ONLY_KEY
import com.kunzisoft.keepass.services.DatabaseTaskNotificationService.Companion.USER_VERIFICATION_KEY
import com.kunzisoft.keepass.settings.AppearanceSettingsActivity
import com.kunzisoft.keepass.settings.DeviceUnlockSettingsActivity
import com.kunzisoft.keepass.settings.PreferencesUtil
import com.kunzisoft.keepass.tasks.ActionRunnable
import com.kunzisoft.keepass.utils.BACK_PREVIOUS_KEYBOARD_ACTION
import com.kunzisoft.keepass.utils.MenuUtil
import com.kunzisoft.keepass.utils.UriUtil.getUri
import com.kunzisoft.keepass.utils.getParcelableCompat
import com.kunzisoft.keepass.utils.getParcelableExtraCompat
import com.kunzisoft.keepass.view.MainCredentialView
import com.kunzisoft.keepass.view.asError
import com.kunzisoft.keepass.viewmodels.DeviceUnlockViewModel
import com.kunzisoft.keepass.viewmodels.MainCredentialViewModel
import kotlinx.coroutines.launch
import java.io.FileNotFoundException
import java.nio.ByteBuffer
import java.nio.CharBuffer


class MainCredentialActivity : DatabaseModeActivity() {

    private var fidoUnlock: com.kunzisoft.keepass.fido2.FidoUnlock? = null

    private val keyFileAssociations by lazy { com.kunzisoft.keepass.fido2.KeyFileAssociation(this) }
    private var keyFilePickerDatabase: Uri? = null

    private var enrollmentDialog: AlertDialog? = null
    private var masterPasswordOverride = false
    private var lastTokenConnected = false
    private val tokenMonitorHandler = Handler(Looper.getMainLooper())
    private val tokenMonitor = object : Runnable {
        override fun run() {
            refreshFidoInputMode()
            tokenMonitorHandler.postDelayed(this, 750)
        }
    }

    private fun refreshFidoInputMode(): Boolean {
        val fido = fidoUnlock ?: return false
        val connected = fido.hasConnectedToken()
        if (connected != lastTokenConnected) {
            masterPasswordOverride = false
            lastTokenConnected = connected
            fido.cancel()
        }
        val pinMode = (connected || fido.isNfcMode) && !masterPasswordOverride
        val changed = pinMode != mainCredentialView.isTokenPinMode
        mainCredentialView.setTokenPinMode(pinMode)
        deviceUnlockButton?.isVisible = false
        fidoFingerprintButton?.isVisible = pinMode
        if (changed) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (pinMode) mDeviceUnlockViewModel?.disconnect()
                else mDeviceUnlockViewModel?.connect(mMainCredentialViewModel.databaseFileUri)
            }
            invalidateOptionsMenu()
        }
        return changed
    }

    override fun onSaveInstanceState(outState: Bundle) {
        keyFilePickerDatabase?.let { outState.putString("fidoKeyFilePickerDatabase", it.toString()) }
        outState.putBoolean("fidoNfcMode", fidoUnlock?.isNfcMode == true)
        super.onSaveInstanceState(outState)
    }

    override fun onStart() {
        super.onStart()
        if (fidoUnlock != null) tokenMonitorHandler.post(tokenMonitor)
    }

    // Views
    private var toolbar: Toolbar? = null
    private var filenameView: TextView? = null
    private var logotypeButton: View? = null
    private var deviceUnlockButton: View? = null
    private var fidoFingerprintButton: View? = null
    private lateinit var mainCredentialView: MainCredentialView
    private var confirmButtonView: Button? = null
    private var infoContainerView: ViewGroup? = null
    private lateinit var coordinatorLayout: CoordinatorLayout
    private var deviceUnlockFragment: DeviceUnlockFragment? = null

    private val mMainCredentialViewModel: MainCredentialViewModel by viewModels()
    private val mDeviceUnlockViewModel: DeviceUnlockViewModel? by lazy {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && com.kunzisoft.keepass.BuildConfig.BUILD_VERSION != "fido2") {
            ViewModelProvider(this)[DeviceUnlockViewModel::class.java]
        } else null
    }

    private val mPasswordActivityEducation = PasswordActivityEducation(this)

    // Manage keyfile selection
    private var openFileResultLauncher: ExternalFileHelper.OpenFileResultLauncher = registerOpenFile { uri ->
        uri?.let {
            if (fidoUnlock != null) {
                val database = keyFilePickerDatabase
                keyFilePickerDatabase = null
                if (database != null && database == mMainCredentialViewModel.databaseFileUri) {
                    fidoUnlock?.cancel()
                    keyFileAssociations.assign(database, uri)
                    mainCredentialView.populateKeyFileView(uri)
                    invalidateOptionsMenu()
                }
            } else mainCredentialView.populateKeyFileView(uri)
        }
    }

    override fun manageDatabaseInfo(): Boolean  = false

    override fun errorCoordinatorView(): View = coordinatorLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        keyFilePickerDatabase = savedInstanceState?.getString("fidoKeyFilePickerDatabase")?.let(Uri::parse)

        setContentView(R.layout.activity_main_credential)

        toolbar = findViewById(R.id.toolbar)
        toolbar?.title = getString(R.string.app_name)
        setSupportActionBar(toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.setDisplayShowHomeEnabled(true)

        filenameView = findViewById(R.id.filename)
        logotypeButton = findViewById(R.id.activity_password_logotype)
        deviceUnlockButton = findViewById(R.id.fragment_device_unlock_container_view)
        fidoFingerprintButton = findViewById(R.id.fido_fingerprint_button)
        fidoFingerprintButton?.setOnClickListener {
            mainCredentialView.populatePasswordTextView(null)
            fidoUnlock?.beginFingerprint(mMainCredentialViewModel.databaseFileUri, mainCredentialView.selectedKeyFile())
        }
        mainCredentialView = findViewById(R.id.activity_password_credentials)
        confirmButtonView = findViewById(R.id.activity_password_open_button)
        infoContainerView = findViewById(R.id.activity_password_info_container)
        coordinatorLayout = findViewById(R.id.activity_password_coordinator_layout)

        if (com.kunzisoft.keepass.BuildConfig.BUILD_VERSION == "fido2" && Build.VERSION.SDK_INT >= 33) {
            mainCredentialView.configureFido2Input()
            window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
            fidoUnlock = com.kunzisoft.keepass.fido2.FidoUnlock(this) { recoveredPassword, selectedKeyFile ->
                mainCredentialView.populatePasswordTextView(null)
                mMainCredentialViewModel.loadDatabase(
                    mainCredential = MainCredential(password = recoveredPassword, keyFileUri = selectedKeyFile),
                    specialMode = mSpecialMode
                )
            }
        }

        if (savedInstanceState?.getBoolean("fidoNfcMode") == true) fidoUnlock?.selectNfc(true)
        refreshFidoInputMode()

        mainCredentialView.keyFileSelectionView.setOpenFileClickListener(this, openFileResultLauncher)

        // If is a view intent
        getUriFromIntent(intent)

        // Show appearance
        logotypeButton?.setOnClickListener {
            startActivity(Intent(this, AppearanceSettingsActivity::class.java))
        }

        // Listen password checkbox to init advanced unlock and confirmation button
        mainCredentialView.onConditionToStoreCredentialChanged = { _, verified ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                mDeviceUnlockViewModel?.checkConditionToStoreCredential(condition = verified)
            }
            mMainCredentialViewModel.onConditionChanged(mainCredentialView.isFill())
        }

        // Encapsulate function to load database
        fun loadDatabase() {
            if (refreshFidoInputMode()) return
            if (mainCredentialView.isTokenPinMode) {
                fidoUnlock?.beginWithPin(mMainCredentialViewModel.databaseFileUri, mainCredentialView.takeTokenPin(), mainCredentialView.selectedKeyFile())
                return
            }
            fidoUnlock?.cancel()
            mMainCredentialViewModel.loadDatabase(
                mainCredential = mainCredentialView.getMainCredential(),
                specialMode = mSpecialMode
            )
        }

        // If Activity is launch with a password and want to open directly
        val intent = intent
        // TODO Change to getCharArrayExtra(KEY_PASSWORD)
        val password = intent.getStringExtra(KEY_PASSWORD)
        // Consume the intent extra password
        intent.removeExtra(KEY_PASSWORD)
        if (password != null) {
            mainCredentialView.populatePasswordTextView(password.toCharArray())
        }
        val launchImmediately = intent.getBooleanExtra(KEY_LAUNCH_IMMEDIATELY, false)
        intent.removeExtra(KEY_LAUNCH_IMMEDIATELY)
        if (launchImmediately) {
            loadDatabase()
        } else {
            // Init Biometric elements
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !mainCredentialView.isTokenPinMode) {
                mDeviceUnlockViewModel?.connect(mMainCredentialViewModel.databaseFileUri)
            }
        }
        // To validate with the keyboard
        mainCredentialView.onValidateListener = {
            loadDatabase()
        }
        // Define listener for validate button
        confirmButtonView?.setOnClickListener {
            loadDatabase()
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    mMainCredentialViewModel.databaseFileUIState.collect { state ->
                        infoContainerView?.isVisible = state.showFileRevokedErrorMessage
                        filenameView?.text = state.fileName
                        if (fidoUnlock != null) {
                            mainCredentialView.populateKeyFileView(keyFileAssociations.resolve(
                                mMainCredentialViewModel.databaseFileUri,
                                mainCredentialView.selectedKeyFile() ?: state.keyFileUri
                            ))
                        } else state.keyFileUri?.let { mainCredentialView.populateKeyFileView(it) }
                        state.hardwareKey?.let {
                            mainCredentialView.populateHardwareKeyView(it)
                        }
                        // Enable or not the open button if setting is checked
                        confirmButtonView?.isEnabled = state.confirmButtonEnabled
                        invalidateOptionsMenu()
                        mainCredentialView.focusPasswordFieldAndOpenKeyboard()
                    }
                }
                launch {
                    mMainCredentialViewModel.databaseFileEvent.collect { event ->
                        when (event) {
                            is MainCredentialViewModel.DatabaseFileEvent.ClearCredentialsView -> {
                                clearCredentialsViews(
                                    clearKeyFile = event.clearKeyFile,
                                    clearHardwareKey = event.clearHardwareKey
                                )
                            }
                            is MainCredentialViewModel.DatabaseFileEvent.LoadDatabase -> {
                                mDatabaseViewModel.loadDatabase(
                                    databaseUri = event.databaseUri,
                                    mainCredential = event.mainCredential,
                                    readOnly = event.readOnly,
                                    allowUserVerification = event.allowUserVerification,
                                    cipherEncryptDatabase = event.cipherEncryptDatabase
                                )
                            }
                            is MainCredentialViewModel.DatabaseFileEvent.OpenGroup -> {
                                clearCredentialsViews(
                                    clearKeyFile = true,
                                    clearHardwareKey = true
                                )
                                GroupActivity.launch(
                                    this@MainCredentialActivity,
                                    event.database,
                                    onValidateSpecialMode = { onValidateSpecialMode() },
                                    onCancelSpecialMode = { onCancelSpecialMode() },
                                    onLaunchActivitySpecialMode = { onLaunchActivitySpecialMode() },
                                    mCredentialActivityResultLauncher
                                )
                            }
                            is MainCredentialViewModel.DatabaseFileEvent.ShowErrorSaveReadOnlyDatabase -> {
                                Snackbar.make(coordinatorLayout,
                                    R.string.error_save_read_only,
                                    Snackbar.LENGTH_LONG).asError().show()
                            }
                            is MainCredentialViewModel.DatabaseFileEvent.ShowLoadDatabaseDuplicateUuidMessage -> {
                                AlertDialog.Builder(this@MainCredentialActivity).apply {
                                    val message = getString(R.string.contains_duplicate_uuid) +
                                            "\n\n" + getString(R.string.contains_duplicate_uuid_procedure)
                                    setMessage(message)
                                    setPositiveButton(getString(android.R.string.ok)) { _, _ ->
                                        event.databaseUri?.let { databaseFileUri ->
                                            mDatabaseViewModel.loadDatabase(
                                                databaseUri = databaseFileUri,
                                                mainCredential = event.mainCredential,
                                                readOnly = event.readOnly,
                                                allowUserVerification = event.allowUserVerification,
                                                cipherEncryptDatabase = event.cipherEncryptDatabase,
                                                fixDuplicateUuid = true,
                                            )
                                        }
                                    }
                                    setNegativeButton(getString(android.R.string.cancel)) { _, _ -> }
                                    create().show()
                                }
                            }
                            is MainCredentialViewModel.DatabaseFileEvent.ShowWarningDatabaseAlreadyOpened -> {
                                Toast.makeText(this@MainCredentialActivity,
                                    R.string.warning_database_already_opened,
                                    Toast.LENGTH_LONG
                                ).show()
                            }
                        }
                    }
                }
                launch {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        mDeviceUnlockViewModel?.let { deviceUnlockViewModel ->
                            deviceUnlockViewModel.uiState.collect { uiState ->
                                // New value received
                                uiState.credentialRequiredCipher?.let { cipher ->
                                    deviceUnlockViewModel.encryptCredential(
                                        credential = getCredentialForEncryption(),
                                        cipher = cipher
                                    )
                                }
                                uiState.cipherEncryptDatabase?.let { cipherEncryptDatabase ->
                                    onCredentialEncrypted(cipherEncryptDatabase)
                                    deviceUnlockViewModel.consumeCredentialEncrypted()
                                }
                                uiState.cipherDecryptDatabase?.let { cipherDecryptDatabase ->
                                    onCredentialDecrypted(cipherDecryptDatabase)
                                    deviceUnlockViewModel.consumeCredentialDecrypted()
                                }
                                uiState.exception?.let { error ->
                                    Snackbar.make(
                                        coordinatorLayout,
                                        deviceUnlockError(error, this@MainCredentialActivity),
                                        Snackbar.LENGTH_LONG
                                    ).asError().show()
                                    deviceUnlockViewModel.exceptionShown()
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshFidoInputMode()

        // Init Biometric elements only if allowed
        if (fidoUnlock == null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
            && PreferencesUtil.isDeviceUnlockEnable(this)) {
            deviceUnlockFragment = supportFragmentManager
                .findFragmentByTag(UNLOCK_FRAGMENT_TAG) as? DeviceUnlockFragment?
            if (deviceUnlockFragment == null) {
                deviceUnlockFragment = DeviceUnlockFragment().also {
                    supportFragmentManager.commit {
                        replace(
                            R.id.fragment_device_unlock_container_view,
                            it,
                            UNLOCK_FRAGMENT_TAG
                        )
                    }
                }
            }
        }

        mMainCredentialViewModel.refreshPreferences()
        mMainCredentialViewModel.onConditionChanged(mainCredentialView.isFill())

        // Back to previous keyboard is setting activated
        if (PreferencesUtil.isKeyboardPreviousDatabaseCredentialsEnable(this@MainCredentialActivity)) {
            sendBroadcast(Intent(BACK_PREVIOUS_KEYBOARD_ACTION))
        }

        mMainCredentialViewModel.loadDatabaseFile(
            mainCredential = mainCredentialView.getMainCredential(),
            specialMode = mSpecialMode,
            typeMode = mTypeMode
        )
    }

    override fun onDatabaseRetrieved(database: ContextualDatabase) {
        super.onDatabaseRetrieved(database)
        // Trying to load another database
        mMainCredentialViewModel.onDatabaseRetrieved(database)
    }

    override fun onDatabaseActionFinished(
        database: ContextualDatabase,
        actionTask: String,
        result: ActionRunnable.Result
    ) {
        super.onDatabaseActionFinished(database, actionTask, result)
        when (actionTask) {
            ACTION_DATABASE_LOAD_TASK -> {
                fidoUnlock?.databaseResult(
                    result.data?.getParcelableCompat<Uri>(DATABASE_URI_KEY),
                    result.data?.getParcelableCompat<MainCredential>(MAIN_CREDENTIAL_KEY)?.password,
                    result.data?.getParcelableCompat<MainCredential>(MAIN_CREDENTIAL_KEY)?.keyFileUri,
                    result.isSuccess
                )
                if (result.isSuccess) {
                    mMainCredentialViewModel.onDatabaseRetrieved(database)
                } else {
                    mainCredentialView.requestPasswordFocus()
                    // Manage special exceptions
                    when (result.exception) {
                        is DuplicateUuidDatabaseException -> {
                            // Relaunch loading if we need to fix UUID
                            result.data?.let { resultData ->
                                mMainCredentialViewModel.showLoadDatabaseDuplicateUuidMessage(
                                    databaseUri = resultData.getParcelableCompat(DATABASE_URI_KEY),
                                    mainCredential = resultData.getParcelableCompat(MAIN_CREDENTIAL_KEY) ?: MainCredential(),
                                    readOnly = resultData.getBoolean(READ_ONLY_KEY),
                                    allowUserVerification = resultData.getBoolean(USER_VERIFICATION_KEY),
                                    cipherEncryptDatabase = resultData.getParcelableCompat(CIPHER_DATABASE_KEY)
                                )
                            }
                        }
                        is FileNotFoundDatabaseException -> {
                            // Remove this default database inaccessible
                            mMainCredentialViewModel.removeDefaultDatabase()
                        }
                    }
                }
            }
        }
        result.clear()
    }

    private fun getUriFromIntent(intent: Intent?) {
        // If is a view intent
        val action = intent?.action
        if (action == VIEW_INTENT) {
            fillCredentials(
                intent.data,
                intent.getUri(KEY_KEYFILE),
                HardwareKey.getHardwareKeyFromString(intent.getStringExtra(KEY_HARDWARE_KEY))
            )
        } else {
            fillCredentials(
                intent?.getParcelableExtraCompat(KEY_FILENAME),
                intent?.getParcelableExtraCompat(KEY_KEYFILE),
                HardwareKey.getHardwareKeyFromString(intent?.getStringExtra(KEY_HARDWARE_KEY))
            )
        }
        try {
            intent?.removeExtra(KEY_KEYFILE)
            intent?.removeExtra(KEY_HARDWARE_KEY)
        } catch (_: Exception) {}
    }

    private fun fillCredentials(
        databaseUri: Uri?,
        keyFileUri: Uri?,
        hardwareKey: HardwareKey?
    ) {
        mMainCredentialViewModel.assignDatabaseUri(databaseUri)
        mainCredentialView.populateKeyFileView(
            if (fidoUnlock != null) keyFileAssociations.resolve(databaseUri, keyFileUri) else keyFileUri
        )
        mainCredentialView.populateHardwareKeyView(hardwareKey)
    }

    override fun onNewIntent(intent: Intent?) {
        if (mainCredentialView.isTokenPinMode) mainCredentialView.populatePasswordTextView(null)
        fidoUnlock?.cancel()
        super.onNewIntent(intent)
        getUriFromIntent(intent)
    }

    private val credentialStorageListener = object: MainCredentialView.CredentialStorageListener {
        override fun passwordToStore(password: CharArray?): ByteArray? {
            if (password == null) return null
            val byteBuffer = DEFAULT_PASSWORD_ENCODING.encode(
                CharBuffer.wrap(password)
            )
            val bytes = ByteArray(byteBuffer.remaining())
            byteBuffer.get(bytes)
            return bytes
        }

        override fun keyfileToStore(keyfile: Uri?): ByteArray? {
            // TODO create byte array to store keyfile
            return null
        }

        override fun hardwareKeyToStore(): ByteArray? {
            // TODO create byte array to store hardware key
            return null
        }
    }

    private fun getCredentialForEncryption(): ByteArray {
        return mainCredentialView.retrieveCredentialForStorage(credentialStorageListener)
            ?: byteArrayOf()
    }

    private fun onCredentialEncrypted(cipherEncryptDatabase: CipherEncryptDatabase) {
        if (fidoUnlock != null || mainCredentialView.isTokenPinMode) return
        fidoUnlock?.cancel()
        // Load the database if password is registered with biometric
        mMainCredentialViewModel.loadDatabase(
            mainCredential = mainCredentialView.getMainCredential(),
            specialMode = mSpecialMode,
            cipherEncryptDatabase = cipherEncryptDatabase
        )
    }

    private fun onCredentialDecrypted(cipherDecryptDatabase: CipherDecryptDatabase) {
        if (fidoUnlock != null || mainCredentialView.isTokenPinMode) return
        fidoUnlock?.cancel()
        // Load the database if password is retrieve from biometric
        // Retrieve from biometric
        val tempMainCredential = mainCredentialView.getMainCredential()
        when (cipherDecryptDatabase.credentialStorage) {
            CredentialStorage.PASSWORD -> {
                val charBuffer = DEFAULT_PASSWORD_ENCODING.decode(
                    ByteBuffer.wrap(cipherDecryptDatabase.decryptedValue)
                )
                val password = CharArray(charBuffer.remaining())
                charBuffer.get(password)
                tempMainCredential.password = password
            }
            CredentialStorage.KEY_FILE -> {
                // TODO advanced unlock key file
            }
            CredentialStorage.HARDWARE_KEY -> {
                // TODO advanced unlock hardware key
            }
        }
        mMainCredentialViewModel.loadDatabase(
            mainCredential = tempMainCredential,
            specialMode = mSpecialMode
        )
    }

    private fun clearCredentialsViews(
        clearKeyFile: Boolean,
        clearHardwareKey: Boolean
    ) {
        mainCredentialView.populatePasswordTextView(null)
        if (clearKeyFile && fidoUnlock == null) {
            mainCredentialView.populateKeyFileView(null)
        }
        if (clearHardwareKey) {
            mainCredentialView.populateHardwareKeyView(null)
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        val inflater = menuInflater
        // Read menu
        inflater.inflate(R.menu.open_file, menu)
        if (fidoUnlock != null) {
            menu.add(0, FIDO_UNLOCK, 0, "USB verwenden").apply {
                isCheckable = true
                isChecked = fidoUnlock?.isNfcMode != true
            }
            menu.add(0, FIDO_NFC, 1, "NFC verwenden").apply {
                isCheckable = true
                isChecked = fidoUnlock?.isNfcMode == true
                isEnabled = fidoUnlock?.hasNfc() == true
            }
            menu.add(0, FIDO_ENROLL, 1, "Token hinzufügen")
            menu.add(0, FIDO_REMOVE, 2, "Tokens verwalten")
            menu.add(0, FIDO_FINGERPRINT, 6, "Token + Fingerprint")
            menu.add(0, FIDO_PIN_SAVE, 7, "Token PIN für Fingerprint speichern")
            menu.add(0, FIDO_PIN_REMOVE, 8, "Gespeicherte Token PINs entfernen")
            menu.add(0, FIDO_MASTER_PASSWORD, 3, "Master Password verwenden")
            menu.add(0, FIDO_KEY_FILE, 4, if (mainCredentialView.selectedKeyFile() == null)
                "Key File zuordnen" else "Key File ändern")
            if (mainCredentialView.selectedKeyFile() != null)
                menu.add(0, FIDO_KEY_FILE_REMOVE, 5, "Key File-Zuordnung entfernen")
        }
        if (mMainCredentialViewModel.isReadOnlyToggleAllowed()) {
            changeDatabaseReadModeIcon(menu.findItem(R.id.menu_open_file_read_mode_key))
        } else {
            menu.removeItem(R.id.menu_open_file_read_mode_key)
        }

        if (mMainCredentialViewModel.isUserVerificationToggleAllowed()) {
            changeUserVerificationModeIcon(
                menu.findItem(R.id.menu_open_file_user_verification_mode_key)
            )
        } else {
            menu.removeItem(R.id.menu_open_file_user_verification_mode_key)
        }

        if (mSpecialMode == SpecialMode.DEFAULT) {
            MenuUtil.defaultMenuInflater(inflater, menu)
        }

        super.onCreateOptionsMenu(menu)

        launchEducation(menu)

        return true
    }

    // To fix multiple view education
    private var performedEductionInProgress = false
    private fun launchEducation(menu: Menu) {
        if (!performedEductionInProgress) {
            performedEductionInProgress = true
            // Show education views
            Handler(Looper.getMainLooper()).post {
                performedNextEducation(menu)
            }
        }
    }

    private fun performedNextEducation(menu: Menu) {
        val educationToolbar = toolbar
        val unlockEducationPerformed = educationToolbar != null
                && mPasswordActivityEducation.checkAndPerformedUnlockEducation(
                educationToolbar,
                        {
                            performedNextEducation(menu)
                        },
                        {
                            performedNextEducation(menu)
                        })
        if (!unlockEducationPerformed) {
            val readOnlyEducationPerformed =
                    educationToolbar?.findViewById<View>(R.id.menu_open_file_read_mode_key) != null
                    && mPasswordActivityEducation.checkAndPerformedReadOnlyEducation(
                    educationToolbar.findViewById(R.id.menu_open_file_read_mode_key),
                    {
                        try {
                            menu.findItem(R.id.menu_open_file_read_mode_key)
                        } catch (e: Exception) {
                            Log.e(TAG, "Unable to find read mode menu", e)
                        }
                        performedNextEducation(menu)
                    },
                    {
                        performedNextEducation(menu)
                    })
            if (!readOnlyEducationPerformed) {
                val userVerificationEducationPerformed =
                    educationToolbar?.findViewById<View>(R.id.menu_open_file_user_verification_mode_key) != null
                            && mPasswordActivityEducation.checkAndPerformedUserVerificationEducation(
                        educationToolbar.findViewById(R.id.menu_open_file_user_verification_mode_key),
                        {
                            try {
                                menu.findItem(R.id.menu_open_file_user_verification_mode_key)
                            } catch (e: Exception) {
                                Log.e(TAG, "Unable to find user verification mode menu", e)
                            }
                            performedNextEducation(menu)
                        },
                        {
                            performedNextEducation(menu)
                        })
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
                        && !userVerificationEducationPerformed
                    ) {
                        val biometricCanAuthenticate = DeviceUnlockManager.canAuthenticate(this)
                        if ((biometricCanAuthenticate == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED
                                    || biometricCanAuthenticate == BiometricManager.BIOMETRIC_SUCCESS)
                            && deviceUnlockButton != null
                        ) {
                            mPasswordActivityEducation.checkAndPerformedBiometricEducation(
                                deviceUnlockButton!!,
                                {
                                    startActivity(
                                        Intent(
                                            this,
                                            DeviceUnlockSettingsActivity::class.java
                                        )
                                    )
                                },
                                {

                                })
                        }
                    }
                } catch (_: Exception) {}
            }
        }
    }

    private fun changeDatabaseReadModeIcon(readOnlyMenuItem: MenuItem) {
        if (mMainCredentialViewModel.readOnly) {
            readOnlyMenuItem.setTitle(R.string.menu_file_selection_read_only)
            readOnlyMenuItem.setIcon(R.drawable.ic_read_only_white_24dp)
        } else {
            readOnlyMenuItem.setTitle(R.string.menu_open_file_read_and_write)
            readOnlyMenuItem.setIcon(R.drawable.ic_read_write_white_24dp)
        }
    }

    private fun changeUserVerificationModeIcon(userVerificationMenuItem: MenuItem) {
        if (mMainCredentialViewModel.userVerificationMode) {
            userVerificationMenuItem.setTitle(R.string.menu_user_verification_enabled)
            userVerificationMenuItem.setIcon(R.drawable.ic_user_verification_enabled_white_24dp)
        } else {
            userVerificationMenuItem.setTitle(R.string.menu_user_verification_disabled)
            userVerificationMenuItem.setIcon(R.drawable.ic_user_verification_disabled_white_24dp)
        }
    }

    private fun showFidoEnrollmentPassword() {
        refreshFidoInputMode()
        fidoUnlock?.cancel()
        // This input is always the database password, never the current PIN field.
        mainCredentialView.populatePasswordTextView(null)
        val input = android.widget.EditText(this).apply {
            hint = "Master Password"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSingleLine = true
            isSaveEnabled = false
            isSaveFromParentEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            imeOptions = android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        }
        val tokenName = android.widget.EditText(this).apply {
            hint = "Token-Name (z. B. Backup zuhause)"
            isSingleLine = true
            filters = arrayOf(android.text.InputFilter.LengthFilter(40))
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        }
        val fields = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(24, 0, 24, 0)
            addView(tokenName)
            addView(input)
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle("Token hinzufügen")
            .setMessage("Bis zu 5 Tokens pro Datenbank auf diesem Gerät. Bestehende Tokens bleiben erhalten. Master Password eingeben; ein zugeordnetes Key File wird mitgeprüft. Danach folgt die Token-PIN. Auf weiteren Geräten ist ein eigenes Enrollment nötig.")
            .setView(fields)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton("Hinzufügen", null)
            .create()
        enrollmentDialog = dialog
        dialog.setOnDismissListener { input.text.clear(); enrollmentDialog = null }
        dialog.show()
        dialog.window?.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val name = tokenName.text.toString().trim()
            if (name.isEmpty()) { tokenName.error = "Token-Name eingeben"; return@setOnClickListener }
            if (input.length() == 0) { input.error = "Master Password eingeben"; return@setOnClickListener }
            val master = CharArray(input.length())
            input.text.getChars(0, master.size, master, 0)
            input.text.clear()
            dialog.dismiss()
            refreshFidoInputMode()
            fidoUnlock?.beginEnrollment(mMainCredentialViewModel.databaseFileUri, master, name, mainCredentialView.selectedKeyFile())
                ?: master.fill('\u0000')
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {

        when (item.itemId) {
            FIDO_FINGERPRINT -> {
                mainCredentialView.populatePasswordTextView(null)
                fidoUnlock?.beginFingerprint(mMainCredentialViewModel.databaseFileUri, mainCredentialView.selectedKeyFile())
                return true
            }
            FIDO_PIN_SAVE -> {
                mainCredentialView.populatePasswordTextView(null)
                fidoUnlock?.beginSavePin(mMainCredentialViewModel.databaseFileUri, mainCredentialView.selectedKeyFile())
                return true
            }
            FIDO_PIN_REMOVE -> {
                fidoUnlock?.removeSavedPins(mMainCredentialViewModel.databaseFileUri)
                return true
            }
            FIDO_KEY_FILE -> {
                fidoUnlock?.cancel()
                keyFilePickerDatabase = mMainCredentialViewModel.databaseFileUri
                if (keyFilePickerDatabase != null) openFileResultLauncher.openDocument.launch(arrayOf("*/*"))
                return true
            }
            FIDO_KEY_FILE_REMOVE -> {
                val database = mMainCredentialViewModel.databaseFileUri ?: return true
                AlertDialog.Builder(this).setTitle("Key File-Zuordnung entfernen?")
                    .setMessage("Dies entfernt nur den gespeicherten Dateiverweis. Eine mit Key File geschützte Datenbank benötigt weiterhin dieselbe Datei. Die Datei wird nicht gelöscht.")
                    .setNegativeButton(android.R.string.cancel, null)
                    .setPositiveButton("Entfernen") { _, _ ->
                        fidoUnlock?.cancel()
                        keyFileAssociations.assign(database, null)
                        mainCredentialView.populateKeyFileView(null)
                        invalidateOptionsMenu()
                    }.show()
                return true
            }
            FIDO_MASTER_PASSWORD -> {
                refreshFidoInputMode()
                fidoUnlock?.cancel()
                masterPasswordOverride = true
                refreshFidoInputMode()
                mainCredentialView.focusPasswordFieldAndOpenKeyboard()
                return true
            }
            FIDO_NFC -> {
                if (fidoUnlock?.selectNfc(true) == true) {
                    masterPasswordOverride = false
                    refreshFidoInputMode()
                    invalidateOptionsMenu()
                    mainCredentialView.focusPasswordFieldAndOpenKeyboard()
                }
                return true
            }
            FIDO_UNLOCK -> {
                fidoUnlock?.selectNfc(false)
                masterPasswordOverride = false
                refreshFidoInputMode()
                invalidateOptionsMenu()
                if (!mainCredentialView.isTokenPinMode) {
                    Toast.makeText(this, "Token2 per USB-C anschließen.", Toast.LENGTH_LONG).show()
                }
                mainCredentialView.focusPasswordFieldAndOpenKeyboard()
                return true
            }
            FIDO_ENROLL -> {
                showFidoEnrollmentPassword()
                return true
            }
            FIDO_REMOVE -> {
                fidoUnlock?.remove(mMainCredentialViewModel.databaseFileUri)
                return true
            }
            android.R.id.home -> finish()
            R.id.menu_open_file_read_mode_key -> {
                mMainCredentialViewModel.toggleReadOnly()
                changeDatabaseReadModeIcon(item)
                // Save the read-only state to database
                mMainCredentialViewModel.databaseFileUri?.let { databaseUri ->
                    FileDatabaseHistoryAction.getInstance(applicationContext).addOrUpdateDatabaseFile(
                        DatabaseFile(
                            databaseUri = databaseUri,
                            readOnly = mMainCredentialViewModel.readOnly
                        )
                    )
                }
            }
            R.id.menu_open_file_user_verification_mode_key -> {
                mMainCredentialViewModel.toggleUserVerificationMode()
                changeUserVerificationModeIcon(item)
                // Save the user verification state to database
                mMainCredentialViewModel.databaseFileUri?.let { databaseUri ->
                    FileDatabaseHistoryAction.getInstance(applicationContext).addOrUpdateDatabaseFile(
                        DatabaseFile(
                            databaseUri = databaseUri,
                            userVerification = mMainCredentialViewModel.userVerificationMode
                        )
                    )
                }
            }
            else -> MenuUtil.onDefaultMenuOptionsItemSelected(this, item)
        }

        return super.onOptionsItemSelected(item)
    }

    override fun onPause() {
        fidoUnlock?.pauseNfc()
        super.onPause()
    }

    override fun onStop() {
        enrollmentDialog?.dismiss()
        tokenMonitorHandler.removeCallbacks(tokenMonitor)
        if (mainCredentialView.isTokenPinMode) mainCredentialView.populatePasswordTextView(null)
        fidoUnlock?.cancel()
        super.onStop()
    }

    override fun onDestroy() {
        fidoUnlock?.close()
        super.onDestroy()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mDeviceUnlockViewModel?.disconnect()
        }
    }

    companion object {
        private const val FIDO_UNLOCK = 0x7f0f7101
        private const val FIDO_ENROLL = 0x7f0f7102
        private const val FIDO_REMOVE = 0x7f0f7103
        private const val FIDO_MASTER_PASSWORD = 0x7f0f7104
        private const val FIDO_KEY_FILE = 0x7f0f7105
        private const val FIDO_KEY_FILE_REMOVE = 0x7f0f7106
        private const val FIDO_FINGERPRINT = 0x7f0f7107
        private const val FIDO_PIN_SAVE = 0x7f0f7108
        private const val FIDO_PIN_REMOVE = 0x7f0f7109
        private const val FIDO_NFC = 0x7f0f710a

        private val TAG = MainCredentialActivity::class.java.name

        private const val UNLOCK_FRAGMENT_TAG = "UNLOCK_FRAGMENT_TAG"

        private const val KEY_FILENAME = "fileName"
        private const val KEY_KEYFILE = "keyFile"
        private const val KEY_HARDWARE_KEY = "hardwareKey"
        private const val VIEW_INTENT = "android.intent.action.VIEW"

        private const val KEY_PASSWORD = "password"
        private const val KEY_LAUNCH_IMMEDIATELY = "launchImmediately"

        private fun buildAndLaunchIntent(
            activity: Activity,
            databaseFile: Uri,
            keyFile: Uri?,
            hardwareKey: HardwareKey?,
            intentBuildLauncher: (Intent) -> Unit
        ) {
            val intent = Intent(activity, MainCredentialActivity::class.java)
            intent.putExtra(KEY_FILENAME, databaseFile)
            if (keyFile != null)
                intent.putExtra(KEY_KEYFILE, keyFile)
            if (hardwareKey != null)
                intent.putExtra(KEY_HARDWARE_KEY, hardwareKey.toString())
            intentBuildLauncher.invoke(intent)
        }

        /*
         * -------------------------
         * 		Standard Launch
         * -------------------------
         */

        @Throws(FileNotFoundException::class)
        fun launch(
            activity: Activity,
            databaseFile: Uri,
            keyFile: Uri?,
            hardwareKey: HardwareKey?
        ) {
            buildAndLaunchIntent(activity, databaseFile, keyFile, hardwareKey) { intent ->
                activity.startActivity(intent)
            }
        }

        /*
         * -------------------------
         * 		Share Launch
         * -------------------------
         */

        @Throws(FileNotFoundException::class)
        fun launchForSearchResult(
            activity: Activity,
            databaseFile: Uri,
            keyFile: Uri?,
            hardwareKey: HardwareKey?,
            searchInfo: SearchInfo
        ) {
            buildAndLaunchIntent(activity, databaseFile, keyFile, hardwareKey) { intent ->
                EntrySelectionHelper.startActivityForSearchModeResult(
                    context = activity,
                    intent = intent,
                    searchInfo = searchInfo
                )
            }
        }

        /*
         * -------------------------
         * 		Selection Launch
         * -------------------------
         */

        @Throws(FileNotFoundException::class)
        fun launchForSelection(
            activity: Activity,
            databaseFile: Uri,
            keyFile: Uri?,
            hardwareKey: HardwareKey?,
            typeMode: TypeMode,
            searchInfo: SearchInfo?,
            activityResultLauncher: ActivityResultLauncher<Intent>?
        ) {
            buildAndLaunchIntent(activity, databaseFile, keyFile, hardwareKey) { intent ->
                EntrySelectionHelper.startActivityForSelectionModeResult(
                    context = activity,
                    intent = intent,
                    typeMode = typeMode,
                    searchInfo = searchInfo,
                    activityResultLauncher = activityResultLauncher
                )
            }
        }

        /*
         * -------------------------
         *      Registration Launch
         * -------------------------
         */

        @Throws(FileNotFoundException::class)
        fun launchForRegistration(
            activity: Activity,
            databaseFile: Uri,
            keyFile: Uri?,
            hardwareKey: HardwareKey?,
            typeMode: TypeMode,
            registerInfo: RegisterInfo?,
            activityResultLauncher: ActivityResultLauncher<Intent>?
        ) {
            buildAndLaunchIntent(activity, databaseFile, keyFile, hardwareKey) { intent ->
                EntrySelectionHelper.startActivityForRegistrationModeResult(
                    context = activity,
                    intent = intent,
                    typeMode = typeMode,
                    registerInfo = registerInfo,
                    activityResultLauncher = activityResultLauncher,
                )
            }
        }
    }
}
