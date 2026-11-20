package com.kunzisoft.keepass.fido2;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;
import java.io.IOException;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/** Per-enrollment PIN only. Never stores database credentials or token-derived secrets. */
@android.annotation.TargetApi(33)
final class BiometricPin {
    interface Callback { void complete(byte[] pin); void failed(); }
    private final android.app.Activity activity;
    private final SharedPreferences preferences;
    private BiometricPrompt prompt;
    private byte[] pending;
    private int generation;

    BiometricPin(android.app.Activity activity) {
        this.activity=activity;
        preferences=activity.getSharedPreferences("fido2_biometric_pins",Context.MODE_PRIVATE);
    }
    static boolean available(Context context) {
        return BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                ==BiometricManager.BIOMETRIC_SUCCESS;
    }
    static String binding(UnlockRecord record)throws Exception {
        return hex(Crypto.sha(record.encode()));
    }
    private static String hex(byte[] value) {
        StringBuilder result=new StringBuilder();for(byte b:value)result.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return result.toString();
    }
    private static String alias(String binding) { return "keepassdx.fido2.pin.v1."+binding; }
    static KeyGenParameterSpec keySpec(String alias) {
        return new KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0,KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true).build();
    }
    private static KeyStore keyStore()throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);return store;
    }
    private static SecretKey key(String binding,boolean create)throws Exception {
        KeyStore store=keyStore();String alias=alias(binding);
        if(!store.containsAlias(alias)&&create) {
            KeyGenerator generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
            generator.init(keySpec(alias));generator.generateKey();
        }
        SecretKey key=(SecretKey)store.getKey(alias,null);
        if(key==null)throw new IOException("PIN erneut für Fingerprint speichern.");
        KeyInfo info=(KeyInfo)SecretKeyFactory.getInstance(key.getAlgorithm(),"AndroidKeyStore").getKeySpec(key,KeyInfo.class);
        int level=info.getSecurityLevel();
        if(level!=KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT&&level!=KeyProperties.SECURITY_LEVEL_STRONGBOX)
            throw new IOException("Hardware-backed Android Keystore ist nicht verfügbar.");
        return key;
    }
    boolean has(UnlockRecord record)throws Exception { return preferences.contains(binding(record)); }
    void remove(UnlockRecord record)throws Exception {
        String binding=binding(record);
        if(!preferences.edit().remove(binding).commit())throw new IOException("Gespeicherte PIN konnte nicht entfernt werden.");
        keyStore().deleteEntry(alias(binding));
    }
    void authenticate(EnrollmentSet.Entry entry,byte[] validatedPin,Callback callback) {
        cancel();final int request=generation;
        pending=validatedPin;
        try {
            if(!available(activity))throw new IOException("Starke Biometrie ist nicht verfügbar. Token PIN manuell eingeben.");
            final boolean save=validatedPin!=null;
            final String binding=binding(entry.record);
            final Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
            final byte[] ciphertext;
            if(save) {
                try { cipher.init(Cipher.ENCRYPT_MODE,key(binding,true)); }
                catch(android.security.keystore.KeyPermanentlyInvalidatedException invalidated) {
                    // Explicit re-saving after a biometric change creates a fresh key.
                    keyStore().deleteEntry(alias(binding));
                    cipher.init(Cipher.ENCRYPT_MODE,key(binding,true));
                }
                ciphertext=null;
            } else {
                String encoded=preferences.getString(binding,null);
                if(encoded==null||encoded.length()>512)throw new IOException("PIN erneut für Fingerprint speichern.");
                Object envelope=Cbor.decode(Base64.decode(encoded,Base64.NO_WRAP));
                if(Cbor.number(Cbor.get(envelope,1))!=1)throw new IOException("Ungültiger PIN-Speicher.");
                byte[] iv=Cbor.bytes(Cbor.get(envelope,2));ciphertext=Cbor.bytes(Cbor.get(envelope,3));
                if(iv.length!=12||ciphertext.length<20||ciphertext.length>79)throw new IOException("Ungültiger PIN-Speicher.");
                cipher.init(Cipher.DECRYPT_MODE,key(binding,false),new GCMParameterSpec(128,iv));
            }
            prompt=new BiometricPrompt((FragmentActivity)activity,ContextCompat.getMainExecutor(activity),new BiometricPrompt.AuthenticationCallback(){
                @Override public void onAuthenticationError(int code,CharSequence error) {
                    if(request!=generation)return;
                    cancel();callback.failed();
                }
                @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                    if(request!=generation)return;
                    byte[] clear=null;
                    try {
                        if(result.getCryptoObject()==null||result.getCryptoObject().getCipher()!=cipher)
                            throw new IOException("Biometric cipher fehlt.");
                        // Do not send even AAD to an auth-per-use key before authorization.
                        cipher.updateAAD(Crypto.utf8("keepassdx.fido2.pin.v1:"+binding));
                        if(save) {
                            byte[] encrypted=cipher.doFinal(pending);
                            String encoded=Base64.encodeToString(Cbor.encode(Cbor.map(1,1,2,cipher.getIV(),3,encrypted)),Base64.NO_WRAP);
                            if(!preferences.edit().putString(binding,encoded).commit())throw new IOException("PIN konnte nicht gespeichert werden.");
                        } else {
                            clear=cipher.doFinal(ciphertext);
                            if(clear.length<4||clear.length>63)throw new IOException("Ungültige PIN-Länge.");
                        }
                        cancel();byte[] owned=clear;clear=null;callback.complete(owned);
                    }catch(Exception error){cancel();callback.failed();}
                    finally{Crypto.wipe(clear);}
                }
            });
            BiometricPrompt.PromptInfo info=new BiometricPrompt.PromptInfo.Builder()
                    .setTitle(save?"Token PIN für Fingerprint speichern":"Token + Fingerprint")
                    .setSubtitle(entry.name)
                    .setDescription(save?"Diese PIN wird nur auf diesem Gerät geschützt gespeichert. Der Token bleibt erforderlich."
                            :"PIN für diesen Token einmal freigeben. Bei mehreren Tokens den passenden Token anschließen.")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .setNegativeButtonText("Abbrechen / PIN manuell").build();
            prompt.authenticate(info,new BiometricPrompt.CryptoObject(cipher));
        } catch(Exception error) {
            cancel();android.widget.Toast.makeText(activity,"Fingerprint nicht verfügbar. Token PIN manuell eingeben oder erneut speichern.",android.widget.Toast.LENGTH_LONG).show();
            callback.failed();
        }
    }
    void cancel() {
        generation++;Crypto.wipe(pending);pending=null;
        BiometricPrompt active=prompt;prompt=null;if(active!=null)active.cancelAuthentication();
    }
}
