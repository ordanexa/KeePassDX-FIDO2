package com.kunzisoft.keepass.fido2;

import android.app.*;
import android.content.*;
import android.hardware.usb.*;
import android.net.Uri;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.*;
import android.text.InputType;
import android.view.*;
import android.widget.*;
import android.annotation.TargetApi;
import java.io.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

/** Activity-scoped coordinator. No plaintext persistence; biometric storage holds only an encrypted PIN. */
@TargetApi(33)
public final class FidoUnlock {
    public interface Callback { void unlock(char[] password, Uri keyFile); }
    private final Activity activity;
    private final UsbManager manager;
    private final Handler main=new Handler(Looper.getMainLooper());
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final String permissionAction;
    private final Callback callback;
    private volatile int generation;
    private volatile CtapTransport io;
    private final NfcAdapter nfcAdapter;
    private boolean nfcMode,readerEnabled,waitingNfc;
    private char[] password;
    private byte[] pendingPin;
    private String database;
    private Uri keyFile;
    private UsbDevice device;
    private boolean enrolling, busy;
    private AlertDialog dialog;
    private UnlockRecord pending;
    private EnrollmentSet snapshot;
    private String tokenName;
    private boolean waitingDatabase;
    private byte[] proofKey, passwordProof;
    private final BiometricPin biometricPin;
    private boolean savePinRequested;
    private EnrollmentSet.Entry fingerprintEntry;

    public FidoUnlock(Activity activity,Callback callback) {
        this.activity=activity;this.callback=callback;
        biometricPin=new BiometricPin(activity);
        manager=(UsbManager)activity.getSystemService(Context.USB_SERVICE);
        nfcAdapter=NfcAdapter.getDefaultAdapter(activity);
        permissionAction=activity.getPackageName()+".FIDO_USB_PERMISSION";
        IntentFilter filter=new IntentFilter(permissionAction);
        filter.addAction(UsbManager.ACTION_USB_DEVICE_DETACHED);
        if(Build.VERSION.SDK_INT>=33)activity.registerReceiver(receiver,filter,Context.RECEIVER_NOT_EXPORTED);
        else activity.registerReceiver(receiver,filter);
    }
    private final BroadcastReceiver receiver=new BroadcastReceiver(){
        @Override public void onReceive(Context context,Intent intent){
            UsbDevice returned=intent.getParcelableExtra(UsbManager.EXTRA_DEVICE);
            if(device==null||returned==null||!device.equals(returned))return;
            if(UsbManager.ACTION_USB_DEVICE_DETACHED.equals(intent.getAction())){cancel();message("Token disconnected. Use your master password or reconnect.");}
            else if(permissionAction.equals(intent.getAction())&&busy){
                if(manager.hasPermission(device))permissionReady();else{cancel();message("USB permission denied.");}
            }
        }
    };
    public boolean hasNfc(){return nfcAdapter!=null;}
    public boolean isNfcMode(){return nfcMode;}
    public boolean selectNfc(boolean enabled){
        cancel();
        if(enabled&&(nfcAdapter==null||!nfcAdapter.isEnabled())){message("NFC in den Android-Einstellungen aktivieren.");return false;}
        nfcMode=enabled;return true;
    }
    public void pauseNfc(){if(readerEnabled)cancel();}
    private void stopNfcReader(){
        waitingNfc=false;
        if(readerEnabled){readerEnabled=false;try{nfcAdapter.disableReaderMode(activity);}catch(RuntimeException ignored){}}
    }
    public boolean hasConnectedToken(){
        for(UsbDevice d:manager.getDeviceList().values())
            if(d.getVendorId()==0x349e&&d.getProductId()==0x0024)return true;
        return false;
    }
    public void beginWithPin(Uri uri,char[] suppliedPin,Uri selectedKeyFile){
        byte[] bytes=null;
        try{
            bytes=UnlockRecord.encodeChars(suppliedPin);
            if(bytes.length<4||bytes.length>63)throw new IOException("PIN must contain 4–63 UTF-8 bytes.");
            begin(uri,null,false,bytes,selectedKeyFile,null);bytes=null;
        }catch(Exception e){message(e.getMessage());}
        finally{Arrays.fill(suppliedPin,'\0');Crypto.wipe(bytes);}
    }
    public void beginSavePin(Uri uri,Uri selectedKeyFile){
        if(!BiometricPin.available(activity)){message("Starke Biometrie einrichten; anschließend erneut versuchen.");return;}
        begin(uri,null,false,null,selectedKeyFile,null,true,null);
    }
    public void beginFingerprint(Uri uri,Uri selectedKeyFile){
        if(busy){message("A token operation is already running.");return;}
        cancel();
        if(uri==null){message("Select a database first.");return;}
        try{
            EnrollmentSet current=EnrollmentStorage.read(activity,uri.toString());
            List<EnrollmentSet.Entry> saved=new ArrayList<>();
            for(EnrollmentSet.Entry entry:current.entries)if(biometricPin.has(entry.record))saved.add(entry);
            if(saved.isEmpty()){message("Zuerst im Menü Token PIN für Fingerprint speichern wählen.");return;}
            if(current.entries.size()==1){begin(uri,null,false,null,selectedKeyFile,null,false,saved.get(0));return;}
            String[] names=new String[saved.size()];for(int i=0;i<names.length;i++)names[i]=saved.get(i).name;
            dialog=new AlertDialog.Builder(activity).setTitle("Angeschlossenen Token wählen")
                    .setItems(names,(d,which)->begin(uri,null,false,null,selectedKeyFile,null,false,saved.get(which)))
                    .setNegativeButton("Abbrechen",(d,w)->cancel()).create();
            dialog.setOnCancelListener(d->cancel());dialog.show();
        }catch(Exception error){cancel();message("Gespeicherte PIN nicht verfügbar. Token PIN manuell eingeben.");}
    }
    public void removeSavedPins(Uri uri){
        if(busy||uri==null)return;
        cancel();
        dialog=new AlertDialog.Builder(activity).setTitle("Gespeicherte Token PINs entfernen?")
                .setMessage("Entfernt die Fingerprint-PINs dieser Datenbank auf diesem Gerät. Token-Enrollment und Datenbank bleiben erhalten.")
                .setNegativeButton("Abbrechen",null).setPositiveButton("Entfernen",(d,w)->{
                    try{for(EnrollmentSet.Entry entry:EnrollmentStorage.read(activity,uri.toString()).entries)biometricPin.remove(entry.record);
                        message("Gespeicherte Token PINs entfernt.");}
                    catch(Exception error){message("PIN-Speicher konnte nicht vollständig entfernt werden.");}
                }).create();
        dialog.show();
    }
    public void beginEnrollment(Uri uri,char[] suppliedPassword,String name,Uri selectedKeyFile){
        begin(uri,suppliedPassword,true,null,selectedKeyFile,name);
    }
    private void begin(Uri uri,char[] suppliedPassword,boolean enroll,byte[] inlinePin,Uri selectedKeyFile,String name){
        begin(uri,suppliedPassword,enroll,inlinePin,selectedKeyFile,name,false,null);
    }
    private void begin(Uri uri,char[] suppliedPassword,boolean enroll,byte[] inlinePin,Uri selectedKeyFile,String name,
                       boolean savePin,EnrollmentSet.Entry selectedFingerprint){
        if(busy){Crypto.wipe(inlinePin);if(suppliedPassword!=null)Arrays.fill(suppliedPassword,'\0');message("A token operation is already running.");return;}
        cancel();pendingPin=inlinePin;
        if(uri==null){if(suppliedPassword!=null)Arrays.fill(suppliedPassword,'\0');cancel();message("Select a database first.");return;}
        if(enroll&&(suppliedPassword==null||suppliedPassword.length==0)){
            if(suppliedPassword!=null)Arrays.fill(suppliedPassword,'\0');message("Enter the database master password first.");return;
        }
        database=uri.toString();enrolling=enroll;password=suppliedPassword;keyFile=selectedKeyFile;
        savePinRequested=savePin;fingerprintEntry=selectedFingerprint;
        try{
            snapshot=EnrollmentStorage.read(activity,database);
            if(enroll){snapshot.checkAddition(name);tokenName=EnrollmentSet.validateName(name);}
            else if(snapshot.entries.isEmpty())throw new IOException("No token enrolled for this database on this device. Use Token hinzufügen first.");
            if(selectedFingerprint!=null){
                EnrollmentSet.Entry latest=snapshot.find(selectedFingerprint.record.credential.id);
                if(!MessageDigest.isEqual(latest.record.encode(),selectedFingerprint.record.encode()))
                    throw new IOException("Enrollment changed. Please try again.");
            }
            if(nfcMode){
                if(nfcAdapter==null||!nfcAdapter.isEnabled())throw new IOException("NFC in den Android-Einstellungen aktivieren.");
                busy=true;permissionReady();return;
            }
            List<UsbDevice> matches=new ArrayList<>();
            for(UsbDevice d:manager.getDeviceList().values())if(d.getVendorId()==0x349e&&d.getProductId()==0x0024)matches.add(d);
            if(matches.size()!=1)throw new IOException("Connect exactly one Token2 PIN+ Dual over USB-C.");
            device=matches.get(0);busy=true;
            if(manager.hasPermission(device))permissionReady();
            else manager.requestPermission(device,PendingIntent.getBroadcast(activity,generation,
                    new Intent(permissionAction).setPackage(activity.getPackageName()),PendingIntent.FLAG_CANCEL_CURRENT|PendingIntent.FLAG_MUTABLE));
        }catch(Exception e){cancel();message(e.getMessage());}
    }
    private void permissionReady(){
        if(pendingPin!=null){byte[] pin=pendingPin;pendingPin=null;run(pin);}
        else if(fingerprintEntry!=null){
            final int request=generation;
            biometricPin.authenticate(fingerprintEntry,null,new BiometricPin.Callback(){
                public void complete(byte[] pin){
                    if(request!=generation||!busy||(!nfcMode&&(device==null||!manager.getDeviceList().containsValue(device)))){
                        Crypto.wipe(pin);cancel();return;
                    }
                    run(pin);
                }
                public void failed(){if(request==generation){cancel();message("Token PIN kann weiterhin manuell eingegeben werden.");}}
            });
        }else promptPin();
    }
    private void promptPin(){
        if(!busy||activity.isFinishing())return;
        final EditText pin=new EditText(activity);
        pin.setHint("Token PIN");pin.setSingleLine(true);
        pin.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);
        pin.setSaveEnabled(false);pin.setSaveFromParentEnabled(false);pin.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        pin.setImeOptions(android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        dialog=new AlertDialog.Builder(activity).setTitle(enrolling?"Token hinzufügen":savePinRequested?"Token PIN für Fingerprint speichern":"Unlock with USB token")
                .setMessage(nfcMode?"Token PIN eingeben. Danach den Token an die NFC-Antenne halten. Keine automatischen PIN-Wiederholungen.":"Enter the token PIN. Touch the token when it blinks. No automatic PIN retries.")
                .setView(pin).setNegativeButton("Cancel",(d,w)->cancel()).setPositiveButton("Continue",null).create();
        dialog.setOnCancelListener(d->cancel());dialog.setOnDismissListener(d->pin.getText().clear());
        dialog.getWindow();dialog.show();dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
            char[] chars=new char[pin.length()];android.text.TextUtils.getChars(pin.getText(),0,chars.length,chars,0);
            byte[] bytes=null;
            try{bytes=UnlockRecord.encodeChars(chars);if(bytes.length<4||bytes.length>63)throw new IOException("PIN must contain 4–63 UTF-8 bytes.");}
            catch(Exception e){Crypto.wipe(bytes);message(e.getMessage());return;}
            finally{Arrays.fill(chars,'\0');}
            pin.getText().clear();dialog.dismiss();dialog=null;
            run(bytes);
        });
    }
    private void run(byte[] pin){
        if(!nfcMode){execute(pin,null);return;}
        if(!busy||nfcAdapter==null||!nfcAdapter.isEnabled()){Crypto.wipe(pin);cancel();message("NFC ist nicht verfügbar.");return;}
        final int request=generation;
        Crypto.wipe(pendingPin);pendingPin=pin;waitingNfc=true;
        dialog=new AlertDialog.Builder(activity).setTitle("NFC token")
                .setMessage("Token an die NFC-Antenne halten und bis zum Abschluss ruhig liegen lassen.")
                .setNegativeButton("Abbrechen",(d,w)->cancel()).create();
        dialog.setOnCancelListener(d->cancel());dialog.show();dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        Bundle options=new Bundle();options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY,2000);
        try{
            readerEnabled=true;
            nfcAdapter.enableReaderMode(activity,tag->main.post(()->acceptNfcTag(tag,request)),
                    NfcAdapter.FLAG_READER_NFC_A|NfcAdapter.FLAG_READER_NFC_B|NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,options);
            main.postDelayed(()->{if(request==generation&&waitingNfc){cancel();message("NFC scan timed out. Start again when ready.");}},60000);
        }catch(RuntimeException error){cancel();message("NFC Reader Mode konnte nicht gestartet werden.");}
    }
    private void acceptNfcTag(Tag tag,int request){
        if(request!=generation||!busy||!waitingNfc)return;
        waitingNfc=false;
        byte[] pin=pendingPin;pendingPin=null;
        if(pin==null){cancel();return;}
        if(dialog!=null){dialog.dismiss();dialog=null;}
        // Reader Mode remains enabled throughout connect/transceive, just as in FidoParole.
        execute(pin,tag);
    }
    private void execute(byte[] pin,Tag nfcTag){
        final int request=generation;
        final String db=database;
        final Uri requestKeyFile=keyFile;
        final boolean enroll=enrolling;
        final EnrollmentSet enrolled=snapshot;
        final UsbDevice selected=device;
        final boolean savePin=savePinRequested;
        final EnrollmentSet.Entry biometricEntry=fingerprintEntry;
        final char[] enrollmentPassword=password;password=null;
        dialog=new AlertDialog.Builder(activity).setTitle(nfcTag==null?"USB token":"NFC token")
                .setMessage("Connecting …").setNegativeButton("Cancel",(d,w)->cancel()).create();
        dialog.setOnCancelListener(d->cancel());dialog.show();dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        worker.execute(()->{
            char[] unlocked=null;byte[] secret=null;UnlockRecord record=null;
            try{
                if(request!=generation)return;
                CtapTransport transport=nfcTag==null?new Hid(new UsbIo(manager,selected)):
                        new NfcTransport(new IsoDepChannel(nfcTag),()->main.post(()->{
                            if(request==generation&&dialog!=null)dialog.setMessage("NFC: Token ruhig an der Antenne halten …");
                        }));
                io=transport;
                if(request!=generation){transport.close();return;}
                try(CtapTransport hid=transport){
                    FidoToken token=new FidoToken(hid,text->main.post(()->{if(request==generation&&dialog!=null)dialog.setMessage(nfcTag==null?text:text.replace("touch the token when it blinks.","hold the token against the NFC antenna."));}));
                        if(enroll){
                            FidoToken.Credential credential=token.create(pin,enrolled.credentials());
                            // Public common salt enables one assertion with an allowList. Each
                            // credential still yields its own independent hmac-secret/key.
                            byte[] salt=enrolled.entries.isEmpty()?Crypto.random(32):enrolled.entries.get(0).record.salt.clone();
                            secret=token.get(pin,credential,salt);
                            record=UnlockRecord.seal(db,credential,salt,secret,enrollmentPassword);
                            // Verify authenticated encryption before attempting database load.
                            unlocked=record.open(secret);
                        }else{
                            FidoToken.Assertion assertion=token.get(pin,biometricEntry==null?enrolled.credentials():
                                    Collections.singletonList(biometricEntry.record.credential),enrolled.entries.get(0).record.salt);
                            secret=assertion.secret;
                            record=enrolled.find(assertion.credential.id).record;
                            unlocked=record.open(secret);
                        }
                }finally{io=null;}
                final char[] result=unlocked;unlocked=null;
                final UnlockRecord candidate=enroll?record:null;
                final EnrollmentSet.Entry savedEntry=savePin?enrolled.find(record.credential.id):null;
                final byte[] verifiedPin=savePin?pin.clone():null;
                main.post(()->{
                    if(request!=generation||activity.isFinishing()){Arrays.fill(result,'\0');Crypto.wipe(verifiedPin);return;}
                    if(nfcTag!=null)stopNfcReader();
                    if(dialog!=null){dialog.dismiss();dialog=null;}
                    if(savePin){
                        // Keep the recovered password owned by cancel() while the prompt is visible.
                        password=result;
                        biometricPin.authenticate(savedEntry,verifiedPin,new BiometricPin.Callback(){
                            public void complete(byte[] unused){
                                Crypto.wipe(unused);
                                if(request!=generation)return;
                                password=null;message("Token PIN für Fingerprint gespeichert.");
                                deliver(result,candidate,requestKeyFile);
                            }
                            public void failed(){if(request==generation){cancel();message("PIN nicht gespeichert. Token PIN bleibt manuell nutzbar.");}}
                        });
                    }else deliver(result,candidate,requestKeyFile);
                });
            }catch(Exception e){main.post(()->{if(request==generation){
                if(biometricEntry!=null&&e.getMessage()!=null&&e.getMessage().startsWith("CTAP 0x31")){
                    try{biometricPin.remove(biometricEntry.record);}catch(Exception ignored){}
                }
                cancel();message(e.getMessage());
            }});}
            finally{Crypto.wipe(pin);Crypto.wipe(secret);if(unlocked!=null)Arrays.fill(unlocked,'\0');if(enrollmentPassword!=null)Arrays.fill(enrollmentPassword,'\0');}
        });
    }
    private void deliver(char[] result,UnlockRecord candidate,Uri requestKeyFile){
        try {
            proofKey=Crypto.random(32);
            byte[] encoded=UnlockRecord.encodeChars(result);
            try { passwordProof=Crypto.hmac(proofKey,encoded); } finally { Crypto.wipe(encoded); }
        } catch(Exception error) { Arrays.fill(result,'\0');cancel();message("Cannot verify pending enrollment.");return; }
        pending=candidate;waitingDatabase=true;
        callback.unlock(result,requestKeyFile);
    }
    public void databaseResult(Uri completedDatabase,char[] completedPassword,Uri completedKeyFile,boolean success){
        if(!waitingDatabase)return;
        byte[] encoded=null,proof=null;
        try {
            if(!Objects.equals(keyFile,completedKeyFile)||completedDatabase==null||!database.equals(completedDatabase.toString())||completedPassword==null) { cancel();return; }
            encoded=UnlockRecord.encodeChars(completedPassword);proof=Crypto.hmac(proofKey,encoded);
            if(!MessageDigest.isEqual(passwordProof,proof)){cancel();return;}
        }catch(Exception error){cancel();return;}
        finally{Crypto.wipe(encoded);Crypto.wipe(proof);}
        UnlockRecord record=pending;pending=null;waitingDatabase=false;
        try{
            if(success&&record!=null){
                EnrollmentStorage.replace(activity,snapshot,snapshot.add(tokenName,record));
                message("Token hinzugefügt. Master Password und gegebenenfalls Key File für Recovery behalten.");
            }else if(!success)message("Database unlock failed. Enrollment was not changed. Use the master password.");
        }catch(Exception e){message("Database opened, but enrollment could not be saved.");}
        finally{cancel();}
    }
    public void remove(Uri uri){
        if(uri==null||busy)return;
        try{
            final EnrollmentSet current=EnrollmentStorage.read(activity,uri.toString());
            if(current.entries.isEmpty()){message("Keine Tokens für diese Datenbank gespeichert.");return;}
            String[] names=new String[current.entries.size()];
            for(int i=0;i<names.length;i++)names[i]=current.entries.get(i).name;
            dialog=new AlertDialog.Builder(activity).setTitle("Tokens verwalten ("+names.length+"/5)")
                .setItems(names,(d,which)->{
                    final EnrollmentSet.Entry selected=current.entries.get(which);
                    dialog=new AlertDialog.Builder(activity).setTitle("Token entfernen: "+selected.name+"?")
                        .setMessage(current.entries.size()==1
                            ?"Dies ist der letzte lokale Token-Zugang. Master Password und gegebenenfalls Key File bleiben erforderlich. Datenbank und Token werden nicht verändert."
                            :"Nur dieses Enrollment auf diesem Gerät wird entfernt. Andere Tokens, Datenbank und Key File bleiben unverändert.")
                        .setNegativeButton("Cancel",null).setPositiveButton("Entfernen",(confirm,w)->{
                            try{
                                EnrollmentStorage.replace(activity,current,current.remove(selected.record.credential.id));
                                biometricPin.remove(selected.record);
                                message("Lokales Token-Enrollment entfernt.");
                            }catch(Exception e){message(e.getMessage());}
                        }).create();
                    dialog.show();
                }).setNegativeButton("Cancel",null).create();
            dialog.show();
        }catch(Exception e){message("Cannot read token enrollments. "+e.getMessage());}
    }
    public void cancel(){
        biometricPin.cancel();savePinRequested=false;fingerprintEntry=null;
        Crypto.wipe(pendingPin);pendingPin=null;
        keyFile=null;snapshot=null;tokenName=null;
        generation++;busy=false;waitingDatabase=false;pending=null;device=null;
        Crypto.wipe(proofKey);Crypto.wipe(passwordProof);proofKey=null;passwordProof=null;
        CtapTransport active=io;if(active!=null)active.close();
        stopNfcReader();
        if(password!=null)Arrays.fill(password,'\0');password=null;
        if(dialog!=null){dialog.setOnCancelListener(null);dialog.dismiss();dialog=null;}
    }
    public void close(){cancel();activity.unregisterReceiver(receiver);worker.shutdownNow();}
    private void message(String text){Toast.makeText(activity,text==null?"Token operation failed.":text,Toast.LENGTH_LONG).show();}
}
