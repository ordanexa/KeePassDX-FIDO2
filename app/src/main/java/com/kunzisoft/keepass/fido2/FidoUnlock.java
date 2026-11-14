package com.kunzisoft.keepass.fido2;

import android.app.*;
import android.content.*;
import android.hardware.usb.*;
import android.net.Uri;
import android.os.*;
import android.text.InputType;
import android.util.AtomicFile;
import android.view.*;
import android.widget.*;
import android.annotation.TargetApi;
import java.io.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

/** Activity-scoped coordinator. No new plaintext persistence; unlock uses the existing KeePassDX pipeline. */
@TargetApi(26)
public final class FidoUnlock {
    public interface Callback { void unlock(char[] password); }
    private final Activity activity;
    private final UsbManager manager;
    private final Handler main=new Handler(Looper.getMainLooper());
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private final String permissionAction;
    private final Callback callback;
    private volatile int generation;
    private volatile UsbIo io;
    private char[] password;
    private String database;
    private UsbDevice device;
    private boolean enrolling, busy;
    private AlertDialog dialog;
    private UnlockRecord pending;
    private boolean waitingDatabase;
    private byte[] proofKey, passwordProof;

    public FidoUnlock(Activity activity,Callback callback) {
        this.activity=activity;this.callback=callback;
        manager=(UsbManager)activity.getSystemService(Context.USB_SERVICE);
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
                if(manager.hasPermission(device))promptPin();else{cancel();message("USB permission denied.");}
            }
        }
    };
    private AtomicFile file(String db)throws Exception{ return EnrollmentStorage.file(activity,db); }
    public void begin(Uri uri,char[] suppliedPassword,boolean enroll){
        if(busy){if(suppliedPassword!=null)Arrays.fill(suppliedPassword,'\0');message("A token operation is already running.");return;}
        cancel();
        if(uri==null){if(suppliedPassword!=null)Arrays.fill(suppliedPassword,'\0');message("Select a database first.");return;}
        if(enroll&&(suppliedPassword==null||suppliedPassword.length==0)){
            if(suppliedPassword!=null)Arrays.fill(suppliedPassword,'\0');message("Enter the database master password first.");return;
        }
        database=uri.toString();enrolling=enroll;password=suppliedPassword;
        try{
            if(!enroll&&!file(database).getBaseFile().exists())throw new IOException("No token enrolled for this database on this device. Use Enroll USB token first.");
            List<UsbDevice> matches=new ArrayList<>();
            for(UsbDevice d:manager.getDeviceList().values())if(d.getVendorId()==0x349e&&d.getProductId()==0x0024)matches.add(d);
            if(matches.size()!=1)throw new IOException("Connect exactly one Token2 PIN+ Dual over USB-C.");
            device=matches.get(0);busy=true;
            if(manager.hasPermission(device))promptPin();
            else manager.requestPermission(device,PendingIntent.getBroadcast(activity,generation,
                    new Intent(permissionAction).setPackage(activity.getPackageName()),PendingIntent.FLAG_CANCEL_CURRENT|PendingIntent.FLAG_MUTABLE));
        }catch(Exception e){cancel();message(e.getMessage());}
    }
    private void promptPin(){
        if(!busy||activity.isFinishing())return;
        final EditText pin=new EditText(activity);
        pin.setHint("Token PIN");pin.setSingleLine(true);
        pin.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);
        pin.setSaveEnabled(false);pin.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        pin.setImeOptions(android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
        dialog=new AlertDialog.Builder(activity).setTitle(enrolling?"Enroll USB token":"Unlock with USB token")
                .setMessage("Enter the token PIN. Touch the token when it blinks. No automatic PIN retries.")
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
        final int request=generation;
        final String db=database;
        final boolean enroll=enrolling;
        final UsbDevice selected=device;
        final char[] enrollmentPassword=password;password=null;
        dialog=new AlertDialog.Builder(activity).setTitle("USB token")
                .setMessage("Connecting …").setNegativeButton("Cancel",(d,w)->cancel()).create();
        dialog.setOnCancelListener(d->cancel());dialog.show();dialog.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        worker.execute(()->{
            char[] unlocked=null;byte[] secret=null;UnlockRecord record=null;
            try{
                UsbIo transport=new UsbIo(manager,selected);io=transport;
                if(request!=generation){transport.close();return;}
                try(Hid hid=new Hid(transport)){
                    FidoToken token=new FidoToken(hid,text->main.post(()->{if(request==generation&&dialog!=null)dialog.setMessage(text);}));
                        if(enroll){
                            FidoToken.Credential credential=token.create(pin);
                            byte[] salt=Crypto.random(32);
                            secret=token.get(pin,credential,salt);
                            record=UnlockRecord.seal(db,credential,salt,secret,enrollmentPassword);
                            // Verify authenticated encryption before attempting database load.
                            unlocked=record.open(secret);
                        }else{
                            AtomicFile storage=file(db);
                            if(storage.getBaseFile().length()>32768)throw new IOException("Enrollment record too large");
                            record=UnlockRecord.decode(db,storage.readFully());
                            secret=token.get(pin,record.credential,record.salt);
                            unlocked=record.open(secret);
                        }
                }finally{io=null;}
                final char[] result=unlocked;unlocked=null;
                final UnlockRecord candidate=enroll?record:null;
                main.post(()->{
                    if(request!=generation||activity.isFinishing()){Arrays.fill(result,'\0');return;}
                    if(dialog!=null){dialog.dismiss();dialog=null;}
                    try {
                        proofKey=Crypto.random(32);
                        byte[] encoded=UnlockRecord.encodeChars(result);
                        try { passwordProof=Crypto.hmac(proofKey,encoded); } finally { Crypto.wipe(encoded); }
                    } catch(Exception error) { Arrays.fill(result,'\0');cancel();message("Cannot verify pending enrollment.");return; }
                    pending=candidate;waitingDatabase=true;
                    // Ownership of result transfers to KeePassDX's existing credential pipeline.
                    callback.unlock(result);
                });
            }catch(Exception e){main.post(()->{if(request==generation){cancel();message(e.getMessage());}});}
            finally{Crypto.wipe(pin);Crypto.wipe(secret);if(unlocked!=null)Arrays.fill(unlocked,'\0');if(enrollmentPassword!=null)Arrays.fill(enrollmentPassword,'\0');}
        });
    }
    public void databaseResult(Uri completedDatabase,char[] completedPassword,boolean success){
        if(!waitingDatabase)return;
        byte[] encoded=null,proof=null;
        try {
            if(completedDatabase==null||!database.equals(completedDatabase.toString())||completedPassword==null) { cancel();return; }
            encoded=UnlockRecord.encodeChars(completedPassword);proof=Crypto.hmac(proofKey,encoded);
            if(!MessageDigest.isEqual(passwordProof,proof)){cancel();return;}
        }catch(Exception error){cancel();return;}
        finally{Crypto.wipe(encoded);Crypto.wipe(proof);}
        UnlockRecord record=pending;pending=null;waitingDatabase=false;
        try{
            if(success&&record!=null){
                AtomicFile storage=file(record.database);FileOutputStream stream=null;
                try{stream=storage.startWrite();stream.write(record.encode());storage.finishWrite(stream);}
                catch(Exception e){if(stream!=null)storage.failWrite(stream);throw e;}
                UnlockRecord.decode(record.database,storage.readFully());
                message("USB token enrolled. Keep your master password for recovery.");
            }else if(!success)message("Database unlock failed. Enrollment was not changed. Use the master password.");
        }catch(Exception e){message("Database opened, but enrollment could not be saved.");}
        finally{cancel();}
    }
    public void remove(Uri uri){
        if(uri==null||busy)return;
        new AlertDialog.Builder(activity).setTitle("Remove local token enrollment?")
                .setMessage("The database and token remain unchanged. You will need the master password.")
                .setNegativeButton("Cancel",null).setPositiveButton("Remove",(d,w)->{
                    try{file(uri.toString()).delete();message("Local enrollment removed.");}catch(Exception e){message("Could not remove enrollment.");}
                }).show();
    }
    public void cancel(){
        generation++;busy=false;waitingDatabase=false;pending=null;device=null;
        Crypto.wipe(proofKey);Crypto.wipe(passwordProof);proofKey=null;passwordProof=null;
        UsbIo active=io;if(active!=null)active.close();
        if(password!=null)Arrays.fill(password,'\0');password=null;
        if(dialog!=null){dialog.setOnCancelListener(null);dialog.dismiss();dialog=null;}
    }
    public void close(){cancel();activity.unregisterReceiver(receiver);worker.shutdownNow();}
    private void message(String text){Toast.makeText(activity,text==null?"Token operation failed.":text,Toast.LENGTH_LONG).show();}
}
