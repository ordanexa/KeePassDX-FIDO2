package com.kunzisoft.keepass.fido2;

import java.util.Objects;

/** One automatic prompt per database/login screen; explicit manual choices win. */
public final class FidoLoginPolicy {
    private String database;
    private boolean automaticUsed,manualPin;
    public void selectDatabase(String selected) {
        if(!Objects.equals(database,selected)){database=selected;automaticUsed=false;manualPin=false;}
    }
    public static boolean preferNfc(Boolean explicitChoice,boolean nfcReady) {
        return nfcReady&&!Boolean.FALSE.equals(explicitChoice);
    }
    public boolean claimAutomatic(boolean foreground,boolean metadataReady,boolean tokenMode,boolean savedPin,boolean busy) {
        if(database==null||automaticUsed||manualPin||!foreground||!metadataReady||!tokenMode||!savedPin||busy)return false;
        automaticUsed=true;return true;
    }
    public boolean prefersFingerprint(boolean savedPin){return savedPin&&!manualPin;}
    public boolean isAutomaticPending(){return !automaticUsed&&!manualPin;}
    public void useManualPin(){manualPin=true;automaticUsed=true;}
    public void useFingerprint(){manualPin=false;automaticUsed=true;}
    public void suppressAutomatic(){automaticUsed=true;}
    public void useDefaultMethod(){manualPin=false;automaticUsed=false;}
    public String getDatabase(){return database;}
    public boolean isAutomaticUsed(){return automaticUsed;}
    public boolean isManualPin(){return manualPin;}
    public void restore(String database,boolean used,boolean manual){this.database=database;automaticUsed=used;manualPin=manual;}
}
