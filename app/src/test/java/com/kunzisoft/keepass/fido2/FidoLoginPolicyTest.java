package com.kunzisoft.keepass.fido2;

import org.junit.Test;
import static org.junit.Assert.*;

public class FidoLoginPolicyTest {
    private FidoLoginPolicy policy(){FidoLoginPolicy p=new FidoLoginPolicy();p.selectDatabase("content://test/daily.kdbx");return p;}
    @Test public void enabledNfcIsDefaultButAnExplicitUsbChoiceWins(){
        assertTrue(FidoLoginPolicy.preferNfc(null,true));
        assertFalse(FidoLoginPolicy.preferNfc(null,false));
        assertFalse(FidoLoginPolicy.preferNfc(false,true));
        assertTrue(FidoLoginPolicy.preferNfc(true,true));
        assertFalse(FidoLoginPolicy.preferNfc(true,false));
    }
    @Test public void automaticFingerprintIsClaimedOnceDespiteRepeatedUiAndResumeEvents(){
        FidoLoginPolicy p=policy();
        assertTrue(p.claimAutomatic(true,true,true,true,false));
        for(int i=0;i<10;i++)assertFalse(p.claimAutomatic(true,true,true,true,false));
    }
    @Test public void waitsForForegroundMatchingMetadataTokenAndIdleStateWithoutConsumingAttempt(){
        FidoLoginPolicy p=policy();
        assertFalse(p.claimAutomatic(false,true,true,true,false));
        assertFalse(p.claimAutomatic(true,false,true,true,false));
        assertFalse(p.claimAutomatic(true,true,false,true,false));
        assertFalse(p.claimAutomatic(true,true,true,true,true));
        assertTrue(p.claimAutomatic(true,true,true,true,false));
    }
    @Test public void phoneBiometricsAloneCannotStartWithoutSavedTokenPin(){
        FidoLoginPolicy p=policy();
        assertFalse(p.prefersFingerprint(false));
        assertFalse(p.claimAutomatic(true,true,true,false,false));
        assertTrue(p.claimAutomatic(true,true,true,true,false));
    }
    @Test public void cancellationSelectsManualPinUntilExplicitFingerprintRequest(){
        FidoLoginPolicy p=policy();
        assertTrue(p.claimAutomatic(true,true,true,true,false));p.useManualPin();
        assertFalse(p.prefersFingerprint(true));
        assertFalse(p.claimAutomatic(true,true,true,true,false));
        p.useFingerprint();assertTrue(p.prefersFingerprint(true));
        assertFalse(p.claimAutomatic(true,true,true,true,false));
    }
    @Test public void setupAndRecoveryActionsSuppressBackgroundAutomaticPrompt(){
        FidoLoginPolicy p=policy();p.suppressAutomatic();
        assertFalse(p.claimAutomatic(true,true,true,true,false));
    }
    @Test public void sameDatabaseKeepsSuppressionButAnotherDatabaseHasItsOwnAttempt(){
        FidoLoginPolicy p=policy();p.useManualPin();p.selectDatabase("content://test/daily.kdbx");
        assertFalse(p.claimAutomatic(true,true,true,true,false));
        p.selectDatabase("content://test/other.kdbx");
        assertTrue(p.prefersFingerprint(true));assertTrue(p.claimAutomatic(true,true,true,true,false));
        p.selectDatabase(null);assertFalse(p.claimAutomatic(true,true,true,true,false));
    }
    @Test public void recreationPreservesUsedPromptAndManualFallback(){
        FidoLoginPolicy old=policy();old.useManualPin();
        FidoLoginPolicy restored=new FidoLoginPolicy();
        restored.restore(old.getDatabase(),old.isAutomaticUsed(),old.isManualPin());
        restored.selectDatabase(old.getDatabase());
        assertFalse(restored.prefersFingerprint(true));
        assertFalse(restored.claimAutomatic(true,true,true,true,false));
    }
    @Test public void explicitTransportChangeCanRequestOneNewDefaultAttempt(){
        FidoLoginPolicy p=policy();p.useManualPin();p.useDefaultMethod();
        assertTrue(p.prefersFingerprint(true));assertTrue(p.claimAutomatic(true,true,true,true,false));
        assertFalse(p.claimAutomatic(true,true,true,true,false));
    }
}
