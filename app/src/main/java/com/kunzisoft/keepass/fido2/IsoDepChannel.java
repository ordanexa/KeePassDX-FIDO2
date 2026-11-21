package com.kunzisoft.keepass.fido2;

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Token2
// Adapted from fidoparole-mobile keys/NfcFido.kt (blob 3a2f60a7).
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import java.io.IOException;

final class IsoDepChannel implements NfcTransport.Channel {
    private final IsoDep iso;
    IsoDepChannel(Tag tag)throws IOException {
        iso=IsoDep.get(tag);
        if(iso==null)throw new IOException("This NFC tag does not support ISO-DEP/FIDO.");
        try { iso.connect();iso.setTimeout(10_000); }
        catch(IOException error){close();throw new IOException("NFC connection failed. Hold the token flat against the phone.",error);}
    }
    public byte[] transmit(byte[] apdu)throws IOException {
        try{return iso.transceive(apdu);}
        catch(IOException error){throw new IOException("NFC token disconnected. Hold it still and start again.",error);}
    }
    public int maxLength(){return iso.getMaxTransceiveLength();}
    public void close(){try{iso.close();}catch(IOException ignored){}}
}
