package com.kunzisoft.keepass.fido2;

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Token2
// Adapted from ordanexa/fidoparole-mobile core/src/ctap/nfc.rs (blob f73df85d).
// License and attribution are packaged in assets/licenses/Token2-FidoParole-MIT.txt.
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/** ISO 7816 short APDUs, command chaining, GET RESPONSE and NFC keepalive polling. */
final class NfcTransport implements CtapTransport {
    interface Channel extends AutoCloseable {
        byte[] transmit(byte[] apdu) throws Exception;
        default int maxLength() { return 261; }
        void close();
    }
    static final byte[] SELECT={(byte)0x00,(byte)0xa4,0x04,0x00,0x08,
            (byte)0xa0,0x00,0x00,0x06,0x47,0x2f,0x00,0x01,0x00};
    static final int MAX_MESSAGE=7609,MAX_RESPONSES=512;
    private final Channel channel;
    private final Runnable processing;
    private volatile boolean closed;
    private boolean initialized;
    NfcTransport(Channel channel,Runnable processing) { this.channel=channel;this.processing=processing; }
    private static final class Reply {
        final byte[] data;final int status;
        Reply(byte[] raw)throws IOException {
            if(raw==null||raw.length<2)throw new IOException("NFC: response without status word.");
            data=Arrays.copyOf(raw,raw.length-2);
            status=((raw[raw.length-2]&255)<<8)|(raw[raw.length-1]&255);
        }
    }
    private void check(long deadline)throws IOException {
        if(closed||Thread.currentThread().isInterrupted())throw new IOException("NFC operation cancelled.");
        if(System.nanoTime()>=deadline)throw new IOException("NFC timeout. Hold the token still and try again.");
    }
    private Reply transmit(byte[] command,long deadline)throws Exception {
        check(deadline);
        if(command.length>channel.maxLength())throw new IOException("NFC reader APDU limit is too small.");
        Reply reply=new Reply(channel.transmit(command));check(deadline);return reply;
    }
    private Reply fullResponse(byte[] command,long deadline)throws Exception {
        Reply reply=transmit(command,deadline);
        ByteArrayOutputStream data=new ByteArrayOutputStream();
        for(int count=0;;count++) {
            if(count>=MAX_RESPONSES||data.size()+reply.data.length>MAX_MESSAGE)
                throw new IOException("NFC response exceeds safe limits.");
            data.write(reply.data);
            if((reply.status>>>8)!=0x61)return new Reply(Crypto.cat(data.toByteArray(),new byte[]{(byte)(reply.status>>>8),(byte)reply.status}));
            reply=transmit(new byte[]{(byte)(command[0]&0x80),(byte)0xc0,0x00,0x00,(byte)reply.status},deadline);
        }
    }
    public void init()throws Exception {
        initialized=false;
        Reply reply=fullResponse(SELECT.clone(),System.nanoTime()+60_000_000_000L);
        if(reply.status!=0x9000||(!Arrays.equals(reply.data,Crypto.utf8("FIDO_2_0"))
                &&!Arrays.equals(reply.data,Crypto.utf8("U2F_V2"))))
            throw new IOException("This NFC tag has no compatible FIDO applet.");
        // Dual-protocol keys return U2F_V2. FidoToken then requires CTAP2 GetInfo,
        // hmac-secret and clientPin before sending PIN authorization.
        initialized=true;
    }
    public byte[] cbor(byte[] request)throws Exception {
        if(!initialized)throw new IOException("NFC applet has not been selected.");
        if(request.length==0||request.length>MAX_MESSAGE)throw new IOException("Invalid NFC request size.");
        long deadline=System.nanoTime()+60_000_000_000L;
        int chunk=Math.min(255,channel.maxLength()-6);
        if(chunk<1)throw new IOException("NFC reader APDU limit is too small.");
        Reply reply=null;
        for(int offset=0;offset<request.length;offset+=chunk) {
            int size=Math.min(chunk,request.length-offset);boolean last=offset+size==request.length;
            byte[] apdu=new byte[5+size+(last?1:0)];
            apdu[0]=(byte)(last?0x80:0x90);apdu[1]=0x10;apdu[2]=(byte)(last?0x80:0x00);apdu[4]=(byte)size;
            System.arraycopy(request,offset,apdu,5,size);
            reply=fullResponse(apdu,deadline);
            if(!last&&(reply.status!=0x9000||reply.data.length!=0))throw new IOException("NFC command chain rejected.");
        }
        int polls=0;
        while(reply.status==0x9100) {
            if(++polls>600)throw new IOException("NFC processing timeout.");
            processing.run();
            Thread.sleep(50);
            // CTAP requires prompt polling; never repeat the original PIN/CTAP command.
            reply=fullResponse(new byte[]{(byte)0x80,0x11,0x00,0x00,0x00},deadline);
        }
        if(reply.status!=0x9000||reply.data.length==0)throw new IOException(String.format(java.util.Locale.ROOT,"NFC operation failed (SW %04X).",reply.status));
        return reply.data;
    }
    public void close() { closed=true;initialized=false;channel.close(); }
}
