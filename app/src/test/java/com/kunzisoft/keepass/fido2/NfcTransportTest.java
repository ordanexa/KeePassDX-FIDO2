package com.kunzisoft.keepass.fido2;

import java.io.IOException;
import java.util.*;
import org.junit.Test;
import static org.junit.Assert.*;

public class NfcTransportTest {
    static final byte[] OK={(byte)0x90,0x00};
    static class Link implements NfcTransport.Channel {
        final Queue<byte[]> replies=new ArrayDeque<>();
        final List<byte[]> sent=new ArrayList<>();boolean closed;int limit=261;
        Link(byte[]... replies){this.replies.add(Crypto.cat(Crypto.utf8("FIDO_2_0"),OK));this.replies.addAll(Arrays.asList(replies));}
        public byte[] transmit(byte[] apdu){if(closed)throw new IllegalStateException("Closed");sent.add(apdu.clone());return replies.remove();}
        public int maxLength(){return limit;}
        public void close(){closed=true;}
    }
    @Test public void chainsWithinReadersLimitAndAdvertisesProcessingSupport()throws Exception {
        Link link=new Link(OK,OK,new byte[]{0x00,(byte)0x90,0x00});link.limit=100;
        try(NfcTransport nfc=new NfcTransport(link,()->{})){
            nfc.init();assertArrayEquals(new byte[]{0},nfc.cbor(new byte[200]));
            assertArrayEquals(NfcTransport.SELECT,link.sent.get(0));
            assertEquals(4,link.sent.size());
            assertEquals(0x90,link.sent.get(1)[0]&255);
            assertEquals(0x80,link.sent.get(3)[0]&255);
            assertEquals(0x80,link.sent.get(3)[2]&255);
            for(byte[] command:link.sent)assertTrue(command.length<=100);
        }
        assertTrue(link.closed);
    }
    @Test public void keepalivePollAndFragmentedResponseDoNotRepeatTheCommand()throws Exception {
        Link link=new Link(new byte[]{0x01,(byte)0x91,0x00},new byte[]{0x00,0x11,0x61,0x01},new byte[]{0x22,(byte)0x90,0x00});
        int[] polls={0};try(NfcTransport nfc=new NfcTransport(link,()->polls[0]++)){
            nfc.init();assertArrayEquals(new byte[]{0,0x11,0x22},nfc.cbor(new byte[]{4}));
            assertEquals(1,polls[0]);assertEquals(4,link.sent.size());
            assertArrayEquals(new byte[]{(byte)0x80,0x11,0,0,0},link.sent.get(2));
            assertArrayEquals(new byte[]{(byte)0x80,(byte)0xc0,0,0,1},link.sent.get(3));
        }
    }
    @Test public void badTagMalformedResponseAndStatusFailClosed()throws Exception {
        Link wrong=new Link();wrong.replies.clear();wrong.replies.add(new byte[]{0x6a,(byte)0x82});
        try(NfcTransport nfc=new NfcTransport(wrong,()->{})){assertThrows(IOException.class,nfc::init);}
        for(byte[] reply:new byte[][]{new byte[]{1},new byte[]{0x6a,(byte)0x80},OK}){
            try(NfcTransport nfc=new NfcTransport(new Link(reply),()->{})){
                nfc.init();assertThrows(IOException.class,()->nfc.cbor(new byte[]{4}));
            }
        }
    }
    @Test public void rejectsOversizedRequestsBeforeSendingAnyCtapCommand()throws Exception {
        Link link=new Link();try(NfcTransport nfc=new NfcTransport(link,()->{})){
            nfc.init();assertThrows(IOException.class,()->nfc.cbor(new byte[NfcTransport.MAX_MESSAGE+1]));
            assertEquals(1,link.sent.size());
        }
    }
    @Test public void unboundedResponseChainingIsStopped()throws Exception {
        Link link=new Link();for(int i=0;i<=NfcTransport.MAX_RESPONSES;i++)link.replies.add(new byte[]{0x61,0});
        try(NfcTransport nfc=new NfcTransport(link,()->{})){
            nfc.init();assertThrows(IOException.class,()->nfc.cbor(new byte[]{4}));
            assertTrue(link.sent.size()<=NfcTransport.MAX_RESPONSES+2);
        }
    }
    @Test public void cancellationDoesNotSendAnotherApdu()throws Exception {
        Link link=new Link();NfcTransport nfc=new NfcTransport(link,()->{});
        nfc.init();nfc.close();assertThrows(IOException.class,()->nfc.cbor(new byte[]{4}));
        assertEquals(1,link.sent.size());
    }
    @Test public void rejectedIntermediateFragmentStopsInsteadOfContinuing()throws Exception {
        Link link=new Link(new byte[]{0x6a,(byte)0x80});
        try(NfcTransport nfc=new NfcTransport(link,()->{})){
            nfc.init();assertThrows(IOException.class,()->nfc.cbor(new byte[400]));assertEquals(2,link.sent.size());
        }
    }
}
