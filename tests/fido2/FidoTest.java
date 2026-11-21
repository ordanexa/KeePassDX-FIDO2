package com.kunzisoft.keepass.fido2;
import java.io.*;
import java.nio.*;
import java.util.*;
public final class FidoTest {
    static int checks;
    static void check(boolean ok,String label){checks++;if(!ok)throw new AssertionError(label);}
    interface Attempt{void run()throws Exception;}
    static void rejects(Attempt a,String label)throws Exception{try{a.run();}catch(Exception expected){checks++;return;}throw new AssertionError(label);}
    static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte v:b)s.append(String.format("%02x",v&255));return s.toString();}
    static byte[] unhex(String s){if(s==null)throw new AssertionError("Simulator stopped");byte[] b=new byte[s.length()/2];for(int i=0;i<b.length;i++)b[i]=(byte)Integer.parseInt(s.substring(2*i,2*i+2),16);return b;}
    static final class Sim implements Hid.Io{
        final Process process;final BufferedReader read;final PrintWriter write;final Queue<byte[]> packets=new ArrayDeque<>();
        ByteArrayOutputStream request;int length,command,channel,sequence;
        Sim(String mode)throws Exception{process=new ProcessBuilder(System.getenv().getOrDefault("FIDO_TEST_PYTHON","python3"),"tests/fido2/authenticator.py",mode).redirectError(ProcessBuilder.Redirect.INHERIT).start();read=new BufferedReader(new InputStreamReader(process.getInputStream()));write=new PrintWriter(process.getOutputStream(),true);}
        public void write(byte[] packet,long deadline)throws Exception{
            int tag=packet[4]&255;int cid=ByteBuffer.wrap(packet).getInt();
            if((tag&128)!=0){channel=cid;command=tag&127;length=((packet[5]&255)<<8)|(packet[6]&255);request=new ByteArrayOutputStream();sequence=0;request.write(packet,7,Math.min(57,length));}
            else{check(cid==channel&&tag==sequence++,"request framing sequence");request.write(packet,5,Math.min(59,length-request.size()));}
            if(request.size()==length){byte[] response;
                if(command==6)response=Crypto.cat(request.toByteArray(),ByteBuffer.allocate(4).putInt(0x12345678).array(),new byte[]{2,1,0,0,4});
                else{check(command==16,"only INIT/CBOR");write.println(hex(request.toByteArray()));response=unhex(read.readLine());}
                // Exercise keepalive packets and HID fragmentation for each response.
                byte[] keep=new byte[64];ByteBuffer.wrap(keep).putInt(channel);keep[4]=(byte)0xbb;keep[6]=1;keep[7]=2;packets.add(keep);
                int p=0,seq=0;byte[] out=new byte[64];ByteBuffer.wrap(out).putInt(channel);out[4]=(byte)(command|128);out[5]=(byte)(response.length>>>8);out[6]=(byte)response.length;int n=Math.min(57,response.length);System.arraycopy(response,0,out,7,n);p=n;packets.add(out);
                while(p<response.length){out=new byte[64];ByteBuffer.wrap(out).putInt(channel);out[4]=(byte)seq++;n=Math.min(59,response.length-p);System.arraycopy(response,p,out,5,n);p+=n;packets.add(out);}
            }
        }
        public byte[] read(long deadline){return packets.remove();}
        public void close(){write.close();try{if(!process.waitFor(2,java.util.concurrent.TimeUnit.SECONDS))process.destroyForcibly();}catch(InterruptedException e){process.destroyForcibly();}}
    }

    // APDU framing fixture bridges complete messages to the independent Python authenticator.
    static final class NfcSim implements NfcTransport.Channel {
        final Hid backend;final ByteArrayOutputStream request=new ByteArrayOutputStream();
        byte[] response;int position;
        NfcSim(String mode)throws Exception { backend=new Hid(new Sim(mode));backend.init(); }
        public int maxLength(){return 80;}
        byte[] part(){
            int count=Math.min(37,response.length-position);
            byte[] data=Arrays.copyOfRange(response,position,position+count);position+=count;
            int remaining=response.length-position;
            return Crypto.cat(data,remaining==0?new byte[]{(byte)0x90,0x00}:new byte[]{0x61,(byte)Math.min(remaining,256)});
        }
        public byte[] transmit(byte[] apdu)throws Exception {
            if(Arrays.equals(apdu,NfcTransport.SELECT))return Crypto.cat(Crypto.utf8("U2F_V2"),new byte[]{(byte)0x90,0x00});
            int instruction=apdu[1]&255;
            if(instruction==0x11){check((apdu[0]&255)==0x80,"NFC processing poll CLA");return part();}
            if(instruction==0xc0){check((apdu[0]&255)==0x80,"NFC GET RESPONSE CLA");return part();}
            check(instruction==0x10,"NFC CTAP command");
            int size=apdu[4]&255;boolean last=(apdu[0]&255)==0x80;
            check(apdu.length==5+size+(last?1:0),"NFC request length");
            check((apdu[2]&255)==(last?0x80:0),"NFC keepalive support flag");
            request.write(apdu,5,size);
            if(!last)return new byte[]{(byte)0x90,0x00};
            response=backend.cbor(request.toByteArray());request.reset();position=0;
            return new byte[]{0x01,(byte)0x91,0x00};
        }
        public void close(){backend.close();}
    }

    public static void main(String[] args)throws Exception{
        for(boolean nfc:new boolean[]{false,true})
        for(String mode:new String[]{"v1","v2","reauth_rejected","wrong_pin","low_retries","no_hmac","create_no_uv","no_uv","no_up","wrong_rp","wrong_signature","wrong_id","replay"}){
            byte[] pin=Crypto.utf8("123456");
            try(CtapTransport hid=nfc?new NfcTransport(new NfcSim(mode),()->{}):new Hid(new Sim(mode))){
                FidoToken token=new FidoToken(hid,s->{});
                Attempt flow=()->{
                    try{
                        FidoToken.Credential credential=token.create(pin);
                        byte[] salt=Crypto.random(32),secret=token.get(pin,credential,salt);
                        char[] password="Test-ä-🔐-password".toCharArray();
                        UnlockRecord record=UnlockRecord.seal("content://test/database",credential,salt,secret,password);
                        byte[] second=token.get(pin,credential,salt);
                        check(Arrays.equals(secret,second),"stable hmac-secret");
                        UnlockRecord read=UnlockRecord.decode(record.database,record.encode());
                        check(Arrays.equals(password,read.open(second)),"password roundtrip "+mode);
                        rejects(()->read.open(new byte[32]),"wrong secret");
                        read.ciphertext[0]^=1;
                        rejects(()->read.open(secret),"tampered ciphertext");
                        rejects(()->UnlockRecord.decode("content://other",record.encode()),"wrong database");
                        Crypto.wipe(secret);Crypto.wipe(second);Arrays.fill(password,'\0');
                    } finally { Crypto.wipe(pin); }
                };
                if(mode.equals("v1")||mode.equals("v2"))flow.run();else rejects(flow,"must reject "+mode);
                check(Arrays.equals(pin,new byte[pin.length]),"PIN wiped");
            }
            System.out.println("PASS "+(nfc?"NFC ":"USB ")+mode);
        }
        // Real wire-format allowList selection, signature validation and duplicate exclusion.
        for(String mode:new String[]{"v1","v2"}){
            try(Hid hid=new Hid(new Sim(mode))){
                FidoToken token=new FidoToken(hid,s->{});byte[] pin=Crypto.utf8("123456");
                FidoToken.Credential actual=token.create(pin);byte[] salt=Crypto.random(32);
                byte[] reference=token.get(pin,actual,salt);
                for(int position=0;position<5;position++){
                    List<FidoToken.Credential> candidates=new ArrayList<>();
                    for(int i=0;i<5;i++)candidates.add(i==position?actual:new FidoToken.Credential(Crypto.random(32),actual.publicKey));
                    FidoToken.Assertion result=token.get(pin,candidates,salt);
                    check(Arrays.equals(result.credential.id,actual.id),"select matching token at position "+position);
                    check(Arrays.equals(result.secret,reference),"independent list selection preserves secret");
                    Crypto.wipe(result.secret);
                }
                try{token.create(pin,Collections.singletonList(actual));throw new AssertionError("duplicate token allowed");}
                catch(IOException expected){check(expected.getMessage().contains("0x19"),"duplicate rejected by excludeList");}
                try{token.get(pin,Collections.singletonList(new FidoToken.Credential(Crypto.random(32),actual.publicKey)),salt);throw new AssertionError("unknown token allowed");}
                catch(IOException expected){check(expected.getMessage().contains("0x2e"),"unknown token rejected without retry");}
                Crypto.wipe(reference);Crypto.wipe(pin);
            }
        }
        // Regression: the simulator must reject reuse after MakeCredential.
        try(Hid hid=new Hid(new Sim("v2"))){
            FidoToken token=new FidoToken(hid,s->{});
            try(FidoToken.Session session=token.new Session(Crypto.utf8("123456"),true)){
                FidoToken.Credential credential=token.create(session);
                try { token.get(session,credential,Crypto.random(32));throw new AssertionError("Consumed authorization accepted"); }
                catch(IOException expected){check(expected.getMessage().contains("0x33"),"consumed authorization returns 0x33");}
            }
        }
        rejects(()->Cbor.decode(new byte[]{(byte)0xa2,1,2,1,3}),"duplicate CBOR keys");
        rejects(()->Cbor.decode(new byte[]{0,0}),"trailing CBOR");
        rejects(()->Cbor.decode(new byte[]{(byte)0x9f,(byte)0xff}),"indefinite CBOR");
        System.out.println("PASS "+checks+" checks");
    }
}

