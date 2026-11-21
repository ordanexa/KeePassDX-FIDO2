package com.kunzisoft.keepass.fido2;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.*;

/** Shared USB/NFC CTAP client. No reset, PIN writes, largeBlob or credential-management commands. */
final class FidoToken {
    static final String RP = "keepassdx-fido2.ordanexa.com";
    interface Progress { void update(String message); }
    final CtapTransport hid;
    final Progress progress;
    FidoToken(CtapTransport hid, Progress progress) { this.hid = hid; this.progress = progress; }

    static final class Credential {
        final byte[] id, publicKey;
        Credential(byte[] id, byte[] publicKey) { this.id = id; this.publicKey = publicKey; }
    }

    Object command(int cmd, Map<Object,Object> args) throws Exception {
        if (cmd != 1 && cmd != 2 && cmd != 4 && cmd != 6) throw new IOException("CTAP operation blocked");
        if (cmd == 6) {
            long sub = Cbor.number(Cbor.get(args, 2));
            if (sub != 1 && sub != 2 && sub != 5 && sub != 9) throw new IOException("PIN write blocked");
            if (sub == 9 && (!RP.equals(Cbor.get(args,10)) || (Cbor.number(Cbor.get(args,9)) & ~3) != 0))
                throw new IOException("Invalid PIN permissions");
        }
        byte[] request = args.isEmpty() ? new byte[]{(byte)cmd} : Crypto.cat(new byte[]{(byte)cmd}, Cbor.encode(args));
        byte[] reply = hid.cbor(request);
        if (reply.length == 0) throw new IOException("Empty CTAP reply");
        int status = reply[0] & 255;
        if (status != 0) {
            String reason;
            switch (status) {
                case 0x19: reason = "This token is already enrolled for this database. Existing enrollment was kept."; break;
                case 0x15: reason = "Token credential-list capacity exceeded. Existing enrollments were kept."; break;
                case 0x31: reason = "Incorrect PIN. No automatic retry."; break;
                case 0x33: reason = "PIN authorization rejected. Enrollment/unlock stopped; no automatic retry."; break;
                case 0x32: reason = "PIN blocked. Do not reset the token."; break;
                case 0x34: reason = "PIN temporarily blocked. Reconnect the token."; break;
                case 0x2e: reason = "This token has no matching credential."; break;
                case 0x2f: reason = "Touch cancelled or timed out."; break;
                default: reason = "Token operation failed.";
            }
            throw new IOException(String.format("CTAP 0x%02x (command 0x%02x): %s", status, cmd, reason));
        }
        return reply.length == 1 ? Cbor.map() : Cbor.decode(Arrays.copyOfRange(reply,1,reply.length));
    }

    final class Session implements AutoCloseable {
        final int version;
        final long maxCredentials;
        byte[] token;
        Session(byte[] pin, boolean enroll) throws Exception {
            int selected = 0;
            try {
                hid.init();
                Object info = command(4,Cbor.map()), options = Cbor.get(info,4);
                Object exts = Cbor.get(info,2), protocols = Cbor.get(info,6);
                Object limit=Cbor.get(info,7);maxCredentials=limit==null?Long.MAX_VALUE:Cbor.number(limit);
                if (!(exts instanceof List) || !((List<?>)exts).contains("hmac-secret"))
                    throw new IOException("Token does not support hmac-secret");
                if (!Boolean.TRUE.equals(Cbor.get(options,"clientPin"))) throw new IOException("Token PIN is not configured");
                if (protocols instanceof List) selected = ((List<?>)protocols).contains(2L) ? 2 : ((List<?>)protocols).contains(1L) ? 1 : 0;
                if (selected == 0) throw new IOException("Unsupported PIN protocol");
                version = selected;
                long retries = Cbor.number(Cbor.get(command(6,Cbor.map(1,version,2,1)),3));
                if (retries <= 2) throw new IOException("Two or fewer PIN attempts remain. Verify your PIN independently.");
                progress.update("Checking PIN. No automatic retries.");
                Object peer = Cbor.get(command(6,Cbor.map(1,version,2,2)),1);
                try (Crypto.Agreement a = new Crypto.Agreement(version,peer)) {
                    byte[] digest = Crypto.sha(pin), shortHash = Arrays.copyOf(digest,16);
                    byte[] encrypted;
                    try { encrypted = a.encrypt(shortHash); } finally { Crypto.wipe(digest); Crypto.wipe(shortHash); }
                    boolean scoped = Boolean.TRUE.equals(Cbor.get(options,"pinUvAuthToken"));
                    Map<Object,Object> args = Cbor.map(1,version,2,scoped ? 9 : 5,3,a.publicKey,6,encrypted);
                    if (scoped) { args.put(9L,enroll ? 1L : 2L); args.put(10L,RP); }
                    token = a.decrypt(Cbor.bytes(Cbor.get(command(6,args),2)));
                    if ((version == 2 && token.length != 32) || (version == 1 && token.length != 16 && token.length != 32))
                        throw new IOException("Invalid PIN token");
                }
            } catch (Exception e) { Crypto.wipe(token); throw e; }
            finally { Crypto.wipe(pin); }
        }
        byte[] auth(byte[] hash) throws Exception {
            byte[] mac = Crypto.hmac(token,hash);
            if (version == 2) return mac;
            try { return Arrays.copyOf(mac,16); } finally { Crypto.wipe(mac); }
        }
        public void close() { Crypto.wipe(token); token = null; }
    }

    // Each UV operation consumes its authorization. Reauthenticate for the next
    // operation instead of reusing a token whose UV flag/permissions were cleared.
    // PIN bytes remain only with the caller for this bounded flow and are wiped there.
    Credential create(byte[] pin) throws Exception { return create(pin,Collections.emptyList()); }
    Credential create(byte[] pin,List<Credential> excluded) throws Exception {
        try (Session session = new Session(pin.clone(), true)) { return create(session,excluded); }
    }
    byte[] get(byte[] pin, Credential credential, byte[] salt) throws Exception {
        try (Session session = new Session(pin.clone(), false)) { return get(session, credential, salt); }
    }

    Credential create(Session session) throws Exception { return create(session,Collections.emptyList()); }
    static List<Object> descriptors(Session session,List<Credential> credentials)throws IOException {
        if(credentials.size()>5||credentials.size()>session.maxCredentials)throw new IOException("Token does not support this credential-list size.");
        List<Object> list=new ArrayList<>();
        for(Credential credential:credentials)list.add(Cbor.map("type","public-key","id",credential.id));
        return list;
    }
    Credential create(Session session,List<Credential> excluded) throws Exception {
        if(excluded.size()+1>session.maxCredentials)throw new IOException("Token cannot unlock a list with this additional enrollment.");
        byte[] hash = Crypto.random(32);
        progress.update("Create credential: touch the token when it blinks.");
        Map<Object,Object> args=Cbor.map(
                1,hash, 2,Cbor.map("id",RP,"name","KeePassDX FIDO2 test"),
                3,Cbor.map("id",Crypto.random(32),"name","Local database unlock","displayName","Local database unlock"),
                4,Collections.singletonList(Cbor.map("type","public-key","alg",-7)),
                6,Cbor.map("hmac-secret",true), 7,Cbor.map("rk",false),
                8,session.auth(hash),9,session.version);
        if(!excluded.isEmpty())args.put(5L,descriptors(session,excluded));
        Object response=command(1,args);
        byte[] ad = Cbor.bytes(Cbor.get(response,2));
        checkAuthData(ad,0xC5);
        if (ad.length < 56) throw new IOException("Truncated attested credential");
        int length = ((ad[53]&255)<<8)|(ad[54]&255);
        if (length < 1 || length > 4096 || ad.length < 55+length) throw new IOException("Invalid credential ID");
        byte[] id = Arrays.copyOfRange(ad,55,55+length);
        Cbor.Reader reader = new Cbor.Reader(ad,55+length);
        Object cose = reader.read(0);
        if (Cbor.number(Cbor.get(cose,1)) != 2 || Cbor.number(Cbor.get(cose,3)) != -7 || Cbor.number(Cbor.get(cose,-1)) != 1)
            throw new IOException("Expected ES256 credential");
        byte[] x = Cbor.bytes(Cbor.get(cose,-2)), y = Cbor.bytes(Cbor.get(cose,-3));
        if (x.length != 32 || y.length != 32) throw new IOException("Invalid credential public key");
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(
                new ECPoint(new BigInteger(1,x),new BigInteger(1,y)),parameters.getParameterSpec(ECParameterSpec.class)));
        Object extensions = reader.read(0);
        if (reader.p != ad.length || !Boolean.TRUE.equals(Cbor.get(extensions,"hmac-secret")))
            throw new IOException("hmac-secret was not enabled");
        // Proof of possession is checked by get() before any record is stored.
        return new Credential(id,publicKey.getEncoded());
    }

    static void checkAuthData(byte[] ad,int required) throws Exception {
        if (ad.length < 37 || !MessageDigest.isEqual(Arrays.copyOf(ad,32),Crypto.sha(Crypto.utf8(RP))) || ((ad[32]&255)&required) != required)
            throw new IOException("Invalid RP, user presence, verification or extension flags");
    }

    static final class Assertion {
        final Credential credential;
        final byte[] secret;
        Assertion(Credential credential,byte[] secret){this.credential=credential;this.secret=secret;}
    }
    Assertion get(byte[] pin,List<Credential> credentials,byte[] salt)throws Exception {
        try(Session session=new Session(pin.clone(),false)){return get(session,credentials,salt);}
    }
    byte[] get(Session session, Credential credential, byte[] salt) throws Exception {
        return get(session,Collections.singletonList(credential),salt).secret;
    }
    Assertion get(Session session,List<Credential> credentials,byte[] salt) throws Exception {
        if(credentials.isEmpty())throw new IOException("No token enrolled for this database.");
        List<Object> allowed=descriptors(session,credentials);
        if (salt.length != 32) throw new IOException("Invalid salt");
        Object peer = Cbor.get(command(6,Cbor.map(1,session.version,2,2)),1);
        try (Crypto.Agreement a = new Crypto.Agreement(session.version,peer)) {
            byte[] encrypted = a.encrypt(salt), hash = Crypto.random(32);
            progress.update("Unlock: touch the token when it blinks.");
            Object response = command(2,Cbor.map(1,RP,2,hash,
                    3,allowed,
                    4,Cbor.map("hmac-secret",Cbor.map(1,a.publicKey,2,encrypted,3,a.authenticate(encrypted),4,session.version)),
                    5,Cbor.map("up",true),6,session.auth(hash),7,session.version));
            Object desc = Cbor.get(response,1);
            Credential credential=null;
            // CTAP may omit the descriptor only for a singleton allowList.
            if(desc==null&&credentials.size()==1)credential=credentials.get(0);
            else if(desc!=null&&"public-key".equals(Cbor.get(desc,"type"))){
                byte[] id=Cbor.bytes(Cbor.get(desc,"id"));
                for(Credential candidate:credentials)if(MessageDigest.isEqual(candidate.id,id)){credential=candidate;break;}
            }
            if(credential==null)throw new IOException("Unexpected credential");
            byte[] ad = Cbor.bytes(Cbor.get(response,2));
            checkAuthData(ad,0x85);
            if ((ad[32]&0x40) != 0) throw new IOException("Unexpected attestation in assertion");
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(credential.publicKey)));
            verifier.update(ad); verifier.update(hash);
            if (!verifier.verify(Cbor.bytes(Cbor.get(response,3)))) throw new IOException("Invalid assertion signature");
            byte[] secret = a.decrypt(Cbor.bytes(Cbor.get(Cbor.decodeAt(ad,37),"hmac-secret")));
            if (secret.length != 32) { Crypto.wipe(secret); throw new IOException("Invalid hmac-secret output"); }
            return new Assertion(credential,secret);
        }
    }
}
