package com.kunzisoft.keepass.fido2;

/** CTAP message channel; PIN/UV, hmac-secret and signature checks stay in FidoToken. */
interface CtapTransport extends AutoCloseable {
    void init() throws Exception;
    byte[] cbor(byte[] request) throws Exception;
    void close();
}
