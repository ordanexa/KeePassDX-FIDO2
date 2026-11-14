"""Independent CTAP wire simulator. All PINs/keys here are synthetic test fixtures."""
import sys, hashlib, hmac
from fido2 import cbor
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

mode=sys.argv[1]
version=1 if mode=='v1' else 2
proto=PinProtocolV1() if version==1 else PinProtocolV2()
RP='keepassdx-fido2.ordanexa.com'
PIN=b'123456'
token=b'T'*32
credential=ec.generate_private_key(ec.SECP256R1())
cred_id=b'synthetic-credential-id'
cred_random=b'R'*32
agreement_private=None
pin_attempts=0
authorized=False
completed_operations=0
permissions=0

def public_cose(key):
    p=key.public_key().public_numbers()
    return {1:2,3:-7,-1:1,-2:p.x.to_bytes(32,'big'),-3:p.y.to_bytes(32,'big')}

def shared(peer):
    pk=ec.EllipticCurvePublicNumbers(int.from_bytes(peer[-2],'big'),int.from_bytes(peer[-3],'big'),ec.SECP256R1()).public_key()
    return proto.kdf(agreement_private.exchange(ec.ECDH(),pk))

def respond(raw):
    global agreement_private,pin_attempts,authorized,completed_operations,permissions
    cmd=raw[0]; a=cbor.decode(raw[1:]) if len(raw)>1 else {}
    if cmd==4:
        return {1:['FIDO_2_1'],2:[] if mode=='no_hmac' else ['hmac-secret'],3:b'A'*16,
                4:{'clientPin':True,'pinUvAuthToken':version==2},5:1024,6:[version]}
    if cmd==6:
        assert a[1]==version
        if a[2]==1:return {3:2 if mode=='low_retries' else 8}
        if a[2]==2:
            agreement_private=ec.generate_private_key(ec.SECP256R1())
            p=public_cose(agreement_private);p[3]=-25
            return {1:p}
        assert a[2]==(9 if version==2 else 5),'PIN write or unsupported command'
        if version==2:assert a[9] in (1,2) and a[10]==RP
        pin_attempts+=1
        assert pin_attempts==completed_operations+1,'Automatic PIN retry'
        s=shared(a[3])
        assert proto.decrypt(s,a[6])==hashlib.sha256(PIN).digest()[:16]
        if mode=='wrong_pin':return 0x31
        if mode=='reauth_rejected' and pin_attempts==2:return 0x33
        permissions=a.get(9,3)
        authorized=True
        return {2:proto.encrypt(s,token)}
    if cmd==1:
        if not authorized or not permissions & 1:return 0x33
        authorized=False;permissions=0;completed_operations+=1
        assert a[2]['id']==RP and a[7]=={'rk':False} and a[6]=={'hmac-secret':True}
        assert a[4]==[{'type':'public-key','alg':-7}]
        assert a[9]==version and hmac.compare_digest(a[8],proto.authenticate(token,a[1]))
        flags=0xc1 if mode=='create_no_uv' else 0xc5
        ad=hashlib.sha256(RP.encode()).digest()+bytes([flags])+b'\0'*4+b'A'*16+len(cred_id).to_bytes(2,'big')+cred_id+cbor.encode(public_cose(credential))+cbor.encode({'hmac-secret':True})
        return {1:'packed',2:ad,3:{'alg':-7,'sig':credential.sign(ad+a[1],ec.ECDSA(hashes.SHA256()))}}
    if cmd==2:
        if not authorized or not permissions & 2:return 0x33
        authorized=False;permissions=0;completed_operations+=1
        assert a[1]==RP and a[5]=={'up':True}
        assert a[3]==[{'type':'public-key','id':cred_id}]
        assert a[7]==version and hmac.compare_digest(a[6],proto.authenticate(token,a[2]))
        hs=a[4]['hmac-secret'];assert hs[4]==version
        s=shared(hs[1]);assert hmac.compare_digest(hs[3],proto.authenticate(s,hs[2]))
        salt=proto.decrypt(s,hs[2]);assert len(salt)==32
        secret=hmac.digest(cred_random,salt,'sha256')
        flags=0x81 if mode=='no_uv' else 0x84 if mode=='no_up' else 0x85
        rp='wrong.example' if mode=='wrong_rp' else RP
        ad=hashlib.sha256(rp.encode()).digest()+bytes([flags])+b'\0'*4+cbor.encode({'hmac-secret':proto.encrypt(s,secret)})
        signer=ec.generate_private_key(ec.SECP256R1()) if mode=='wrong_signature' else credential
        sig=signer.sign(ad+(b'X'*32 if mode=='replay' else a[2]),ec.ECDSA(hashes.SHA256()))
        return {1:{'type':'public-key','id':b'wrong' if mode=='wrong_id' else cred_id},2:ad,3:sig}
    raise AssertionError('Forbidden CTAP command')

for line in sys.stdin:
    try:
        response=respond(bytes.fromhex(line.strip()))
        print((bytes([response]) if isinstance(response,int) else b'\0'+cbor.encode(response)).hex(),flush=True)
    except Exception:
        import traceback
        traceback.print_exc(file=sys.stderr);sys.exit(1)
