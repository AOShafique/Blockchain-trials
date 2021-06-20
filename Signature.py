from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
def generate_keys():
    private = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend = default_backend()
        )
    
    public = private.public_key()
    return private, public

def sign(msg, private):
    sig = private.sign(
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
              hashes.SHA256()
        )
    return sig

def verify(msg, sig, public):
    try: 
        public.verify(
         sig,
         msg,
         padding.PSS(
             mgf=padding.MGF1(hashes.SHA256()),
             salt_length=padding.PSS.MAX_LENGTH
         ),
         hashes.SHA256()
     )
        return True
    except InvalidSignature:
        return False
    except:
        print("Error executing public.verify")
        return False

if __name__ == '__main__':
    pr, pu = generate_keys()
    print(pr)
    print(pu)
    msg = b"this is a secret msg"
    sig = sign(msg,pr)
    print(sig)
    correct = verify(msg,sig,pu)
    print(correct)
    
    if correct:
        print("Success! Good signature detected")
    else:
        print("Error! Bad signature detected")    
        
    pr2, pu2 = generate_keys()
    sig2 = sign(msg,pr2)    
    correct = verify(msg,sig2,pu)
    if correct:
        print("Error! Bad signature checks out")
    else:
        print("Success! Bad signature detected")
        
    badmsg = b"Q"
    correct = verify(badmsg,sig,pu)
    if correct:
        print("Error! Tampered msg checks out")
    else:
        print("Success! Tampering detected")
         
    