from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes




class someClass:
    string = None
    num = 328965
    def __init__(self,mystring):
        self.string = mystring
    def __repr__(self):
        return self.string + "^^^" + str(self.num)

class cBlock:
    data = None
    previousHash = None
    previousBlock = None
    
    def __init__(self,data,previousBlock):
        self.data = data
        self.previousBlock = previousBlock
        if previousBlock != None:
            self.previousHash = previousBlock.computeHash()
    
    def computeHash(self):
        digest = hashes.Hash(hashes.SHA256(),backend = default_backend())
        digest.update(bytes(str(self.data),'utf8'))
        digest.update(bytes(str(self.previousHash),'utf8'))
        return digest.finalize()

if __name__ == '__main__':
    root = cBlock('I am root', None)
    B1 = cBlock('I am a child', root)
    B2 = cBlock('I am B1s brother',root)
    B3 = cBlock(12354,B1)
    B4 = cBlock(someClass("Hi, there!"),B3)
    B5 = cBlock("Top class",B4)
    
    for b in [B1,B2,B3,B4,B5]:
        if B1.previousBlock.computeHash() == B1.previousHash:
            print("Success! Hash is good!") 
        else:
            print("Error! Hash is not good!")
            
    B3.data = 12345
    if B4.previousBlock.computeHash() == B4.previousHash:
        print("Error! Could not detect tampering")
    else:
        print("Success! Tampering detected")
    print(B4.data)
    B4.data.num = 999999
    print(B4.data)
    if B5.previousBlock.computeHash() == B5.previousHash():
        print("Error! Could not detect tampering")
    else:
        print("Success! Tampering detected")