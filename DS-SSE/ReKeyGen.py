from tools import *
from pypbc import *

ParameterPath=ParameterPathFromTools

def ReKeyGenThroughFile():
    """[User u generate re-encryption key]

    Args:
        params ([type]): [description]
        g ([type]): [description]
        sku ([type]): [Secret key of User u]
        pkv ([type]): [Public key of user v]

    Returns:
        [type]: [Re-encryption key]
    """
    logger.info("==================ReKeyGen Start==================")
    [params,g,Kx,Kz,Kl]=readPP(ServerPathFromTools)
    pairing = Pairing(params) 
    uKey=readReceiverUKey(ServerPathFromTools)
    [pku,sku]=uKey
    vKey=readReceiverVKey(ServerPathFromTools)
    [pkv,skv]=vKey

    rkuv={}
    alpha=sku["sk"]
    pku=Element(pairing,G1,value=g ** alpha)
    zone=Element.one(pairing,Zr)
    gone=Element.one(pairing,G1)
    r3=Element.random(pairing,Zr)
    X=Element.random(pairing,G1)
    hashE0 = Element.from_hash(pairing, G1, Hash1(str(pku).encode()).hexdigest())
    temp=Element(pairing,G1,value=hashE0 ** -alpha)#H^{-alpha}
    hash_value = Element.from_hash(pairing, G1, Hash1(str(X).encode('utf-8')).hexdigest())

    rkuv[1]=Element(pairing,G1,value=g ** r3)
    rkuv[2]=Element(pairing,G1,value=X * (pkv ** r3))
    rkuv[3]=Element(pairing,G1,value=temp * hash_value)#H^{-alpha}*H(X)
    rkuv[4]=Element(pairing,G1,value=pkv ** (zone/alpha))

    rkuvCopy={}
    rkuvCopy[1]=str(rkuv[1])
    rkuvCopy[2]=str(rkuv[2])
    rkuvCopy[3]=str(rkuv[3])
    rkuvCopy[4]=str(rkuv[4])

    createFile(ServerPathFromTools+ParameterPath+"rkuv.dat",str(rkuvCopy),"w")
    logger.info("==================ReKeyGen End==================")
    return rkuv

if __name__ == '__main__':
    ReKeyGenThroughFile()