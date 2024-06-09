from tools import *
from pypbc import *

ParameterPath=ParameterPathFromTools

def KeyGenReceiverUThroughFile():
    """[KGC generate key pair for User]

    Args:
        params ([type]): [description]
        g ([type]): [description]
        Kx ([type]): [description]
        Kz ([type]): [description]
        Kl ([type]): [description]

    Returns:
        [type]: [Key pair]
    """
    logger.info("==================KeyGenReceiver Start==================")
    pp=readPP(ServerPathFromTools)

    [params,g,Kx,Kz,Kl]=pp
    pairing = Pairing(params) 

    alpha = Element.random(pairing,Zr) 
    pku = Element(pairing, G1, value=g ** alpha) 
    sku = {"sk":alpha,"Kx":Kx,"Kz":Kz,"Kl":Kl}

    pkuCopy = str(pku)
    skuCopy = {"sk":str(alpha),"Kx":str(Kx),"Kz":str(Kz),"Kl":str(Kl)}
    uKeyCopy=[pkuCopy,skuCopy]

    createFile(ServerPathFromTools+ParameterPath+"uKey.dat",str(uKeyCopy),"w")
    logger.info("==================KeyGenReceiver End==================")
    return [pku,sku]

if __name__ == '__main__':
    KeyGenReceiverUThroughFile()