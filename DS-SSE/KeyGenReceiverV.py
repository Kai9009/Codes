from tools import *
from pypbc import *

ParameterPath=ParameterPathFromTools

def KeyGenReceiverVThroughFile():
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
    beta = Element.random(pairing,Zr) 
    pkv = Element(pairing, G1, value=g ** beta) 
    skv = {"sk":beta,"Kx":Kx,"Kz":Kz,"Kl":Kl}

    pkvCopy = str(pkv)
    skvCopy = {"sk":str(beta),"Kx":str(Kx),"Kz":str(Kz),"Kl":str(Kl)}
    vKeyCopy=[pkvCopy,skvCopy]

    createFile(ServerPathFromTools+ParameterPath+"vKey.dat",str(vKeyCopy),"w")
    logger.info("==================KeyGenReceiver End==================")
    return [pkv,skv]

if __name__ == '__main__':
    KeyGenReceiverVThroughFile()