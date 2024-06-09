from tools import *
from pypbc import *

ParameterPath=ParameterPathFromTools

def KeyGenServerThroughFile():
    """[KGC generate key pair for server]

    Args:
        params ([type]): [description]
        g ([type]): [description]
        Kx ([type]): [description]
        Kz ([type]): [description]
        Kl ([type]): [description]

    Returns:
        [type]: [Key pair]
    """
    logger.info("==================KeyGenServer Start==================")
    pp=readPP(ServerPathFromTools)

    [params,g,Kx,Kz,Kl]=pp
    pairing = Pairing(params) 

    gamma = Element.random(pairing,Zr)  
    eta = Element.random(pairing,Zr) 

    pkfs = Element(pairing, G1, value=g ** gamma) 
    skfs = {"sk":gamma,"Kx":Kx,"Kz":Kz,"Kl":Kl}
    pkbs = Element(pairing, G1, value=g ** eta) 
    skbs = {"sk":eta,"Kx":Kx,"Kz":Kz,"Kl":Kl}

    pkfsCopy = str(pkfs)
    skfsCopy = {"sk":str(gamma),"Kx":str(Kx),"Kz":str(Kz),"Kl":str(Kl)}
    pkbsCopy = str(pkbs)
    skbsCopy = {"sk":str(eta),"Kx":str(Kx),"Kz":str(Kz),"Kl":str(Kl)}
    serverKeyCopy=[pkfsCopy,skfsCopy,pkbsCopy,skbsCopy]

    createFile(ServerPathFromTools+ParameterPath+"serverKey.dat",str(serverKeyCopy),"w")
    logger.info("==================KeyGenServer End==================")
    return [pkfs,skfs,pkbs,skbs]

if __name__ == '__main__':
    KeyGenServerThroughFile()