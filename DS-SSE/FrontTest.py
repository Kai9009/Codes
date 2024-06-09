from tools import *
from pypbc import *

ParameterPath=ParameterPathFromTools
StatusCopy={}
def FrontTestThroughFile():
    """[Front Server generate state for Back Server]

    Args:
        params ([type]): [description]
        g ([type]): [description]
        tokenfs ([type]): [Token tokenfs received from User]
        skfs ([type]): [Secret key of Front Server]

    Returns:
        [type]: [Token tokenbs for Back Server]
    """
    logger.info("==================FrontTest Start==================")
    [params,g,Kx,Kz,Kl]=readPP(ServerPathFromTools)
    pairing = Pairing(params) 

    serverKey=readServerKey(ServerPathFromTools)
    [pkfs,skfs,pkbs,skbs]=serverKey

    ztwo=Element(pairing,Zr,value=2)

    tokenfsCopy=loadFile(ServerPathFromTools+"tokenfs.dat")

    [l,TrapCopy,booleanVector]=tokenfsCopy
    Status={}
    Trap={}
    i=1
    while(i<=len(TrapCopy)):
        Trap[i]={}
        Status[i]={}
        StatusCopy[i]={}
        i=i+1

    i=1
    while(i<=len(TrapCopy)):
        j=1
        while(j<=len(TrapCopy[i])):
            [T1Copy,T2Copy]=TrapCopy[i][j]
            T1=Element(pairing,G1,value=T1Copy)
            T2=Element(pairing,G1,value=T2Copy)
            Trap[i][j]=[T1,T2]
            T2g=Element(pairing,G1,value=T2 ** skfs["sk"])
            T1g=Element(pairing,G1,value=T1 ** (skfs["sk"] ** ztwo))
            Tg=Element(pairing,G1,value=T2g /T1g)
            Status[i][j]=Tg # Tgamma=T2^{gamma}  /  T1^{gamma^2}
            StatusCopy[i][j]=str(Tg)
            j=j+1
        i=i+1

    tokenbs=[l,Trap,Status,booleanVector]
    tokenbsCopy=[l,TrapCopy,StatusCopy,booleanVector]
    createFile(ServerPathFromTools+"tokenbs.dat",str(tokenbsCopy),"w")
    logTime.info("Server tokenbs.dat size is %s KB",os.path.getsize(ServerPathFromTools+"tokenbs.dat")/1024)
    logger.info("==================FrontTest End==================")
    return tokenbs

def FrontTest(params,skfs,tokenfsCopy):
    pairing = Pairing(params) 
    ztwo=Element(pairing,Zr,value=2)
    [l,TrapCopy,booleanVector]=tokenfsCopy
    Status={}
    Trap={}
    i=1
    while(i<=len(TrapCopy)):
        Trap[i]={}
        Status[i]={}
        StatusCopy[i]={}
        i=i+1

    i=1
    while(i<=len(TrapCopy)):
        j=1
        while(j<=len(TrapCopy[i])):
            [T1Copy,T2Copy]=TrapCopy[i][j]
            T1=Element(pairing,G1,value=T1Copy)
            T2=Element(pairing,G1,value=T2Copy)
            Trap[i][j]=[T1,T2]
            T2g=Element(pairing,G1,value=T2 ** skfs["sk"])
            T1g=Element(pairing,G1,value=T1 ** (skfs["sk"] ** ztwo))
            Tg=Element(pairing,G1,value=T2g /T1g)
            Status[i][j]=Tg # Tgamma=T2^{gamma}  /  T1^{gamma^2}
            StatusCopy[i][j]=str(Tg)
            j=j+1
        i=i+1

    tokenbs=[l,Trap,Status,booleanVector]
    tokenbsCopy=[l,TrapCopy,StatusCopy,booleanVector]
    createFile(ServerPathFromTools+"tokenbs.dat",str(tokenbsCopy),"w")
    logTime.info("Server tokenbs.dat size is %s KB",os.path.getsize(ServerPathFromTools+"tokenbs.dat")/1024)
    logger.info("==================FrontTest End==================")
    return tokenbs

if __name__ == '__main__':
    FrontTestThroughFile()