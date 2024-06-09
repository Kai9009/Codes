from tools import *
from pypbc import *

import hashlib

ParameterPath=ParameterPathFromTools
# Hash1 = hashlib.sha256
# Hash2 = hashlib.sha256

def BackTestThroughFile():
    """[Back Server search data with tokenbs and return to User]

    Args:
        params ([type]): [description]
        g ([type]): [Generator of G1]
        tokenbs ([type]): [Token tokenbs received from Front Server]
        skbs ([type]): [description]
        rkuv ([type]): [Re-encryption key convert U->V]
        EDB ([type]): [description]
        XSet ([type]): [description]

    Returns:
        [type]: [Test result]
    """
    logger.info("==================BackTest Start==================")
    [params,g,Kx,Kz,Kl]=readPP(ServerPathFromTools)
    pairing = Pairing(params) 
    serverKey=readServerKey(ServerPathFromTools)
    [pkfs,skfs,pkbs,skbs]=serverKey

    ztwo=Element(pairing,Zr,value=2)
    vector={}
    EDBCopy=loadFile(ServerPathFromTools+ParameterPath+"EDB.dat")
    XSetCopy=loadFile(ServerPathFromTools+ParameterPath+"XSet.dat")
    tokenbsCopy=loadFile(ServerPathFromTools+"tokenbs.dat")
    [l,TrapCopy,StatusCopy,booleanVector]=tokenbsCopy

    rkuvCopy=loadFile(ServerPathFromTools+ParameterPath+"rkuv.dat")
    rkuv={}
    rkuv[1]=Element(pairing,G1,value=rkuvCopy[1])
    rkuv[2]=Element(pairing,G1,value=rkuvCopy[2])
    rkuv[3]=Element(pairing,G1,value=rkuvCopy[3])
    rkuv[4]=Element(pairing,G1,value=rkuvCopy[4])
    

    #[l,Trap,Status]=tokenbs
    i=1
    isExistInEDB=0
    #判断是否存在EDB[li]
    while(i<=len(l)):
        for item in EDBCopy.keys():
            if(l[i]==item):
                isExistInEDB=1
        i=i+1
    
    #print("isExistInEDB=",isExistInEDB)
    if(isExistInEDB==0):
        return 0
    
    b=1
    i=1
    #由于l是传过来的,省略0位置,此处要写<=
    while(i<=len(l) and b==1):
        if(l[i] in EDBCopy.keys()):
            #print(EDB[l[i]])
            e1Copy=EDBCopy[l[i]]['e1']
            e1=Element(pairing,Zr,value=int(e1Copy,16))
            count=0
            j=1
            while(j<=len(TrapCopy[i])):
                [T1Copy,T2Copy]=TrapCopy[i][j]
                T1=Element(pairing,G1,value=T1Copy)
                T2=Element(pairing,G1,value=T2Copy)
                TgCopy=StatusCopy[i][j]
                Tg=Element(pairing,G1,value=TgCopy)
                T2e=Element(pairing,G1,value=T2 ** skbs["sk"])
                T1e=Element(pairing,G1,value=T1 ** (skbs["sk"] ** ztwo))
                Te=Element(pairing,G1,value=T2e /T1e)#  Teta=T2^{eta}  /  T1^{eta^2}

                UgUe=pairing.apply(Element(pairing,G1,value=rkuv[4] ** e1),Element(pairing,G1,value=Tg/Te))
                flag=0#判断本次关键字是否在XSet中
                for itemCopy in XSetCopy.values():
                    item=Element(pairing,GT,value=itemCopy)
                    if(UgUe==item):
                        #count=count+1 #仅用于Conjuctive Search
                        flag=1

                vector[j]=flag
                j=j+1
  
            if(vector==booleanVector):
                b=1
            else:
                b=0

        i=i+1
    
    logger.info("BackTest Result=%s",b)
    logger.info("==================BackTest End==================")
    return b

if __name__ == '__main__':
    BackTestThroughFile()