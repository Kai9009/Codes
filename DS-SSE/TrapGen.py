from tools import *
from pypbc import *

ParameterPath=ParameterPathFromTools
TrapCopy={}
WSet={}#readWSet(ClientPathFromTools)

def Get(delta,w,WSet):
    """[The number of keyword w in DB]

    Args:
        delta ([type]): [description]
        w ([type]): [description]

    Returns:
        [type]: [The number of keyword w]
    """
    c=0
    if w in WSet.keys():
        c=WSet[w]
    else: WSet[w]=0
    print(c)
    return c

def TrapGenThroughFile():
    """[User v generate token to server]

    Args:
        params ([type]): [description]
        g ([type]): [description]
        skv ([type]): [Secret key of user v]
        pkfs ([type]): [Public key of Front Server]
        pkbs ([type]): [Public key of Back Srever]
        Q ([type]): [Query like (w1,w2,...)]

    Returns:
        [type]: [Token token for Front Server]
    """
    logger.info("==================TrapGen Start==================")
    Copy=loadFile(ClientPathFromTools+"para.dat")
    [Q,V]=Copy
    logTime.info("Generate Trap for %s",Q)
    print(Q)

    # 仅用于做实验
    i=1
    V={}
    V[0]=1
    while(i<len(Q)):
        V[i]=1
        i+=1


    [params,g,Kx,Kz,Kl]=readPP(ClientPathFromTools)
    pairing = Pairing(params) 

    serverKey=readServerKey(ClientPathFromTools)
    [pkfs,skfs,pkbs,skbs]=serverKey

    vKey=readReceiverVKey(ClientPathFromTools)
    [pkv,skv]=vKey

    WSet=readWSet(ClientPathFromTools)

    zone=Element.one(pairing,Zr)
    beta=skv["sk"]

    

    i=1
    n=Get(0,Q[i],WSet)

    logger.info("Trap length is %s",n)
    q=len(Q)
    logger.info("Send to Front Server for %s times",n)
    logger.info("Query Keywords = %s",Q)
    logger.info("Query keyword number = %d",q-1)

    l={}
    Trap={}
    boolVector={}
    i=1
    #因为有个Q[0]是空,所以<
    while(i<q):
        boolVector[i]=V[i]
        i+=1

    i=1
    while(i<=n):
        Trap[i]={}
        TrapCopy[i]={}
        i=i+1

    i=1
    while(i<=n):
        w1=str(Q[1]).encode('utf-8')
        #print(w1)
        c=str(i).encode('utf-8')
        l[i]=PRF_F(skv["Kl"],w1+c)
        z=PRF_Fp(params,skv["Kz"],w1+c)
        
        j=1
        #因为有个Q[0]是空,所以<
        while(j<q):
            wj=str(Q[j]).encode('utf-8')
            r2=Element.random(pairing,Zr)
            T1=Element(pairing,G1,value=g ** r2)    #g^r2 "w".encode()
            hash_value = Element.from_hash(pairing, G1, Hash1(wj).hexdigest())   #H1(wj)
            T2=Element(pairing,G1,value= (hash_value ** (zone/(beta*z))) * ((pkfs * pkbs) ** r2) ) #H1(wj)^{1/(beta*z)}  *  (g^{gamma+eta})^{r2}

            trap=[T1,T2]
            Trap[i][j]=trap
            TrapCopy[i][j]=[str(T1),str(T2)]
            j=j+1
        i=i+1

    tokenfs=[l,Trap,boolVector]
    tokenfsCopy=[l,TrapCopy,boolVector]
    createFile(ClientPathFromTools+"tokenfs.dat",str(tokenfsCopy),"w")
    logger.info("==================TrapGen End==================")
    return tokenfs

def TrapGen(params,g,pkfs,pkbs,skv,WSet,Q,V):
    pairing = Pairing(params) 
    zone=Element.one(pairing,Zr)
    beta=skv["sk"]

    i=1
    n=Get(0,Q[i],WSet)

    logger.info("Trap length is %s",n)
    q=len(Q)
    logger.info("Send to Front Server for %s times",n)
    logger.info("Query Keywords = %s",Q)
    logger.info("Query keyword number = %d",q-1)

    l={}
    Trap={}
    boolVector={}
    i=1
    #因为有个Q[0]是空,所以<
    while(i<q):
        boolVector[i]=V[i]
        i+=1

    i=1
    while(i<=n):
        Trap[i]={}
        TrapCopy[i]={}
        i=i+1

    i=1
    while(i<=n):
        w1=str(Q[1]).encode('utf-8')
        #print(w1)
        c=str(i).encode('utf-8')
        l[i]=PRF_F(skv["Kl"],w1+c)
        z=PRF_Fp(params,skv["Kz"],w1+c)
        
        j=1
        #因为有个Q[0]是空,所以<
        while(j<q):
            wj=str(Q[j]).encode('utf-8')
            r2=Element.random(pairing,Zr)
            T1=Element(pairing,G1,value=g ** r2)    #g^r2 "w".encode()
            hash_value = Element.from_hash(pairing, G1, Hash1(wj).hexdigest())   #H1(wj)
            T2=Element(pairing,G1,value= (hash_value ** (zone/(beta*z))) * ((pkfs * pkbs) ** r2) ) #H1(wj)^{1/(beta*z)}  *  (g^{gamma+eta})^{r2}

            trap=[T1,T2]
            Trap[i][j]=trap
            TrapCopy[i][j]=[str(T1),str(T2)]
            j=j+1
        i=i+1

    tokenfs=[l,Trap,boolVector]
    tokenfsCopy=[l,TrapCopy,boolVector]
    createFile(ClientPathFromTools+"tokenfs.dat",str(tokenfsCopy),"w")
    logger.info("==================TrapGen End==================")
    return tokenfs

if __name__ == '__main__':
    TrapGenThroughFile()


