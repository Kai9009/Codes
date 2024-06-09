from typing import DefaultDict
from pypbc import *
import hashlib
import random
import logging
from pathlib import Path
from email.parser import Parser
#import paramiko
import os

import nltk
from nltk.tokenize import *
from nltk.corpus import stopwords
from string import punctuation
import string
from datetime import datetime

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

ip = "122.112.197.56"#服务器ip
port = 22#端口号
username = "root"#用户名
password = "PSK_Violet+8421"#密码

Hash1 = hashlib.sha256
Hash2 = hashlib.sha256

isFirst=1#第一次执行默认执行EDBSetup
# localRootPath="/home/caedios/Project/ThesisAlgorithm/"
# remoteRootPath="/home/Project/"
# ssh = paramiko.SSHClient()
# ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# ssh.connect(ip, port, username, password)
# sftp = ssh.open_sftp()


WSet={}
if(os.path.exists("WSet.dat") and not isFirst):
        fileWSet=open("WSet.dat","r")
        WSet=eval(fileWSet.read())

inds={}
if(os.path.exists("Inds.dat") and not isFirst):
        fileInds=open("Inds.dat","r")
        inds=eval(fileInds.read())

EDBCopy={}
XSetCopy={}
IndsCopy={}
tokenfsCopy=[]
TrapCopy={}
StatusCopy={}

#logging.getLogger().setLevel(logging.INFO)
logging.getLogger().setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
file_handler = logging.FileHandler("log")
file_handler.setLevel(level=logging.INFO)
file_handler.setFormatter(formatter)
logging.getLogger().addHandler(file_handler)


def Get(delta,w):
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
    return c

def Update(delta,w,c):
    """[Update DB[w] for its number]

    Args:
        delta ([type]): [description]
        w ([type]): [Keyword]
        c ([type]): [description]

    Returns:
        [type]: [Success or not]
    """
    state=0
    if w in WSet.keys():
        WSet[w]=c
        state=1
    return state

def PRF_F(key,msg):
    """[PRF_F]

    Args:
        key ([type]): [description]
        msg ([type]): [description]

    Returns:
        [type]: [Random number]
    """
    random.seed(key+msg)
    final=random.random()*1000000000000000000
    return final

def PRF_Fp(params,key,msg):
    """[PRF_Fp]

    Args:
        params ([type]): [description]
        key ([str]): [description]
        msg ([str]): [description]

    Returns:
        [type]: [Random hash value in group Zr]
    """
    pairing = Pairing(params)
    hash_value = Element.from_hash(pairing, Zr, Hash2((key+msg)).hexdigest())
    #hash_value = Element.from_hash(pairing, Zr, Hash2(("1".encode())).hexdigest())
    return hash_value

def GlobalSetup(qbits=512, rbits=160):
    """[KGC generate public parameter]

    Args:
        qbits (int, optional): [description]. Defaults to 512.
        rbits (int, optional): [description]. Defaults to 160.

    Returns:
        [type]: [description]
    """
    logging.info("==================GlobalSetup Start==================")
    params = Parameters(qbits=qbits, rbits=rbits)   #参数初始化
    pairing = Pairing(params)  # 根据参数实例化双线性对
    g = Element.random(pairing, G1)  # g是G1的一个生成元
    Kx="Kx".encode('utf-8')
    Kz="Kz".encode('utf-8')
    Kl="Kl".encode('utf-8')

    logging.info("==================GlobalSetup End==================")
    return [params,g,Kx,Kz,Kl]

def GlobalSetupThroughFile(qbits=512, rbits=160):
    """[KGC generate public parameter]

    Args:
        qbits (int, optional): [description]. Defaults to 512.
        rbits (int, optional): [description]. Defaults to 160.

    Returns:
        [type]: [description]
    """
    logging.info("==================GlobalSetup Start==================")
    params = Parameters(qbits=qbits, rbits=rbits)   #参数初始化
    pairing = Pairing(params)  # 根据参数实例化双线性对
    g = Element.random(pairing, G1)  # g是G1的一个生成元
    Kx="Kx".encode('utf-8')
    Kz="Kz".encode('utf-8')
    Kl="Kl".encode('utf-8')

    paramsCopy = str(params)
    gCopy = str(g)
    KxCopy = str(Kx)
    KzCopy = str(Kz)
    KlCopy = str(Kl)

    ppCopy = [paramsCopy,gCopy,KxCopy,KzCopy,KlCopy]

    writeFile("pp.dat",ppCopy)
    logging.info("==================GlobalSetup End==================")
    return [params,g,Kx,Kz,Kl]

def KeyGenServer(params,g,Kx,Kz,Kl):
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
    logging.info("==================KeyGenServer Start==================")
    pairing = Pairing(params) 
    gamma = Element.random(pairing,Zr)  
    eta = Element.random(pairing,Zr) 

    pkfs = Element(pairing, G1, value=g ** gamma) 
    skfs = {"sk":gamma,"Kx":Kx,"Kz":Kz,"Kl":Kl}
    pkbs = Element(pairing, G1, value=g ** eta) 
    skbs = {"sk":eta,"Kx":Kx,"Kz":Kz,"Kl":Kl}

    logging.info("==================KeyGenServer End==================")
    return [pkfs,skfs,pkbs,skbs]

def KeyGenServerThroughFile(params,g,Kx,Kz,Kl):
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
    logging.info("==================KeyGenServer Start==================")
    ppCopy=loadFile("pp.dat")

    [paramsCopy,gCopy,KxCopy,KzCopy,KlCopy]=ppCopy
    params = Parameters(paramsCopy)
    pairing = Pairing(params) 
    g=Element(pairing,G1,value=gCopy)
    Kx=KxCopy
    Kz=KzCopy
    Kl=KlCopy

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

    writeFile("serverKey.dat",serverKeyCopy)
    logging.info("==================KeyGenServer End==================")
    return [pkfs,skfs,pkbs,skbs]

def KeyGenReceiver(params,g,Kx,Kz,Kl):
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
    logging.info("==================KeyGenReceiver Start==================")
    pairing = Pairing(params)
    alpha = Element.random(pairing,Zr) 
    pku = Element(pairing, G1, value=g ** alpha) 
    sku = {"sk":alpha,"Kx":Kx,"Kz":Kz,"Kl":Kl}
    logging.info("==================KeyGenReceiver End==================")
    return [pku,sku]

def KeyGenReceiverUThroughFile(params,g,Kx,Kz,Kl):
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
    logging.info("==================KeyGenReceiver Start==================")
    ppCopy=loadFile("pp.dat")

    [paramsCopy,gCopy,KxCopy,KzCopy,KlCopy]=ppCopy
    params = Parameters(paramsCopy)
    pairing = Pairing(params) 
    g=Element(pairing,G1,value=gCopy)
    Kx=KxCopy
    Kz=KzCopy
    Kl=KlCopy

    pairing = Pairing(params)
    alpha = Element.random(pairing,Zr) 
    pku = Element(pairing, G1, value=g ** alpha) 
    sku = {"sk":alpha,"Kx":Kx,"Kz":Kz,"Kl":Kl}

    pkuCopy = str(pku)
    skuCopy = {"sk":str(alpha),"Kx":str(Kx),"Kz":str(Kz),"Kl":str(Kl)}
    uKeyCopy=[pkuCopy,skuCopy]

    writeFile("uKey.dat",uKeyCopy)
    logging.info("==================KeyGenReceiver End==================")
    return [pku,sku]

def KeyGenReceiverVThroughFile(params,g,Kx,Kz,Kl):
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
    logging.info("==================KeyGenReceiver Start==================")
    ppCopy=loadFile("pp.dat")

    [paramsCopy,gCopy,KxCopy,KzCopy,KlCopy]=ppCopy
    params = Parameters(paramsCopy)
    pairing = Pairing(params) 
    g=Element(pairing,G1,value=gCopy)
    Kx=KxCopy
    Kz=KzCopy
    Kl=KlCopy

    pairing = Pairing(params)
    beta = Element.random(pairing,Zr) 
    pkv = Element(pairing, G1, value=g ** beta) 
    skv = {"sk":beta,"Kx":Kx,"Kz":Kz,"Kl":Kl}

    pkvCopy = str(pkv)
    skvCopy = {"sk":str(beta),"Kx":str(Kx),"Kz":str(Kz),"Kl":str(Kl)}
    vKeyCopy=[pkvCopy,skvCopy]

    writeFile("vKey.dat",vKeyCopy)
    logging.info("==================KeyGenReceiver End==================")
    return [pkv,skv]

def EDBSetup(params,g,D,sku,pkfs,pkbs,EDB,XSet):
    """[User u encrypt his file and generate EDB and XSet]

    Args:
        params ([type]): [description]
        g ([type]): [description]
        D ([type]): [description]
        sku ([type]): [Secret key of user u]
        pkfs ([type]): [Public key of Front Server]
        pkbs ([type]): [Public key of Back Srever]
        EDB ([type]): [description]
        XSet ([type]): [description]

    Returns:
        [type]: [description]
    """
    logging.info("==================EDBSetup Start==================")

    pairing = Pairing(params)
    alpha=sku["sk"]
    pku=Element(pairing,G1,value=g ** alpha)
    zone=Element.one(pairing,Zr)
    #print(D)
    [filePath,WindSet]=D

    ind=generate_random_str(32)
    fileOrigin=open(filePath,"r")
    fileData=fileOrigin.read()
    Kind=generate_random_str(16)
    iv=generate_random_str(16)
    fileEncrypted=encrypt(fileData,Kind,iv)

    path="maildirENC/"
    createFile(fileEncrypted,path+ind,"wb")


    for keyword,content in WindSet.items():
        c=Get(0,content)
        c=c+1
        Update(0,content,c)

    indByte=str(ind).encode()
    xind=PRF_Fp(params,sku["Kx"],indByte)
    for keyword,content in WindSet.items():
        r1=Element.random(pairing,Zr) 
        c=Get(0,content)

        cw=str(c).encode('utf-8')
        w=str(content).encode('utf-8')
        
        l=PRF_F(sku["Kl"],w+cw)
        z=PRF_Fp(params,sku["Kz"],w+cw)
        m=pairing.apply(Element.random(pairing,G1), Element.random(pairing,G1))
        inds[str(m)]=[filePath,ind,Kind,iv]
        IndsCopy[str(m)]=[str(filePath),str(ind),str(Kind),str(iv)]

        a=Element(pairing, G1, value=g ** r1)   #g^r1
        hashE0 = Element.from_hash(pairing, G1, Hash1(str(pku).encode()).hexdigest())#H(g^alpha)
        temp=pairing.apply(a,Element(pairing,G1,value=hashE0 ** alpha))
        b=Element(pairing, GT, value= m * temp )
        e0={"a":a,"b": b}   #(g^r1,m*g^{alpha*r1})
        e1=Element(pairing,Zr,value=(xind * z * alpha)) #xind*z*alpha
        EDB[l]={"e0":e0,"e1":e1}
        EDBCopy[l]={"e0":{"a":str(a),"b":str(b)},"e1":str(e1)}

        hash_value = Element.from_hash(pairing, G1, Hash1(w).hexdigest())   #H1(w)
        xtag=pairing.apply(Element(pairing,G1,value=pkfs/pkbs), Element(pairing,G1,value=hash_value ** xind))   #e(g^{gamma-eta},H1(w)^xind)
        XSet[l]=xtag
        XSetCopy[l]=str(xtag)

    logging.info("==================EDBSetup End==================")
    return [EDB,XSet]

def TrapGen(params,g,skv,pkfs,pkbs,Q):
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
    logging.info("==================TrapGen Start==================")
    pairing = Pairing(params)
    zone=Element.one(pairing,Zr)
    beta=skv["sk"]

    i=1
    n=0
    while(i<len(Q)):
        wNumber=Get(0,Q[i])
        if(wNumber>n):
            n=wNumber
        i=i+1

    logging.info("Trap length is %s",n)
    q=len(Q)
    logging.info("Send to Front Server for %s times",n)
    logging.info("Query Keywords = %s",Q)
    logging.info("Query keyword number = %d",q-1)

    l={}
    Trap={}
    i=1
    while(i<=n):
        Trap[i]={}
        i=i+1

    i=1
    while(i<=n):
        w1=str(Q[1]).encode('utf-8')
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
            j=j+1
        i=i+1

    tokenfs=[l,Trap]
    logging.info("==================TrapGen End==================")
    return tokenfs

def TrapGenThroughFile(params,g,skv,pkfs,pkbs,Q,V):
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
    logging.info("==================TrapGen Start==================")
    pairing = Pairing(params)
    zone=Element.one(pairing,Zr)
    beta=skv["sk"]

    i=1
    n=Get(0,Q[i])

    logging.info("Trap length is %s",n)
    q=len(Q)
    logging.info("Send to Front Server for %s times",n)
    logging.info("Query Keywords = %s",Q)
    logging.info("Query keyword number = %d",q-1)

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
    writeFile("tokenfs.dat",tokenfsCopy)
    logging.info("==================TrapGen End==================")
    return tokenfs

def FrontTest(params,g,tokenfs,skfs):
    """[Front Server generate state for Back Server]

    Args:
        params ([type]): [description]
        g ([type]): [description]
        tokenfs ([type]): [Token tokenfs received from User]
        skfs ([type]): [Secret key of Front Server]

    Returns:
        [type]: [Token tokenbs for Back Server]
    """
    logging.info("==================FrontTest Start==================")
    pairing = Pairing(params)
    zone=Element.one(pairing,Zr)
    ztwo=Element(pairing,Zr,value=2)
    [l,Trap]=tokenfs
    Status={}
    i=1
    while(i<=len(Trap)):
        Status[i]={}
        i=i+1

    i=1
    while(i<=len(Trap)):
        j=1
        while(j<=len(Trap[i])):
            [T1,T2]=Trap[i][j]
            T2g=Element(pairing,G1,value=T2 ** skfs["sk"])
            T1g=Element(pairing,G1,value=T1 ** (skfs["sk"] ** ztwo))
            Tg=Element(pairing,G1,value=T2g /T1g)
            Status[i][j]=Tg # Tgamma=T2^{gamma}  /  T1^{gamma^2}
            j=j+1
        i=i+1

    tokenbs=[l,Trap,Status]
    logging.info("==================FrontTest End==================")
    return tokenbs

def FrontTestThroughFile(params,g,tokenfs,skfs):
    """[Front Server generate state for Back Server]

    Args:
        params ([type]): [description]
        g ([type]): [description]
        tokenfs ([type]): [Token tokenfs received from User]
        skfs ([type]): [Secret key of Front Server]

    Returns:
        [type]: [Token tokenbs for Back Server]
    """
    logging.info("==================FrontTest Start==================")
    pairing = Pairing(params)
    zone=Element.one(pairing,Zr)
    ztwo=Element(pairing,Zr,value=2)

    tokenfsCopy=loadFile("tokenfs.dat")

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
    writeFile("tokenbs.dat",tokenbsCopy)
    logging.info("==================FrontTest End==================")
    return tokenbs

def ReKeyGen(params,g,sku,pkv):
    """[User u generate re-encryption key]

    Args:
        params ([type]): [description]
        g ([type]): [description]
        sku ([type]): [Secret key of User u]
        pkv ([type]): [Public key of user v]

    Returns:
        [type]: [Re-encryption key]
    """
    logging.info("==================ReKeyGen Start==================")
    rkuv={}
    pairing=Pairing(params)
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

    logging.info("==================ReKeyGen End==================")
    return rkuv

def ReKeyGenThroughFile(params,g,sku,pkv):
    """[User u generate re-encryption key]

    Args:
        params ([type]): [description]
        g ([type]): [description]
        sku ([type]): [Secret key of User u]
        pkv ([type]): [Public key of user v]

    Returns:
        [type]: [Re-encryption key]
    """
    logging.info("==================ReKeyGen Start==================")
    rkuv={}
    pairing=Pairing(params)
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

    writeFile("rkuv.dat",rkuvCopy)
    logging.info("==================ReKeyGen End==================")
    return rkuv

def BackTest(params,g,tokenbs,skbs,rkuv,EDB,XSet):
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
    logging.info("==================BackTest Start==================")
    pairing = Pairing(params)
    zone=Element.one(pairing,Zr)
    ztwo=Element(pairing,Zr,value=2)
    gone=Element.one(pairing,G1)

    i=1
    [l,Trap,Status]=tokenbs
    
    isExistInEDB=0
    #判断是否存在EDB[li]
    while(i<=len(l)):
        for item in EDB.keys():
            if(l[i]==item):
                isExistInEDB=1
        i=i+1
    
    #print("isExistInEDB=",isExistInEDB)
    if(isExistInEDB==0):
        return 0
    
    b=1
    i=1
    #由于l是传过来的,省略0位置,此处要写<=
    while(i<=len(l)):
        if(l[i] in EDB.keys() and b==1):
            #print(EDB[l[i]])
            e1=EDB[l[i]]['e1']
            count=0
            j=1
            while(j<=len(Trap[i])):
                [T1,T2]=Trap[i][j]
                Tg=Status[i][j]
                T2e=Element(pairing,G1,value=T2 ** skbs["sk"])
                T1e=Element(pairing,G1,value=T1 ** (skbs["sk"] ** ztwo))
                Te=Element(pairing,G1,value=T2e /T1e)#  Teta=T2^{eta}  /  T1^{eta^2}

                UgUe=pairing.apply(Element(pairing,G1,value=rkuv[4] ** e1),Element(pairing,G1,value=Tg/Te))
                for item in XSet.values():
                    if(UgUe==item):
                        count=count+1
                        
                j=j+1
  
            if(count==len(Trap[i])):
                b=1
            else:
                b=0

        i=i+1
    
    logging.info("BackTest Result=%s",b)
    logging.info("==================BackTest End==================")
    return b

def BackTestThroughFile(params,g,tokenbs,skbs,rkuv):
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
    logging.info("==================BackTest Start==================")
    pairing = Pairing(params)
    zone=Element.one(pairing,Zr)
    ztwo=Element(pairing,Zr,value=2)
    gone=Element.one(pairing,G1)
    vector={}
    EDBCopy=loadFile("EDB.dat")
    XSetCopy=loadFile("XSet.dat")

    tokenbsCopy=loadFile("tokenbs.dat")
    [l,TrapCopy,StatusCopy,booleanVector]=tokenbsCopy

    rkuvCopy=loadFile("rkuv.dat")
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
    
    logging.info("BackTest Result=%s",b)
    logging.info("==================BackTest End==================")
    return b

def Search(params,g,tokenbs,skbs,rkuv,EDB,XSet):
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
        [type]: [Searched result]
    """
    logging.info("==================Search Start==================")
    pairing = Pairing(params)
    zone=Element.one(pairing,Zr)
    ztwo=Element(pairing,Zr,value=2)
    gone=Element.one(pairing,G1)
    i=1
    [l,Trap,Status]=tokenbs
    Res=list()
    #由于l是传过来的,省略0位置,此处要写<=
    while(i<=len(l)):
        if(l[i] in EDB.keys()):
            #print(EDB[l[i]])
            logging.info("Judge Trap[%s] UgUe is exist for j in XSet",i)
            e0=EDB[l[i]]['e0']
            e1=EDB[l[i]]['e1']
            count=0
            j=1
            while(j<=len(Trap[i])):
                [T1,T2]=Trap[i][j]
                Tg=Status[i][j]
                T2e=Element(pairing,G1,value=T2 ** skbs["sk"])
                T1e=Element(pairing,G1,value=T1 ** (skbs["sk"] ** ztwo))
                Te=Element(pairing,G1,value=T2e /T1e)#  Teta=T2^{eta}  /  T1^{eta^2}
                UgUe=pairing.apply(Element(pairing,G1,value=rkuv[4] ** e1),Element(pairing,G1,value=Tg/Te))

                for item in XSet.values():
                    if(UgUe==item):
                        count=count+1   
                
                j=j+1
            
            if(count==len(Trap[i])):
                a=Element(pairing,G1,value=e0["a"])
                b=Element(pairing,GT,value=e0["b"])
                c1=Element(pairing,G1,value=a)
                temp=pairing.apply(a,rkuv[3])
                c2=Element(pairing,GT,value=b*temp)
                c3=[rkuv[1],rkuv[2]]
                e=[c1,c2,c3]
                Res.append(e)
                logging.info("Check Trap[%s] UgUe success",i)
            else:
                logging.info("Check Trap[%s] UgUe fail",i)

        i=i+1
    logging.info("==================Search End==================")
    return Res

def SearchThroughFile(params,g,tokenbs,skbs,rkuv):
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
        [type]: [Searched result]
    """
    logging.info("==================Search Start==================")
    EDBCopy=loadFile("EDB.dat")
    XSetCopy=loadFile("XSet.dat")
    pairing = Pairing(params)
    zone=Element.one(pairing,Zr)
    ztwo=Element(pairing,Zr,value=2)
    gone=Element.one(pairing,G1)
    vector={}

    tokenbsCopy=loadFile("tokenbs.dat")
    [l,TrapCopy,StatusCopy,booleanVector]=tokenbsCopy

    rkuvCopy=loadFile("rkuv.dat")
    rkuv={}
    rkuv[1]=Element(pairing,G1,value=rkuvCopy[1])
    rkuv[2]=Element(pairing,G1,value=rkuvCopy[2])
    rkuv[3]=Element(pairing,G1,value=rkuvCopy[3])
    rkuv[4]=Element(pairing,G1,value=rkuvCopy[4])

    #[l,Trap,Status]=tokenbs
    i=1
    Res=list()
    ResCopy=list()
    #由于l是传过来的,省略0位置,此处要写<=
    while(i<=len(l)):
        if(l[i] in EDBCopy.keys()):
            #print(EDB[l[i]])
            logging.info("Judge Trap[%s] UgUe is exist for j in XSet",i)
            e0Copy=EDBCopy[l[i]]['e0']
            e0={}
            e0['a']=Element(pairing,G1,value=e0Copy['a'])
            e0['b']=Element(pairing,GT,value=e0Copy['b'])
            e1Copy=EDBCopy[l[i]]['e1']
            e1=Element(pairing,Zr,value=int(str(e1Copy),16))
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
            #if(count==len(TrapCopy[i])): #仅用于Conjuctive Search
                a=Element(pairing,G1,value=e0["a"])
                b=Element(pairing,GT,value=e0["b"])
                c1=Element(pairing,G1,value=a)
                temp=pairing.apply(a,rkuv[3])
                c2=Element(pairing,GT,value=b*temp)
                c3=[rkuv[1],rkuv[2]]
                e=[c1,c2,c3]
                Res.append(e)
                ResCopy.append([str(c1),str(c2),[str(rkuv[1]),str(rkuv[2])]])
                logging.info("Check Trap[%s] UgUe success",i)
            else:
                logging.info("Check Trap[%s] UgUe fail",i)

        i=i+1

    writeFile("Res.dat",ResCopy)
    logging.info("==================Search End==================")
    return Res

def Retrieve(params,g,Res,skv):
    """[Decrypt files with ind||Kind searched from Res]

    Args:
        params ([type]): [description]
        g ([type]): [Generator of G1]
        Res ([dict]): [Searched result]
        skv ([dict]): [Secret key of User v]

    Returns:
        [type]: [description]
    """
    logging.info("==================Retrieve Start==================")
    beta=skv["sk"]
    pairing = Pairing(params)
    if(Res):
        for item in Res:
            c1=Element(pairing,G1,value=item[0])
            c2=Element(pairing,GT,value=item[1])
            c3=item[2]
            #[c1,c2,c3]=item
            a=Element(pairing,G1,value=c3[0])
            b=Element(pairing,G1,value=c3[1])
            #[a,b]=c3
            X=Element(pairing,G1,value=b/(a ** beta))
            hash_value = Element.from_hash(pairing, G1, Hash1(str(X).encode()).hexdigest())
            temp=pairing.apply(c1,hash_value)#temp=e(g^{r1},H(X))
            m=Element(pairing,GT,value=c2/temp)
            
            #logging.info("The original file path %s. Now its name is %s",inds[str(m)][0],inds[str(m)][1])
            #logging.info("The Kind is %s, iv is %s",inds[str(m)][2],inds[str(m)][3])

            logging.info("Decrypting files")
            srcpath="maildirENC/"
            dstpath="maildirDEC/"

            ind=inds[str(m)][1]
            Kind=inds[str(m)][2]
            iv=inds[str(m)][3]
            file=open(srcpath+ind,"r")
            dataEnc=file.read()
            dataDec=decrypt(dataEnc,Kind,iv)
            createFile(dataDec,dstpath+ind,"w")

            
    else:
        logging.info("Res is null")
    
    logging.info("==================Retrieve End==================")
    return 0

def RetrieveThroughFile(params,g,Res,skv):
    """[Decrypt files with ind||Kind searched from Res]

    Args:
        params ([type]): [description]
        g ([type]): [Generator of G1]
        Res ([dict]): [Searched result]
        skv ([dict]): [Secret key of User v]

    Returns:
        [type]: [description]
    """
    logging.info("==================Retrieve Start==================")
    beta=skv["sk"]
    pairing = Pairing(params)
    ResCopy=loadFile("Res.dat")
    Res=ResCopy
    if(Res):
        for item in Res:
            c1=Element(pairing,G1,value=item[0])
            c2=Element(pairing,GT,value=item[1])
            c3=item[2]
            #[c1,c2,c3]=item
            a=Element(pairing,G1,value=c3[0])
            b=Element(pairing,G1,value=c3[1])
            #[a,b]=c3
            X=Element(pairing,G1,value=b/(a ** beta))
            hash_value = Element.from_hash(pairing, G1, Hash1(str(X).encode()).hexdigest())
            temp=pairing.apply(c1,hash_value)#temp=e(g^{r1},H(X))
            m=Element(pairing,GT,value=c2/temp)
            
            #logging.info("The original file path %s. Now its name is %s",inds[str(m)][0],inds[str(m)][1])
            #logging.info("The Kind is %s, iv is %s",inds[str(m)][2],inds[str(m)][3])

            logging.info("Decrypting files")
            srcpath="maildirENC/"
            dstpath="maildirDEC/"

            ind=inds[str(m)][1]
            Kind=inds[str(m)][2]
            iv=inds[str(m)][3]
            file=open(srcpath+ind,"r")
            dataEnc=file.read()
            dataDec=decrypt(dataEnc,Kind,iv)
            createFile(dataDec,dstpath+ind,"w")
        
    else:
        logging.info("Res is null")
    
    logging.info("==================Retrieve End==================")
    return 0

def main():
    """[Main function]
    """
    logging.info("==================main Start==================")
    #DList=GetDList("maildir/allen-p/straw")
    DList=GetDList("maildir/allen-p/sent_items")

    [params,g,Kx,Kz,Kl]=GlobalSetup(512, 160)
    [pkfs,skfs,pkbs,skbs]=KeyGenServer(params,g,Kx,Kz,Kl)
    [pku,sku]=KeyGenReceiver(params, g, Kx, Kz, Kl)
    [pkv,skv]=KeyGenReceiver(params, g, Kx, Kz, Kl)

    EDB={}
    XSet={}

    EDBSetupTimeStart=datetime.now()
    for item in DList.items():
        [EDB,XSet]=EDBSetup(params, g, item, sku, pkfs, pkbs,EDB,XSet)
    EDBSetupTimeEnd=datetime.now()
    timeleapEDB=EDBSetupTimeEnd-EDBSetupTimeStart

    ReKeyGenTimeStart=datetime.now()
    rkuv=ReKeyGen(params,g,sku,pkv)
    ReKeyGenTimeEnd=datetime.now()
    timeleapReKeyGen=ReKeyGenTimeEnd-ReKeyGenTimeStart

    #Q=["","calxa@aol.com","Lime"]
    Q=["","phillip.allen@enron.com","Request","Steve"]
    TrapGenTimeStart=datetime.now()
    #tokenfs=TrapGenThroughFile(params,g,skv,pkfs,pkbs,Q)
    tokenfs=TrapGen(params,g,skv,pkfs,pkbs,Q)
    TrapGenTimeEnd=datetime.now()
    timeleapTrapGen=TrapGenTimeEnd-TrapGenTimeStart

    FrontTestTimeStart=datetime.now()
    #tokenbs=FrontTestThroughFile(params,g,tokenfs,skfs)
    tokenbs=FrontTest(params,g,tokenfs,skfs)
    FrontTestTimeEnd=datetime.now()
    timeleapFrontTest=FrontTestTimeEnd-FrontTestTimeStart

    BackTestTimeStart=datetime.now()
    b=BackTest(params,g,tokenbs,skbs,rkuv,EDB,XSet)
    #b=BackTestThroughFile(params,g,tokenbs,skbs,rkuv)
    BackTestTimeEnd=datetime.now()
    timeleapBackTest=BackTestTimeEnd-BackTestTimeStart

    SearchTimeStart=datetime.now()
    Res=Search(params,g,tokenbs,skbs,rkuv,EDB,XSet)
    #Res=SearchThroughFile(params,g,tokenbs,skbs,rkuv)
    SearchTimeEnd=datetime.now()
    timeleapSearch=SearchTimeEnd-SearchTimeStart

    RetrieveTimeStart=datetime.now()
    Retrieve(params,g,Res,skv)
    RetrieveTimeEnd=datetime.now()
    timeleapRetrieve=RetrieveTimeEnd-RetrieveTimeStart

    logging.info("EDBSetup Time: %s seconds, %s microseconds",timeleapEDB.seconds,timeleapEDB.microseconds)
    logging.info("ReKeyGen Time: %s seconds, %s microseconds",timeleapReKeyGen.seconds,timeleapReKeyGen.microseconds)
    logging.info("TrapGen Time: %s seconds, %s microseconds",timeleapTrapGen.seconds,timeleapTrapGen.microseconds)
    logging.info("FrontTest Time: %s seconds, %s microseconds",timeleapFrontTest.seconds,timeleapFrontTest.microseconds)
    logging.info("BackTest Time: %s seconds, %s microseconds",timeleapBackTest.seconds,timeleapBackTest.microseconds)
    logging.info("Search Time: %s seconds, %s microseconds",timeleapSearch.seconds,timeleapSearch.microseconds)
    logging.info("Retrieve Time: %s seconds, %s microseconds",timeleapRetrieve.seconds,timeleapRetrieve.microseconds)

    logging.info("==================main End==================")

def vice():
    """[Vice function]
    """
    #log=initLogging("log",Exception)
    logging.info("==================vice Start==================")

    DList=GetDList("maildir/allen-p/straw")
    #DList=GetDList("maildir/allen-p")

    Q=["","calxa@aol.com","Lime","rob_tom@freenet.carleton.ca"]
    #Q=["","phillip.allen@enron.com","Request","Steve"]
    
    V=[0,1,1,1]

    if(isFirst):
        [params,g,Kx,Kz,Kl]=GlobalSetupThroughFile(512, 160)
        KeyGenServerThroughFile(params,g,Kx,Kz,Kl)
        KeyGenReceiverUThroughFile(params, g, Kx, Kz, Kl)
        KeyGenReceiverVThroughFile(params, g, Kx, Kz, Kl)

    [ppCopy,serverKeyCopy,uKeyCopy,vKeyCopy]=readPublicFiles()
    [paramsCopy,gCopy,KxCopy,KzCopy,KlCopy]=ppCopy
    [pkfsCopy,skfsCopy,pkbsCopy,skbsCopy]=serverKeyCopy
    [pkuCopy,skuCopy]=uKeyCopy
    [pkvCopy,skvCopy]=vKeyCopy

    params = Parameters(paramsCopy)
    pairing = Pairing(params) 
    g=Element(pairing,G1,value=gCopy)

    pkfs=Element(pairing,G1,value=pkfsCopy)
    skfs=skfsCopy
    skfs['sk']=Element(pairing,Zr,value=int(skfsCopy['sk'],16))

    pkbs=Element(pairing,G1,value=pkbsCopy)
    skbs=skbsCopy
    skbs['sk']=Element(pairing,Zr,value=int(skbsCopy['sk'],16))

    pku=Element(pairing,G1,value=pkuCopy)
    sku=skuCopy
    sku['sk']=Element(pairing,Zr,value=int(skuCopy['sk'],16))

    pkv=Element(pairing,G1,value=pkvCopy)
    skv=skvCopy
    skv['sk']=Element(pairing,Zr,value=int(skvCopy['sk'],16))

    EDB={}
    XSet={}
    EDBSetupTimeStart=datetime.now()
    if(isFirst):
        for item in DList.items():
            [EDB,XSet]=EDBSetup(params, g, item, sku, pkfs, pkbs,EDB,XSet)
        storeEXIFiles(EDBCopy,XSetCopy,IndsCopy)
    EDBSetupTimeEnd=datetime.now()
    timeleapEDB=EDBSetupTimeEnd-EDBSetupTimeStart
    writeFile("WSet.dat",str(WSet))

    ReKeyGenTimeStart=datetime.now()
    rkuv=ReKeyGenThroughFile(params,g,sku,pkv)
    ReKeyGenTimeEnd=datetime.now()
    timeleapReKeyGen=ReKeyGenTimeEnd-ReKeyGenTimeStart

    TrapGenTimeStart=datetime.now()
    tokenfs=TrapGenThroughFile(params,g,skv,pkfs,pkbs,Q,V)
    TrapGenTimeEnd=datetime.now()
    timeleapTrapGen=TrapGenTimeEnd-TrapGenTimeStart

    FrontTestTimeStart=datetime.now()
    tokenbs=FrontTestThroughFile(params,g,tokenfs,skfs)
    FrontTestTimeEnd=datetime.now()
    timeleapFrontTest=FrontTestTimeEnd-FrontTestTimeStart

    BackTestTimeStart=datetime.now()
    b=BackTestThroughFile(params,g,tokenbs,skbs,rkuv)
    BackTestTimeEnd=datetime.now()
    timeleapBackTest=BackTestTimeEnd-BackTestTimeStart

    SearchTimeStart=datetime.now()
    Res=SearchThroughFile(params,g,tokenbs,skbs,rkuv)
    SearchTimeEnd=datetime.now()
    timeleapSearch=SearchTimeEnd-SearchTimeStart

    RetrieveTimeStart=datetime.now()
    RetrieveThroughFile(params,g,Res,skv)
    RetrieveTimeEnd=datetime.now()
    timeleapRetrieve=RetrieveTimeEnd-RetrieveTimeStart

    
    logging.info("EDBSetup Time: %s s, %s ms",timeleapEDB.seconds,timeleapEDB.microseconds)
    logging.info("ReKeyGen Time: %s s, %s ms",timeleapReKeyGen.seconds,timeleapReKeyGen.microseconds)
    logging.info("TrapGen Time: %s s, %s ms",timeleapTrapGen.seconds,timeleapTrapGen.microseconds)
    logging.info("FrontTest Time: %s s, %s ms",timeleapFrontTest.seconds,timeleapFrontTest.microseconds)
    logging.info("BackTest Time: %s s, %s ms",timeleapBackTest.seconds,timeleapBackTest.microseconds)
    logging.info("Search Time: %s s, %s ms",timeleapSearch.seconds,timeleapSearch.microseconds)
    logging.info("Retrieve Time: %s s, %s ms",timeleapRetrieve.seconds,timeleapRetrieve.microseconds)
    logging.info("==================vice End==================")

def GetDList(dir):
    """[Reading files in deep]

    Args:
        dir ([str]): [Dir]

    Returns:
        [dict]: [Email dictionary]
    """
    logging.info("==================GetDList Start==================")
    
    p = Path(dir) 
    DList={}
    FileList=list(p.glob("**/*.")) #递归查询文件
    for filepath in FileList:
        logging.info("Reading %s",filepath)
        f=open(filepath, "rb+")
        byt = f.read()
        data=byt.decode("ISO-8859-1")
        #data=f.read()
        email = Parser().parsestr(data)

        #针对文件subject实现模糊搜索
        subject=email['subject']
        words= word_tokenize(subject)
        for word in words:
            email[word]=word

        #针对文件subject实现模糊搜索 
        # article=email.get_payload()
        # articlewords= word_tokenize(article)
        # useful_words = [word  for word in articlewords if word not in stopwords.words('english')]
        # frequency = nltk.FreqDist(useful_words)
        # frequency.most_common(10)
        # for item in frequency:
        #     email[item]=item

        DList[filepath]=email
        for key,value in email.items():
            print(key,value)

    logging.info("==================GetDList End==================")
    return DList

def add_to_16(text):
    """[Append text to be enough for times of 16]

    Args:
        text ([str]): [Original text]

    Returns:
        [str]: [Qualified text]
    """
    #text=text.encode()
    if len(text) % 16:
        add = 16 - (len(text) % 16)
    else:
        add = 0
    text = text + ('\0' * add)
    return text

def encrypt(text,key,iv):
    """[Encrypt data by AES]

    Args:
        text ([str]): [Plain data]
        key ([str]): [AES key must be times of 16]
        iv ([str]): [iv must be times of 16]

    Returns:
        [byte]: [Encrypted data]
    """
    key = key.encode('utf-8')
    mode = AES.MODE_CBC
    #iv = b'qqqqqqqqqqqqqqqq'
    iv=iv.encode('utf-8')
    text = add_to_16(text)
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(text)
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
    return b2a_hex(cipher_text)

def decrypt(text,key,iv):
    """[Decrypt encrypted data by AES]

    Args:
        text ([str]): [Encrypted data]
        key ([str]): [AES key must be times of 16]
        iv ([str]): [iv must be times of 16]

    Returns:
        [str]: [Decrypted data]
    """
    key = key.encode('utf-8')
    mode = AES.MODE_CBC
    #iv = b'qqqqqqqqqqqqqqqq'
    iv=iv.encode('utf-8')
    cryptos = AES.new(key, mode, iv)
    plain_text = cryptos.decrypt(a2b_hex(text))
    return bytes.decode(plain_text).rstrip('\0')# 解密后，去掉补足的空格用strip() 去掉

def generate_random_str(randomlength=16):
    """[生成一个指定长度的随机字符串]

    Args:
        randomlength (int, optional): [description]. Defaults to 16.

    Returns:
        [str]: [String in random]
    """
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'
    length = len(base_str) - 1
    for i in range(randomlength):
        random_str += base_str[random.randint(0, length)]
    return random_str

def catchMainKeyword(data):
    words= word_tokenize(data)
    useful_words = [word  for word in words if word not in (stopwords.words('english') and string.punctuation)]
    frequency = nltk.FreqDist(useful_words)
    return frequency.most_common(100)

def createFile(data,dstpath,type):
    """[给定一个文件路径,自动创建文件夹并新建文件]

    Args:
        data ([str|byte]): [Depends on parameter type]
        dstpath ([str]): [The file path you want to create]
        type ([str]): [r,w,x,b]

    Returns:
        [int]: [Not in use]
    """
    path=dstpath.split("/")
    i=0
    temp=""
    while(i<len(path)):
        temp += path[i]
        if(i+1<len(path)):#代表这就是个文件夹
            if(not os.path.exists(temp)):
                os.mkdir(temp)
            temp+="/"
        else:#即文件
            logging.info("Creating %s",temp)
            f=open(temp,type)
            f.write(data)
        i+=1

    return 0

def storeEXIFiles(EDBCopy,XSetCopy,IndsCopy):
    writeFile("EDB.dat",str(EDBCopy))
    writeFile("XSet.dat",str(XSetCopy))
    writeFile("Inds.dat",str(IndsCopy))

def readWSet():
    path="WSet.dat"
    WSetLocal={}
    if(os.path.exists(path)):
        fileWSet=open(path,"r")
        WSetLocal=eval(fileWSet.read())
    return WSetLocal

def writeFile(filePath,data):
    logging.info("Creating %s file",filePath)
    fileCopy=open(filePath,"w")
    fileCopy.write(str(data))
    #uploadfiletoserver(localRootPath+filePath,remoteRootPath+filePath)

def loadFile(filePath):
    logging.info("Reading %s file",filePath)
    fileCopy=open(filePath,"r")
    Copy=eval(fileCopy.read())
    return Copy

def readPublicFiles():
    ppCopy=loadFile("pp.dat")
    [paramsCopy,gCopy,KxCopy,KzCopy,KlCopy]=ppCopy
    Kx=KxCopy.encode()
    Kz=KzCopy.encode()
    Kl=KlCopy.encode()

    serverKeyCopy=loadFile("serverKey.dat")
    [pkfsCopy,skfsCopy,pkbsCopy,skbsCopy]=serverKeyCopy
    skfsCopy['Kx']=Kx
    skfsCopy['Kz']=Kz
    skfsCopy['Kl']=Kl
    skbsCopy['Kx']=Kx
    skbsCopy['Kz']=Kz
    skbsCopy['Kl']=Kl

    uKeyCopy=loadFile("uKey.dat")
    [pkuCopy,skuCopy]=uKeyCopy
    skuCopy['Kx']=Kx
    skuCopy['Kz']=Kz
    skuCopy['Kl']=Kl

    vKeyCopy=loadFile("vKey.dat")
    [pkvCopy,skvCopy]=vKeyCopy
    skvCopy['Kx']=Kx
    skvCopy['Kz']=Kz
    skvCopy['Kl']=Kl

    return [ppCopy,serverKeyCopy,uKeyCopy,vKeyCopy]

def uploadfiletoserver(local,remote):#上传文件到服务器.local是要上传文件的本地路径；remote是上传到服务器的路径
    logging.info("Uploading %s to %s",local,remote)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, port, username, password)
 
    sftp = ssh.open_sftp()
    sftp.put(local, remote)
    return remote

def initLogging(logFilename,e):

  logging.basicConfig(
                    level = logging.INFO,
                    format ='%(asctime)s-%(levelname)s-%(message)s',
                    datefmt = '%y-%m-%d %H:%M',
                    filename = logFilename,
                    filemode = 'a')
  
  filehandler = logging.FileHandler(logFilename,encoding='utf-8')
  logging.getLogger().addHandler(filehandler )
  log = logging.exception(e)
  return log

if __name__ == '__main__':
    vice()
    
    