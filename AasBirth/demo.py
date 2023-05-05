from typing import DefaultDict
from pypbc import *
import hashlib
import random
import logging
from pathlib import Path
from email.parser import Parser
#import paramiko
import os
from wolfcrypt.hashes import HmacSha256

import nltk
from nltk.tokenize import *
from nltk.corpus import stopwords
from string import punctuation
import string
from datetime import datetime,timedelta

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

Hash1 = hashlib.sha256
Hash2 = hashlib.sha256
Hash3 = hashlib.sha256

logger=logging.getLogger("Caedios")
logger.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
file_handler = logging.FileHandler("log")
file_handler.setLevel(level=logging.INFO)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

logTime=logging.getLogger("logTime")
logTime.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
fileTime_handler = logging.FileHandler("logTime")
fileTime_handler.setLevel(level=logging.INFO)
fileTime_handler.setFormatter(formatter)
logTime.addHandler(fileTime_handler)

ParameterPathFromTools="Parameter/"
ServerPathFromTools="Server/"
ClientPathFromTools="Client/"
MailEncPathFromTools="MailEnc/"
MailDecPathFromTools="MailDec/"

WSet={}
Inds={}
IndsCopy={}

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
    return c

def Update(delta,w,c,WSet):
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

def MACKeyGen():
    return "0123456789012345"

def MACSign(key,sigma):
    h = HmacSha256(str(key))
    h.update(str(sigma))
    Tag=h.hexdigest()
    return Tag

def MACVerify(key,sigma,Tag):
    h = HmacSha256(str(key))
    h.update(str(sigma))
    Tag2=h.hexdigest()
    if(str(Tag)==str(Tag2)): b=1
    else: b=0
    return b

def GlobalSetup(qbits=512, rbits=160):
    """[KGC generate public parameter]

    Args:
        qbits (int, optional): [description]. Defaults to 512.
        rbits (int, optional): [description]. Defaults to 160.

    Returns:
        [type]: [description]
    """
    logger.info("==================GlobalSetup Start==================")
    params = Parameters(qbits=qbits, rbits=rbits)   
    pairing = Pairing(params)  
    g = Element.random(pairing, G1)  
    alpha = Element.random(pairing,Zr)  
    gamma = Element.random(pairing,Zr) 
    #h = Element(pairing, G1, value=g ** alpha)
    Kx="Kx".encode('utf-8')
    Kz="Kz".encode('utf-8')
    Kl="Kl".encode('utf-8')
    Ky="Ky".encode('utf-8')

    PP=[params,g]
    MK=[Kx,Kz,Kl,Ky,gamma,alpha]

    PPCopy=[str(params),str(g)]
    MKCopy=[str(Kx),str(Kz),str(Kl),str(Ky),str(gamma),str(alpha)]

    createFile(ServerPathFromTools+ParameterPathFromTools+"PP.dat",str(PPCopy),"w")
    createFile(ServerPathFromTools+ParameterPathFromTools+"MK.dat",str(MKCopy),"w")

    logger.info("==================GlobalSetup End==================")
    return [PP,MK]

def KeyGenS(PP,MK):
    logger.info("==================KeyGenS End==================")
    [params,g]=PP
    [Kx,Kz,Kl,Ky,gamma,alpha]=MK
    pairing = Pairing(params)
    beta = Element.random(pairing,Zr)
    h=Element(pairing, G1, value=g ** beta) 
    sks=[alpha,beta]
    pks=h

    sksCopy=[str(alpha),str(beta)]
    pksCopy=str(h)
    createFile(ServerPathFromTools+ParameterPathFromTools+"sks.dat",str(sksCopy),"w")
    createFile(ServerPathFromTools+ParameterPathFromTools+"pks.dat",str(pksCopy),"w")

    logger.info("==================KeyGenS End==================")
    return [pks,sks]

def KeyGenC(PP,MK,ATT):
    logger.info("==================KeyGenC End==================")
    [params,g]=PP
    [Kx,Kz,Kl,Ky,gamma,alpha]=MK
    pairing = Pairing(params)
    r=Element.random(pairing,Zr)
    v=Element(pairing,G1,value=g**(alpha*r))

    A=getAbyATT(params,g,gamma,ATT)
    Alpha=Element(pairing,G1,value=A**alpha)

    skc=[Kx,Kz,Kl,Ky,gamma,v,Alpha]
    skcCopy=[str(Kx),str(Kz),str(Kl),str(Ky),str(gamma),str(v),str(Alpha)]
    createFile(ServerPathFromTools+ParameterPathFromTools+"skc.dat",str(skcCopy),"w")
    logger.info("==================KeyGenC End==================")
    return skc

def EDBSetup(PP,D,skc,pks,ATT0,EDB,XSet):
    [params,g]=PP
    [Kx,Kz,Kl,Ky,gamma,v,Alpha]=skc
    pairing = Pairing(params)
    [filePath,WindSet]=D
    ind=generate_random_str(32)
    try:
        fileOrigin=open(filePath,"r")
        fileData=fileOrigin.read()
    except Exception as e:
        logger.info(e)
        return [EDB,XSet]

    Kind=generate_random_str(32)
    iv=generate_random_str(16)
    fileEncrypted=encrypt(fileData,Kind,iv)

    path=ServerPathFromTools+MailEncPathFromTools
    createFile(path+ind,fileEncrypted,"wb")

    for keyword,content in WindSet.items():
        c=Get(0,content)
        c=c+1
        Update(0,content,c)

    indString=str(ind).encode()
    xind=PRF_Fp(params,Kx,indString)
    for keyword,content in WindSet.items():
        c=Get(0,content)
        cString=str(c).encode()
        wString=str(content).encode()
        l=PRF_F(Kl,cString+wString)
        z=PRF_Fp(params,Kz,cString+wString)
        ATTString=str(ATT0).encode()
        vString=str(v).encode()
        eta=PRF_Fp(params,Ky,ATTString+vString)

        temp=Element.random(pairing,Zr)
        m=Element(pairing,G1,value=g**temp)
        Inds[str(m)]=[ind,Kind,iv]
        IndsCopy[str(m)]=[str(ind),str(Kind),str(iv)]
        e0=Element(pairing,G1,value=m*(g**gamma))
        e1=Element(pairing,G1,value=g**(z*xind))
        hashValue=Element.from_hash(pairing,Zr,Hash1(wString).hexdigest())
        e2=Element(pairing,G1,value=g**(gamma*hashValue*xind))
        t=Element.random(pairing,Zr)
        temp1=Element(pairing,G1,value=pks**t) # = g^{beta*t}
        temp2=Element(pairing,G1,value=g**eta) # = g^{eta}
        e3=Element(pairing,G1,temp1*temp2)
        e4=Element(pairing,G1,value=g**t)
        EDB[l]={"e0":e0,"e1":e1,"e2":e2,"e3":e3,"e4":e4}
        xtag=pairing.apply(e4,e2)
        XSet[l]=xtag

    return [EDB,XSet]

def DBSetup(PP,D,skc,pks,ATT0,DB,DBCopy):
    [params,g]=PP
    [Kx,Kz,Kl,Ky,gamma,v,Alpha]=skc
    pairing = Pairing(params)
    [filePath,WindSet]=D
    EDB={}
    XSet={}
    EDBCopy={}
    XSetCopy={}
    ind=generate_random_str(32)
    try:
        fileOrigin=open(filePath,"r")
        fileData=fileOrigin.read()
    except Exception as e:
        logger.info("Reading File Failed",e)
        return DB

    Kind=generate_random_str(32)
    iv=generate_random_str(16)
    fileEncrypted=encrypt(fileData,Kind,iv)

    path=ServerPathFromTools+MailEncPathFromTools
    createFile(path+ind,fileEncrypted,"wb")

    for keyword,content in WindSet.items():
        c=Get(0,content,WSet)
        c=c+1
        Update(0,content,c,WSet)

    indString=str(ind).encode()
    xind=PRF_Fp(params,Kx,indString)
    ATTString=str(ATT0).encode()
    vString=str(v).encode()
    eta=PRF_Fp(params,Ky,ATTString+vString)
    h1=Element(pairing,G1,value=g**eta)
    ld=Hash1(str(h1).encode()).hexdigest()
    temp2=Element(pairing,G1,value=g**eta) # = g^{eta}

    if(ld in DB.keys()):
        [EDB,XSet]=DB[ld]
        [EDBCopy,XSetCopy]=DBCopy[ld]
    
    for keyword,content in WindSet.items():
        c=Get(0,content,WSet)
        cString=str(c).encode()
        wString=str(content).encode()
        l=PRF_F(Kl,cString+wString)
        z=PRF_Fp(params,Kz,cString+wString)

        temp=Element.random(pairing,Zr)
        t=Element.random(pairing,Zr)
        m=Element(pairing,G1,value=g**temp)
        Inds[str(m)]=[ind,Kind,iv]
        IndsCopy[str(m)]=[str(ind),str(Kind),str(iv)]
        e0=Element(pairing,G1,value=m*(g**gamma)*(pks**t))
        e1=Element(pairing,G1,value=g**(z*xind))
        hashValue=Element.from_hash(pairing,Zr,Hash1(wString).hexdigest())
        e2=Element(pairing,G1,value=g**(gamma*hashValue*xind))
        temp1=Element(pairing,G1,value=pks**t) # = g^{beta*t}

        e3=Element(pairing,G1,temp1*temp2)
        e4=Element(pairing,G1,value=g**t)
        EDB[l]={"e0":e0,"e1":e1,"e2":e2,"e3":e3,"e4":e4}
        xtag=pairing.apply(e4,e2)
        XSet[l]=xtag

        EDBCopy[l]={"e0":str(e0),"e1":str(e1),"e2":str(e2),"e3":str(e3),"e4":str(e4)}
        XSetCopy[l]=str(xtag)


    DB[ld]=[EDB,XSet]
    DBCopy[ld]=[EDBCopy,XSetCopy]
    return DB,DBCopy

def AllSetup(PP,skc,pks,ATT0):
    DList=GetDList("../CSExperiment/maildir/corman-s/osha")
    EDB={}
    XSet={}
    logger.info("==================EDBSetup Start==================")
    for D in DList.items():
        [EDB,XSet]=EDBSetup(PP,D,skc,pks,ATT0,EDB,XSet)
    logger.info("==================EDBSetup End==================")
    return EDB,XSet

def AllSetupDB(PP,skc,pks,sks,ATT0,dictATT):
    DList=GetDList("../CSExperiment/maildir/corman-s/osha")
    DB={}
    DBCopy={}
    logger.info("==================AllSetupDB Start==================")
    i=0
    allTimeLeapDBSetup=timedelta()
    allTimeLeapTransPolicy=timedelta()
    allTimeLeapPolicyAdp=timedelta()
    for D in DList.items():
        i+=1
        logger.info("Attribute quantity is %s",i)
        DBSetupTimeStart=datetime.now()
        DB,DBCopy=DBSetup(PP,D,skc,pks,ATT0,DB,DBCopy)
        DBSetupTimeEnd=datetime.now()
        timeleapDBSetup=DBSetupTimeEnd-DBSetupTimeStart
        allTimeLeapDBSetup+=timeleapDBSetup
        logger.info("Encrypt 1 file Time: %s s","{:}.{:06}".format(timeleapDBSetup.seconds,timeleapDBSetup.microseconds))

        ATT2=dictATT[i]
        TransPolicyTimeStart=datetime.now()
        TransPolicyGen(PP,skc,pks,ATT0,ATT0,ATT2)
        TransPolicyTimeEnd=datetime.now()
        timeleapTransPolicy=TransPolicyTimeEnd-TransPolicyTimeStart
        allTimeLeapTransPolicy+=timeleapTransPolicy
        logger.info("Generate 1 TransPolicy Time: %s s","{:}.{:06}".format(timeleapTransPolicy.seconds,timeleapTransPolicy.microseconds))

        [sigma,Tag]=readPolicy(ServerPathFromTools)

        PolicyAdpTimeStart=datetime.now()
        DB=PolicyAdpDB(PP,sks,sigma,Tag,DB,DBCopy)
        PolicyAdpTimeEnd=datetime.now()
        timeleapPolicyAdp=PolicyAdpTimeEnd-PolicyAdpTimeStart
        allTimeLeapPolicyAdp+=timeleapPolicyAdp
        logger.info("Execute 1 PolicyAdp Time: %s s","{:}.{:06}".format(timeleapPolicyAdp.seconds,timeleapPolicyAdp.microseconds))

        if(i==50):i=0

    #print(len(DBCopy))
    createFile(ServerPathFromTools+ParameterPathFromTools+"DB.dat",str(DBCopy),"w")
    createFile(ServerPathFromTools+ParameterPathFromTools+"WSet.dat",str(WSet),"w")
    createFile(ServerPathFromTools+ParameterPathFromTools+"Inds.dat",str(IndsCopy),"w")

    logTime.info("Encrypt All DB Time: %s s","{:}.{:06}".format(allTimeLeapDBSetup.seconds,allTimeLeapDBSetup.microseconds))
    logTime.info("TransPolicy All Time: %s s","{:}.{:06}".format(allTimeLeapTransPolicy.seconds,allTimeLeapTransPolicy.microseconds))
    logTime.info("PolicyAdp All Time: %s s","{:}.{:06}".format(allTimeLeapPolicyAdp.seconds,allTimeLeapPolicyAdp.microseconds))
    

    logger.info("==================AllSetupDB End==================")
    return DB

def TransPolicyGen(PP,skc,pks,ATT0,ATT1,ATT2):
    [params,g]=PP
    [Kx,Kz,Kl,Ky,gamma,v,Alpha]=skc
    pairing = Pairing(params)
    t=Element.random(pairing,Zr)
    h=Element(pairing,G1,value=g**t)
    x1=[]
    y1=[]
    x1Copy=[]
    y1Copy=[]
    i=0
    while(i<len(ATT1)):
        hashValueX=Element.from_hash(pairing,Zr,Hash2(("2"+str(ATT1[i])).encode()).hexdigest())
        xi=Element(pairing,G1,value=g**(gamma*hashValueX))
        x1.append(xi)
        x1Copy.append(str(xi))
        hashValueY=Element.from_hash(pairing,Zr,Hash3(("3"+str(ATT1[i])).encode()).hexdigest())
        yi=Element(pairing,G1,value=g**(gamma*hashValueY))
        y1.append(yi)
        y1Copy.append(str(yi))
        i+=1

    x2=[]
    y2=[]
    x2Copy=[]
    y2Copy=[]
    i=0
    while(i<len(ATT2)):
        hashValueX=Element.from_hash(pairing,Zr,Hash2(("2"+str(ATT2[i])).encode()).hexdigest())
        xi=Element(pairing,G1,value=g**(gamma*hashValueX))
        x2.append(xi)
        x2Copy.append(str(xi))
        hashValueY=Element.from_hash(pairing,Zr,Hash3(("3"+str(ATT2[i])).encode()).hexdigest())
        yi=Element(pairing,G1,value=g**(gamma*hashValueY))
        y2.append(yi)
        y2Copy.append(str(yi))
        i+=1

    vString=str(v).encode()
    ATT1String=str(ATT1).encode()
    eta1=PRF_Fp(params,Ky,ATT1String+vString)
    h1=Element(pairing,G1,value=(pks**t)*(g**eta1))
    ATT2String=str(ATT2).encode()
    eta2=PRF_Fp(params,Ky,ATT2String+vString)
    h2=Element(pairing,G1,value=(pks**t)*(g**eta2))

    if(str(ATT0)==str(ATT1)):# 两者相等代表是第一次更新
        st=0
    else: # 否则是至少更新过一次
        st=1

    sigma=[x1,y1,x2,y2,h1,h2,h,st]
    sigmaCopy=[str(x1Copy),str(y1Copy),str(x2Copy),str(y2Copy),str(h1),str(h2),str(h),st]
    #print(sigmaCopy[0])
    Tag=MACSign(MACKeyGen(),sigma)
    TagCopy=str(Tag)
    policy=[str(sigmaCopy),str(TagCopy)]
    createFile(ClientPathFromTools+ParameterPathFromTools+"policy.dat",str(policy),"w")
    createFile(ServerPathFromTools+ParameterPathFromTools+"policy.dat",str(policy),"w")

    return [sigma,Tag]

def PolicyAdp(PP,sks,sigma,Tag,EDB,XSet):
    [params,g]=PP
    [alpha,beta]=sks
    [x1,y1,x2,y2,h1,h2,st]=sigma
    pairing = Pairing(params)
    B1=getBbyXY(params,g,x1,y1)
    B2=getBbyXY(params,g,x2,y2)
    ld1=1
    ld2=2
    #print(EDB)
    for key,value in EDB.items():
        e0=value['e0']
        e1=value['e1']
        e2=value['e2']
        e3=value['e3']
        e4=value['e4']
        e4Beta=Element(pairing,G1,value=e4**beta)
        temp=Element(pairing,G1,value=e3/e4Beta)
        if(h1==temp):
            B2Alpha=Element(pairing,G1,value=B2**alpha)
            if(st==0):# 代表第一次更新
                e0=Element(pairing,G1,value=e0*B2Alpha)
            else:# 代表至少更新过一次
                B1Alpha=Element(pairing,G1,value=B1**alpha)
                e0=Element(pairing,G1,value=e0/B1Alpha*B2Alpha)

            xtag=pairing.apply(B2Alpha,e2)
            XSet[key]=xtag

            e3=Element(pairing,G1,value=e3/h1*h2)
            EDB[key]={"e0":e0,"e1":e1,"e2":e2,"e3":e3,"e4":e4}
        else:
            break
    return [EDB,XSet]

def PolicyAdpDB(PP,sks,sigma,Tag,DB,DBCopy):
    if(MACVerify(MACKeyGen(),sigma,Tag)==0):#消息验证错误,不执行策略转换
        return DB

    [params,g]=PP
    [alpha,beta]=sks
    [x1,y1,x2,y2,h1,h2,h,st]=sigma
    pairing = Pairing(params)
    h1=Element(pairing,G1,value=h1/(h**beta))
    h2=Element(pairing,G1,value=h2/(h**beta))
    B1=getBbyXY(params,g,x1,y1)
    B2=getBbyXY(params,g,x2,y2)
    B1Alpha=Element(pairing,G1,value=B1**alpha)
    B2Alpha=Element(pairing,G1,value=B2**alpha)
    ld2=Hash1(str(B2Alpha).encode()).hexdigest()

    for ld,array in DB.items():
        EDB,XSet=array
        print(len(EDB))

    if(st==0):# 第一次策略转换
        ld1=Hash1(str(h1).encode()).hexdigest()
        if(ld1 in DB.keys()):
            [EDB,XSet]=DB[ld1]
            [EDBCopy,XSetCopy]=DBCopy[ld1]
            delKeys=list()
            for key,value in EDB.items():
                e0=value['e0']
                e1=value['e1']
                e2=value['e2']
                e3=value['e3']
                e4=value['e4']
                e4Beta=Element(pairing,G1,value=e4**beta)
                temp=Element(pairing,G1,value=e3/e4Beta)
                if(h1==temp):
                    if(st==0):# 代表第一次更新
                        e0=Element(pairing,G1,value=e0*B2Alpha/e4Beta)
                    else:# 代表至少更新过一次
                        e0=Element(pairing,G1,value=e0/B1Alpha*B2Alpha)

                    xtag=pairing.apply(B2Alpha,e2)
                    delKeys.append(key)
                    xtagCopy=str(xtag)
                    #XSet[key]=xtag

                    e3=Element(pairing,G1,value=e3/h1*h2)
                    tuple={"e0":e0,"e1":e1,"e2":e2,"e3":e3,"e4":e4}
                    tupleCopy={"e0":str(e0),"e1":str(e1),"e2":str(e2),"e3":str(e3),"e4":str(e4)}
                    #EDB[key]=tuple

                    if(ld2 in DB.keys()):# 如果本身ld2位置就有元素,逐个加入即可
                        DB[ld2][0][key]=tuple
                        DB[ld2][1][key]=xtag
                        DBCopy[ld2][0][key]=tupleCopy
                        DBCopy[ld2][1][key]=xtagCopy

                    else:
                        tempEDB={}
                        tempXSet={}
                        DB[ld2]=[tempEDB,tempXSet]
                        DB[ld2][0][key]=tuple
                        DB[ld2][1][key]=xtag
                        tempEDBCopy={}
                        tempXSetCopy={}
                        DBCopy[ld2]=[tempEDBCopy,tempXSetCopy]
                        DBCopy[ld2][0][key]=tupleCopy
                        DBCopy[ld2][1][key]=xtagCopy

                else:
                    continue
            #此时EDB与XSet都已经翻新过,删除原有字典,添加现在字典
            for key in delKeys:
                del EDB[key]
                del XSet[key]
                del EDBCopy[key]
                del XSetCopy[key]

            DB[ld1]=[EDB,XSet]
            DBCopy[ld1]=[EDBCopy,XSetCopy]
    else:# 第n次策略转换
        ld1=Hash1(str(B1Alpha).encode()).hexdigest()
        if(ld1 in DB.keys()):
            [EDB,XSet]=DB[ld1]
            [EDBCopy,XSetCopy]=DBCopy[ld1]
            print("EDB",len(EDB))
            delKeys=list()
            for key,value in EDB.items():
                e0=value['e0']
                e1=value['e1']
                e2=value['e2']
                e3=value['e3']
                e4=value['e4']
                e4Beta=Element(pairing,G1,value=e4**beta)
                temp=Element(pairing,G1,value=e3/e4Beta)
                print(h1)
                print(temp)
                print(h1==temp)
                if(h1==temp):
                    if(st==0):# 代表第一次更新
                        e0=Element(pairing,G1,value=e0*B2Alpha/e4Beta)
                    else:# 代表至少更新过一次
                        e0=Element(pairing,G1,value=e0/B1Alpha*B2Alpha)

                    xtag=pairing.apply(B2Alpha,e2)
                    delKeys.append(key)
                    xtagCopy=str(xtag)
                    #XSet[key]=xtag

                    e3=Element(pairing,G1,value=e3/h1*h2)
                    tuple={"e0":e0,"e1":e1,"e2":e2,"e3":e3,"e4":e4}
                    tupleCopy={"e0":str(e0),"e1":str(e1),"e2":str(e2),"e3":str(e3),"e4":str(e4)}
                    #EDB[key]=tuple

                    if(ld2 in DB.keys()):# 如果本身ld2位置就有元素,逐个加入即可
                        DB[ld2][0][key]=tuple
                        DB[ld2][1][key]=xtag
                        DBCopy[ld2][0][key]=tupleCopy
                        DBCopy[ld2][1][key]=xtagCopy
                    else:
                        tempEDB={}
                        tempXSet={}
                        DB[ld2]=[tempEDB,tempXSet]
                        DB[ld2][0][key]=tuple
                        DB[ld2][1][key]=xtag
                        tempEDBCopy={}
                        tempXSetCopy={}
                        DBCopy[ld2]=[tempEDBCopy,tempXSetCopy]
                        DBCopy[ld2][0][key]=tupleCopy
                        DBCopy[ld2][1][key]=xtagCopy

                else:
                    continue
            #此时EDB与XSet都已经翻新过,删除原有字典
            for key in delKeys:
                logger.info("delete",key)
                del EDB[key]
                del XSet[key]
                del EDBCopy[key]
                del XSetCopy[key]
            print("del",len(delKeys))
            print("EDB",len(EDB))
            DB[ld1]=[EDB,XSet]
            DBCopy[ld1]=[EDBCopy,XSetCopy]

    for ld,array in DB.items():
        EDB,XSet=array
        print(len(EDB))

    return DB

def TrapGen(PP,Q,skc):
    [params,g]=PP
    pairing = Pairing(params)
    [Kx,Kz,Kl,Ky,gamma,v,Alpha]=skc

    i=1
    n=Get(0,Q[1])
    logger.info("Trap length is %s",n)
    q=len(Q)
    logger.info("Send to Front Server for %s times",n)
    logger.info("Query Keywords = %s",Q)
    logger.info("Query keyword number = %d",q-1)

    l={}
    Trap={}

    i=1
    while(i<=n):
        Trap[i]={}
        #TrapCopy[i]={}
        i=i+1

    i=1
    while(i<=n):
        w1=str(Q[1]).encode('utf-8')
        c=str(i).encode('utf-8')
        l[i]=PRF_F(Kl,c+w1)
        z=PRF_Fp(params,Kz,c+w1)

        j=1
        #因为有个Q[0]是空,所以<
        while(j<q):
            wj=str(Q[j]).encode('utf-8')
            hash_value = Element.from_hash(pairing, Zr, Hash1(wj).hexdigest())   #H1(wj)
            trap=Element(pairing,G1,Alpha**(gamma*hash_value/z))
            Trap[i][j]=trap
            #TrapCopy[i][j]=[str(T1),str(T2)]
            j=j+1
        i=i+1
    token=[l,Trap]
    return token

def TrapGenDB(PP,Q,skc,WSet):
    [params,g]=PP
    pairing = Pairing(params)
    [Kx,Kz,Kl,Ky,gamma,v,Alpha]=skc

    i=1
    n=Get(0,Q[1],WSet)
    logger.info("Trap length is %s",n)
    q=len(Q)
    logger.info("Send to Front Server for %s times",n)
    logger.info("Query Keywords = %s",Q)
    logger.info("Query keyword number = %d",q-1)

    booleanVector={}
    i=1
    while(i<=q-1):
        booleanVector[i]=1
        i+=1

    l={}
    lCopy={}
    Trap={}
    TrapCopy={}

    i=1
    while(i<=n):
        Trap[i]={}
        TrapCopy[i]={}
        i=i+1

    i=1
    while(i<=n):
        w1=str(Q[1]).encode('utf-8')
        c=str(i).encode('utf-8')
        l[i]=PRF_F(Kl,c+w1)
        z=PRF_Fp(params,Kz,c+w1)

        j=1
        #因为有个Q[0]是空,所以<
        while(j<q):
            wj=str(Q[j]).encode('utf-8')
            hash_value = Element.from_hash(pairing, Zr, Hash1(wj).hexdigest())   #H1(wj)
            trap=Element(pairing,G1,Alpha**(gamma*hash_value/z))
            Trap[i][j]=trap
            TrapCopy[i][j]=str(trap)
            j=j+1
        i=i+1
    ld=Hash1(str(Alpha).encode()).hexdigest()
    token=[l,Trap,ld,booleanVector]
    tokenCopy=[str(l),TrapCopy,ld,booleanVector]
    createFile(ClientPathFromTools+ParameterPathFromTools+"token.dat",str(tokenCopy),"w")
    return token

def Search(PP,token,EDB,XSet):
    [params,g]=PP
    pairing = Pairing(params)
    vector={}
    booleanVector={}
    i=1
    [l,Trap]=token
    R=list()
    while(i<=len(l)):
        if(l[i] in EDB.keys()):
            logger.info("Judge Trap[%s] is exist for j in XSet",i)
            #print(type(l[i]))
            e0=EDB[l[i]]['e0']
            e1=EDB[l[i]]['e1']

            j=1
            while(j<=len(Trap[i])):
                trap=Trap[i][j]
                flag=0#判断本次关键字是否在XSet中
                trap=Element(pairing,G1,value=trap)
                e1=Element(pairing,G1,value=e1)
                temp=pairing.apply(trap,e1)
                for item in XSet.values():
                    #item=Element(pairing,GT,value=itemCopy)
                    if(temp==item):
                        #count=count+1 #仅用于Conjuctive Search
                        flag=1

                vector[j]=flag
                booleanVector[j]=1
                j=j+1
            #print(vector,booleanVector)
            if(vector==booleanVector):
                R.append(e0)
        i+=1
    return R

def SearchDB(PP,token,DB):
    [params,g]=PP
    pairing = Pairing(params)
    vector={}
    booleanVector={}
    EDB={}
    XSet={}

    [l,Trap,ld,booleanVector]=token
    R=list()
    RCopy=list()
    #print(DB.keys())
    #print(ld)
    if(ld in DB.keys()):
        [EDB,XSet]=DB[ld]

    i=1
    while(i<=len(l)):
        if(l[i] in EDB.keys()):
            logger.info("Judge Trap[%s] is exist for j in XSet?",i)
            #print(type(l[i]))
            e0=EDB[l[i]]['e0']
            e1=EDB[l[i]]['e1']

            j=1
            while(j<=len(Trap[i])):
                trap=Trap[i][j]
                flag=0#判断本次关键字是否在XSet中
                trap=Element(pairing,G1,value=str(trap))
                #print(trap)
                e1=Element(pairing,G1,value=e1)
                temp=pairing.apply(trap,e1)
                for item in XSet.values():
                    #item=Element(pairing,GT,value=itemCopy)
                    if(temp==item):
                        #count=count+1 #仅用于Conjuctive Search
                        flag=1

                vector[j]=flag
                #booleanVector[j]=1
                j=j+1
            #print(vector,booleanVector)
            #print(vector==booleanVector)
            if(vector==booleanVector):
                R.append(e0)
                RCopy.append(str(e0))
        i+=1

    createFile(ServerPathFromTools+ParameterPathFromTools+"Res.dat",str(RCopy),"w")
    return R

def Retrieve(PP,skc,R,Inds):
    [params,g]=PP
    pairing = Pairing(params)
    [Kx,Kz,Kl,Ky,gamma,v,Alpha]=skc
    gGamma=Element(pairing,G1,value=g**gamma)

    #这部分加个转换

    filesToReceive=list()
    for e0 in R:
        m=Element(pairing,G1,value=e0/(gGamma*Alpha))
        ind=Inds[str(m)][0]
        Kind=Inds[str(m)][1]
        iv=Inds[str(m)][2]
        tuple=[ind,Kind,iv]
        filesToReceive.append(tuple)
        #createFile(ClientPathFromTools+"passInd.dat",str(filesToReceive),"w")
    return filesToReceive

def RetrieveDecFiles(filesToReceive):
    #srcpath=ClientPathFromTools+MailEncPathFromTools
    srcpath=ServerPathFromTools+MailEncPathFromTools
    dstpath=ClientPathFromTools+MailDecPathFromTools
    #copy=loadFile(ClientPathFromTools+"passInd.dat")
    for tuple in filesToReceive:
        ind=tuple[0]
        Kind=tuple[1]
        iv=tuple[2]
        file=open(srcpath+ind,"r")
        dataEnc=file.read()
        dataDec=decrypt(dataEnc,Kind,iv)
        createFile(dstpath+ind,dataDec,"w")

def main():
    """[summary]

    Returns:
        [Attention]: [注意一下ATT必须排序之后进行lagrange]
        [User1]: [设定User1拥有属性ATT1]
        [User2]: [设定User1拥有属性ATT2]
    """
    ATT0=['NoAtt1','NoAtt2']
    #ATT1=['Att0','Att1', 'Att2', 'Att3', 'Att4', 'Att8', 'Att6', 'Att7', 'Att5', 'Att9', 'Att10']
    ATT1=['Att1', 'Att2','Att3']
    ATT1=sorted(ATT1)
    dictATT=getDictATT()
    
    Q=['','russell.tucker@enron.com','Revisions', 'to', 'CORMAN-S','scorman.nsf', 'Ergonomics', 'Program', 'Draft']
    DB={}

    [PP,MK]=GlobalSetup()
    PP=readPP(ServerPathFromTools)
    MK=readMK(ServerPathFromTools)

    KeyGenS(PP,MK)
    [pks,sks]=readServerKey(ServerPathFromTools)

    KeyGenC(PP,MK,ATT1)
    skc=readClientKey(ServerPathFromTools)

    AllSetupDB(PP,skc,pks,sks,ATT0,dictATT)
    DB=readDB(ServerPathFromTools)

    IndsLocal=readInds(ServerPathFromTools)
    WSetLocal=readWSet(ServerPathFromTools)

    TrapGenDB(PP,Q,skc,WSetLocal)
    token=readToken(ServerPathFromTools)

    SearchDB(PP,token,DB)
    R=readRes(ServerPathFromTools)

    filesToReceive=Retrieve(PP,skc,R,IndsLocal)
    RetrieveDecFiles(filesToReceive)

def vice():
   
    """[summary]

    Returns:
        [Attention]: [注意一下ATT必须排序之后进行lagrange]
        [User1]: [设定User1拥有属性ATT1]
        [User2]: [设定User1拥有属性ATT2]
    """
    ATT0=['NoAtt1','NoAtt2']
    ATT1=['Att0','Att1', 'Att2', 'Att3', 'Att4', 'Att8', 'Att6', 'Att7', 'Att5', 'Att9', 'Att10']
    ATT2=['Att1','Att0', 'Att2', 'Att3', 'Att8', 'Att6', 'Att7', 'Att5', 'Att10']
    Q=['','russell.tucker@enron.com','Revisions', 'to', 'CORMAN-S','scorman.nsf', 'Ergonomics', 'Program', 'Draft']
    ATT1=sorted(ATT1)
    ATT2=sorted(ATT2)
    DB={}

    [PP,MK]=GlobalSetup()
    [pks,sks]=KeyGenS(PP,MK)
    skc=KeyGenC(PP,MK,ATT1)
    skc2=KeyGenC(PP,MK,ATT2)
    [EDB,XSet]=AllSetup(PP,skc,pks,ATT0)
    [sigma,Tag]=TransPolicyGen(PP,skc,ATT0,ATT0,ATT2)
    [EDB,XSet]=PolicyAdp(PP,sks,sigma,Tag,EDB,XSet)

    token=TrapGen(PP,Q,skc2)
    R=Search(PP,token,EDB,XSet)
    filesToReceive=Retrieve(PP,skc2,R)
    RetrieveDecFiles(filesToReceive)
    

    return 1

def getAbyATT(params,g,gamma,ATT):
    pairing = Pairing(params)
    i=0
    x=[]
    y=[]
    while(i<len(ATT)):
        hashValueX=Element.from_hash(pairing,Zr,Hash2(("2"+str(ATT[i])).encode()).hexdigest())
        xi=Element(pairing,G1,value=g**(gamma*hashValueX))
        x.append(xi)
        hashValueY=Element.from_hash(pairing,Zr,Hash3(("3"+str(ATT[i])).encode()).hexdigest())
        yi=Element(pairing,G1,value=g**(gamma*hashValueY))
        y.append(yi)
        i+=1
    equation=mylagrange(params,g,x,y)
    A=Element.one(pairing,G1)
    i=0
    while(i<len(equation)):
        A=Element(pairing,G1,value=A*equation[i])
        i+=1
    return A

def getBbyXY(params,g,x,y):
    pairing = Pairing(params)
    equation=mylagrange(params,g,x,y)
    B=Element.one(pairing,G1)
    i=0
    while(i<len(equation)):
        B=Element(pairing,G1,value=B*equation[i])
        i+=1
    return B

def mylagrange(params,g,x,y):
    #logger.info("=======================mylagrange Start=======================")
    """[返回拉格朗日插值法系数]

    Args:
        params ([type]): [description]
        g ([type]): [description]
        x ([array]): [假定为G1的数组]
        y ([type]): [假定为G1的数组]

    Returns:
        [type]: [description]
    """
    mylagrangeTimeStart=datetime.now()

    
    equation={}
    pairing=Pairing(params)
    zzero=Element(pairing,G1,value=0)
    zone=Element.one(pairing,G1)
    j=0
    while(j<len(x)):
        #logger.info("针对%s等式",j)
        equationj={}
        k=0
        while(k<len(x)):
            #logger.info("k=",k)
            if k == j:
                k+=1
                continue
            
            fac = Element(pairing,G1,value=x[j]-x[k])
            temp2=Element(pairing,G1,value=zone/fac)#因为这个是带x的
            temp1=Element(pairing,G1,value=-x[k]/fac)#这个是一个常数

            if(len(equationj)==0):
                #logger.info("初次计算")
                equationj[0]=temp1
                equationj[1]=temp2
            else:
                #logger.info("再次计算")
                tempEquation1={}
                tempEquation2={}
                tempEquation2[0]=zzero
                i=0
                #计算出分别的多项式
                while(i<len(equationj)):
                    #logger.info("i=%s",i)
                    tempEquation1[i]=Element(pairing,G1,value=equationj[i]*temp1)
                    tempEquation2[i+1]=Element(pairing,G1,value=equationj[i]*temp2)
                    i+=1

                i=0
                #logger.info("计算本次等式")
                while(i<len(equationj)):
                    equationj[i]=Element(pairing,G1,value=tempEquation1[i]+tempEquation2[i])
                    i+=1
                equationj[i]=tempEquation2[i]

            k+=1
        i=0
        while(i<len(equationj)):
            equationj[i]=Element(pairing,G1,value=equationj[i]*y[j])
            i+=1
        #logger.info("equationj=",equationj)
        equation[j]=equationj
        j+=1

    #logger.info("equation=",equation)

    lastEquaion={}
    j=0
    #初始赋值
    while(j<len(equation[0])):
        lastEquaion[j]=zzero
        j+=1
    i=0
    #等式各系数相加得到最终系数
    while(i<len(equation)):
        j=0
        while(j<len(equation[i])):
            lastEquaion[j]=Element(pairing,G1,value=lastEquaion[j]+equation[i][j])
            j+=1
        i+=1
    
    # logger.info("lastEquaion=%s",lastEquaion)    
    #print(lastEquaion)
    mylagrangeTimeEnd=datetime.now()
    timeleapmylagrange=mylagrangeTimeEnd-mylagrangeTimeStart
    logger.info("mylagrange Time: %s s","{:}.{:06}".format(timeleapmylagrange.seconds,timeleapmylagrange.microseconds))
    #logger.info("=======================mylagrange End=======================")
    return lastEquaion

def GetDList(dir):
    """[Reading files in deep]

    Args:
        dir ([str]): [Dir]

    Returns:
        [dict]: [Email dictionary]
    """
    logger.info("==================GetDList Start==================")
    
    p = Path(dir) 
    DList={}
    FileList=list(p.glob("**/*.")) #递归查询文件
    for filepath in FileList:
        logger.info("Reading %s",filepath)

        D={}

        f=open(filepath, "rb+")
        byt = f.read()
        data=byt.decode("ISO-8859-1")
        #data=f.read()
        email = Parser().parsestr(data)

        D['Message-ID']=email['Message-ID']
        D['Date']=email['Date']
        D['From']=email['From']
        D['X-FileName']=email['X-FileName']
        D['X-Origin']=email['X-Origin']
        D['X-From']=email['X-From']
        D['X-Folder']=email['X-Folder']
        toMails=email['To']
        toMailsList=re.split('[,\s]',str(toMails))
        #toMailsList=str(toMails).split(",")
        for mail in toMailsList:
            D[mail]=mail
        
        #针对文件subject实现模糊搜索
        subject=email['subject']
        words= word_tokenize(subject)
        for word in words:
            D[word]=word

        # nlp = spacy.load("en_core_web_sm")
        # tr = pytextrank.TextRank()
        # nlp.add_pipe(tr.PipelineComponent, name="textrank", last=True)
        # doc = nlp(email.get_payload())

        # i=1
        # for p in doc._.phrases:
        #     if(i<=10):
        #         D[p.text]=p.text

        DList[filepath]=D
        # for key,value in D.items():
        #     print(key,value)

    logger.info("==================GetDList End==================")
    return DList

def getDictATT():
    """[获得50组属性]

    Returns:
        [type]: [description]
    """
    dictATT={}
    i=1
    while(i<=50):
        temp='Att'+str(i)
        if(i==1):
            ATT=list()
            ATT.append(temp)
            dictATT[i]=ATT
        else:
            ATT=list(dictATT[i-1])
            ATT.append(temp)
            dictATT[i]=ATT
        i+=1
    return dictATT

def getDBCopy(PP,DB):
    [params,g]=PP
    #pairing = Pairing(params)
    DBCopy={}
    for ld,EDBXSet in DB.items():
        EDB,XSet=DB[ld]
        DBCopy[ld]=list()
        EDBCopy=dict()
        XSetCopy=dict()
        #DBCopy[ld]=[{},{}]
        for l in EDB.keys():
            e0=EDB[l]['e0']
            e1=EDB[l]['e1']
            e2=EDB[l]['e2']
            e3=EDB[l]['e3']
            e4=EDB[l]['e4']
            EDBCopy[l]={"e0":str(e0),"e1":str(e1),"e2":str(e2),"e3":str(e3),"e4":str(e4)}
            xtag=XSet[l]
            XSetCopy[l]=str(xtag)
        
        DBCopy[ld]=[EDBCopy,XSetCopy]
    
    return DBCopy

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

def createDir(dstpath):
    """[递归创建文件夹]

    Args:
        dstpath ([type]): [description]
        type ([type]): [description]
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
        
        i+=1

def createFile(dstpath,data,type):
    """[给定一个文件路径,自动创建文件夹并新建文件]

    Args:
        data ([str|byte]): [Depends on parameter type]
        dstpath ([str]): [The file path you want to create]
        type ([str]): [r,w,x,b]

    Returns:
        [int]: [Not in use]
    """
    logger.info("Creating %s file",dstpath)
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

def loadFile(filePath):
    logger.info("Reading %s file",filePath)
    fileCopy=open(filePath,"r")
    Copy=eval(fileCopy.read())
    return Copy

def readPP(root):
    """[summary]

    Args:
        root ([type]): [Client/ or Server/]

    Returns:
        [type]: [description]
    """
    ppCopy=loadFile(root+ParameterPathFromTools+"PP.dat")
    [paramsCopy,gCopy]=ppCopy

    params = Parameters(paramsCopy)
    pairing = Pairing(params) 
    g=Element(pairing,G1,value=gCopy)

    pp=[params,g]

    return pp

def readMK(root):
    """[summary]

    Args:
        root ([type]): [Client/ or Server/]

    Returns:
        [type]: [description]
    """
    PP=readPP(root)
    [params,g]=PP
    mkCopy=loadFile(root+ParameterPathFromTools+"MK.dat")
    [KxCopy,KzCopy,KlCopy,KyCopy,gammaCopy,alphaCopy]=mkCopy

    pairing = Pairing(params) 
    Kx=KxCopy.encode()
    Kz=KzCopy.encode()
    Kl=KlCopy.encode()
    Ky=KyCopy.encode()
    gamma=Element(pairing,Zr,value=int(gammaCopy,16))
    alpha=Element(pairing,Zr,value=int(alphaCopy,16))

    MK=[Kx,Kz,Kl,Ky,gamma,alpha]

    return MK

def readServerKey(root):
    PP=readPP(root)
    [params,g]=PP
    sksCopy=loadFile(root+ParameterPathFromTools+"sks.dat")
    [alphaCopy,betaCopy]=sksCopy
    #pksCopy=loadFile(root+ParameterPathFromTools+"pks.dat")

    pairing = Pairing(params) 
    beta=Element(pairing,Zr,value=int(betaCopy,16))
    alpha=Element(pairing,Zr,value=int(alphaCopy,16))

    pks=Element(pairing,G1,value=g**beta)
    sks=[alpha,beta]

    return [pks,sks]

def readClientKey(root):
    PP=readPP(root)
    [params,g]=PP
    pairing = Pairing(params) 
    skcCopy=loadFile(root+ParameterPathFromTools+"skc.dat")
    [KxCopy,KzCopy,KlCopy,KyCopy,gammaCopy,vCopy,AlphaCopy]=skcCopy
    Kx=KxCopy.encode()
    Kz=KzCopy.encode()
    Kl=KlCopy.encode()
    Ky=KyCopy.encode()

    gamma=Element(pairing,Zr,value=int(gammaCopy,16))
    v=Element(pairing,G1,value=vCopy)
    Alpha=Element(pairing,G1,value=AlphaCopy)

    skc=[Kx,Kz,Kl,Ky,gamma,v,Alpha]
    return skc

def readPolicy(root):
    PP=readPP(root)
    [params,g]=PP
    pairing=Pairing(params)
    policyCopy=loadFile(root+ParameterPathFromTools+"policy.dat")
    sigmaCopy,TagCopy=policyCopy
    # 现在sigmaCopy是str类型,回来转换成eval
    sigmaCopy=eval(sigmaCopy)
    #print(sigmaCopy)
    x1Copy=eval(sigmaCopy[0])
    y1Copy=eval(sigmaCopy[1])
    x2Copy=eval(sigmaCopy[2])
    y2Copy=eval(sigmaCopy[3])
    h1Copy=sigmaCopy[4]
    h2Copy=sigmaCopy[5]
    hCopy=sigmaCopy[6]
    st=sigmaCopy[7]

    x1=[]
    y1=[]
    x2=[]
    y2=[]

    i=0
    while(i<len(x1Copy)):
        xi=Element(pairing,G1,value=x1Copy[i])
        yi=Element(pairing,G1,value=y1Copy[i])
        x1.append(xi)
        y1.append(yi)
        i+=1

    i=0
    while(i<len(x2Copy)):
        xi=Element(pairing,G1,value=x2Copy[i])
        yi=Element(pairing,G1,value=y2Copy[i])
        x2.append(xi)
        y2.append(yi)
        i+=1

    h=Element(pairing,G1,value=hCopy)
    h1=Element(pairing,G1,value=h1Copy)
    h2=Element(pairing,G1,value=h2Copy)


    #print(x1Copy)
    #[x1Copy,y1Copy,x2Copy,y2Copy,h1Copy,h2Copy,st]=sigmaCopy
    sigma=[x1,y1,x2,y2,h1,h2,h,st]
    Tag=TagCopy
    return [sigma,Tag]

def readToken(root):
    PP=readPP(root)
    [params,g]=PP
    pairing=Pairing(params)
    tokenCopy=loadFile(root+ParameterPathFromTools+"token.dat")
    [lCopy,TrapCopy,ld,booleanVector]=tokenCopy
    #print(type(booleanVector),booleanVector)
    l=eval(lCopy)
    Trap={}

    i=1
    while(i<=len(TrapCopy)):
        Trap[i]={}
        j=1
        while(j<=len(TrapCopy[i])):
            trap=Element(pairing,G1,value=TrapCopy[i][j])
            Trap[i][j]=trap
            j+=1
        i+=1

    token=[l,Trap,ld,booleanVector]
    return token

def readRes(root):
    PP=readPP(root)
    [params,g]=PP
    pairing=Pairing(params)
    ResCopy=loadFile(root+ParameterPathFromTools+"Res.dat")
    R=[]
    for item in ResCopy:
        e0=Element(pairing,G1,item)
        R.append(e0)
    return R

def readInds(root):
    path=root+ParameterPathFromTools+"Inds.dat"
    IndsLocal={}
    if(os.path.exists(path)):
        fileInds=open(path,"r")
        IndsLocal=eval(fileInds.read())
    return IndsLocal

def readDB(root):
    PP=readPP(root)
    [params,g]=PP
    pairing=Pairing(params)

    path=root+ParameterPathFromTools+"DB.dat"
    DBLocal={}
    DB={}
    if(os.path.exists(path)):
        fileDB=open(path,"r")
        DBLocal=eval(fileDB.read())
    
    #print(len(DBLocal))

    for ld,array in DBLocal.items():
        
        EDBCopy,XSetCopy=array
        EDB=dict()
        XSet=dict()
        for l in EDBCopy.keys():
            e0Copy=EDBCopy[l]['e0']
            e1Copy=EDBCopy[l]['e1']
            e2Copy=EDBCopy[l]['e2']
            e3Copy=EDBCopy[l]['e3']
            e4Copy=EDBCopy[l]['e4']
            e0=Element(pairing,G1,value=e0Copy)
            e1=Element(pairing,G1,value=e1Copy)
            e2=Element(pairing,G1,value=e2Copy)
            e3=Element(pairing,G1,value=e3Copy)
            e4=Element(pairing,G1,value=e4Copy)
            EDB[l]={"e0":e0,"e1":e1,"e2":e2,"e3":e3,"e4":e4}

            xtagCopy=XSetCopy[l]
            xtag=Element(pairing,GT,value=xtagCopy)
            XSet[l]=xtag
        
        DB[ld]=[EDB,XSet]
    #print(DB.keys())
    return DB

def readWSet(root):
    path=root+ParameterPathFromTools+"WSet.dat"
    WSetLocal={}
    if(os.path.exists(path)):
        fileWSet=open(path,"r")
        WSetLocal=eval(fileWSet.read())
    return WSetLocal

if __name__ == '__main__':
    MainTimeStart=datetime.now()
    main()
    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("Main Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))














