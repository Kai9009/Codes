from re import S, X
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
import spacy
import pytextrank

import nltk
from nltk.tokenize import *
from nltk.corpus import stopwords
from string import punctuation
import string
from datetime import datetime,timedelta

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

logger=logging.getLogger("Caedios")
logger.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
file_handler = logging.FileHandler("log")
file_handler.setLevel(level=logging.INFO)
file_handler.setFormatter(formatter)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

logTime=logging.getLogger("logTime")
logTime.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
fileTime_handler = logging.FileHandler("logTime")
fileTime_handler.setLevel(level=logging.INFO)
fileTime_handler.setFormatter(formatter)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logTime.addHandler(fileTime_handler)
logTime.addHandler(console_handler)

Hash = hashlib.sha256

AttributeNumber=10
ParameterPathFromTools="Parameter/"

def H(params,WTF):
    """[{0,1}*-->Zr]

    Args:
        params ([type]): [description]
        WTF ([type]): [description]

    Returns:
        [type]: [description]
    """
    pairing=Pairing(params)
    hash_value = Element.from_hash(pairing, Zr, Hash(str(WTF).encode()).hexdigest())
    return hash_value

def GlobalSetup(qbits=512, rbits=160, Universe={}):
    """[summary]

    Args:
        qbits (int, optional): [description]. Defaults to 512.
        rbits (int, optional): [description]. Defaults to 160.
        Universe (dict, optional): [description]. Defaults to {}.
    """
    logger.info("==================GlobalSetup Start==================")
    MainTimeStart=datetime.now()
    params = Parameters(qbits=qbits, rbits=rbits)   #参数初始化
    pairing = Pairing(params)  # 根据参数实例化双线性对
    g = Element.random(pairing, G1)  # g是G1的一个生成元

    n=len(Universe)
    y=Element.random(pairing,Zr)
    egg=pairing.apply(g,g)
    Y1=Element(pairing,GT,value=egg*y)
    Y2=Element(pairing,G1,value=g**y)

    tDic={}
    TDic={}
    for i in range(1,3*n+1):
        ti=Element.random(pairing,Zr)
        Ti=Element(pairing,G1,value=g**ti)
        tDic[i]=ti
        TDic[i]=Ti

    PP=[params,g,Y1,Y2,TDic]
    MK=[y,tDic]

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("GlobalSetup Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

    createFile(ParameterPathFromTools+"PP.dat",str(PP),"w")
    createFile(ParameterPathFromTools+"MK.dat",str(MK),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"PP.dat")
    logTime.info("%s is %s KB","PP.dat",filesize_bytes/1024)
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"MK.dat")
    logTime.info("%s is %s KB","MK.dat",filesize_bytes/1024)

    return [PP,MK]

def WSetup(PP,Universe):
    logger.info("==================WSetup Start==================")
    MainTimeStart=datetime.now()
    [params,g,Y1,Y2,TDic]=PP

    pairing=Pairing(params)
    beta=Element.random(pairing,Zr)
    yq=Element.random(pairing,Zr)
    g1=Element(pairing,G1,value=g**yq)

    Y1q=Element(pairing,GT,value=Y1**(yq*yq*yq))
    Y2q=Element(pairing,G1,value=Y2**(yq*yq))

    n=len(Universe)
    tDicq={}
    TDicq={}
    for i in range(1,3*n+1):
        Ti=TDic[i]

        tiq=Element.random(pairing,Zr)
        Tiq=Element(pairing,G1,value=Ti**(yq*tiq))

        tDicq[i]=tiq
        TDicq[i]=Tiq

    PPq=[params,g1,Y1q,Y2q,TDicq]
    RKGC=[beta,yq,tDicq]

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("WSetup Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

    createFile(ParameterPathFromTools+"PPq.dat",str(PPq),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"PPq.dat")
    logTime.info("%s is %s KB","PPq.dat",filesize_bytes/1024)
    createFile(ParameterPathFromTools+"RKGC.dat",str(RKGC),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"RKGC.dat")
    logTime.info("%s is %s KB","RKGC.dat",filesize_bytes/1024)

    return [PPq,RKGC]

def KeyGen(ID,SID,PPq,MK,Universe):
    logger.info("==================KeyGen Start==================")
    MainTimeStart=datetime.now()
    [params,g1,Y1q,Y2q,TDicq]=PPq
    [y,tDic]=MK

    pairing=Pairing(params)

    y=Element(pairing,Zr,value=int(str(y),16))
    g1=Element(pairing,G1,value=str(g1))
    Y1q=Element(pairing,GT,value=str(Y1q))
    xid=Element.random(pairing,Zr)
    Zid=Element(pairing,GT,value=Y1q**xid)

    eg1g1=pairing.apply(g1,g1)

    n=len(Universe)
    r=Element(pairing,Zr,value=0)
    KDic={}
    KhDic={}
    eg1g1rDic={}
    for i in range(1,n+1):
        ti=Element(pairing,Zr,value=int(str(tDic[i]),16))
        tnpi=Element(pairing,Zr,value=int(str(tDic[n+i]),16))
        t2npi=Element(pairing,Zr,value=int(str(tDic[2*n+i]),16))
        ri=Element.random(pairing,Zr)
        Ki=Element(pairing,G1,value=g1**(ri/ti))
        Kih=Element(pairing,G1,value=g1**(ri/t2npi))

        eg1g1ri=Element(pairing,GT,value=eg1g1**ri)
        r=Element(pairing,Zr,value=r+ri)
        KDic[i]=Ki
        KhDic[i]=Kih
        eg1g1rDic[i]=eg1g1ri

    Kh=Element(pairing,G1,value=g1**(y-r))
    eg1g1r=Element(pairing,GT,value=eg1g1**r)
    
    piskid=[eg1g1,eg1g1r,eg1g1rDic]
    skid=[xid,Kh,KDic,KhDic]

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("KeyGen Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

    createFile(ParameterPathFromTools+"skid.dat",str(skid),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"skid.dat")
    logTime.info("%s is %s KB","skid.dat",filesize_bytes/1024)
    createFile(ParameterPathFromTools+"piskid.dat",str(skid),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"piskid.dat")
    logTime.info("%s is %s KB","piskid.dat",filesize_bytes/1024)

    return [skid,piskid,Zid]

def WKeyGen(PPq,skid,piskid,Zid,RKGC,Universe):
    logger.info("==================WKeyGen Start==================")
    MainTimeStart=datetime.now()
    [params,g1,Y1q,Y2q,TDicq]=PPq
    [xid,Kh,KDic,KhDic]=skid
    [eg1g1,eg1g1r,eg1g1rDic]=piskid
    [beta,yq,tDicq]=RKGC

    pairing=Pairing(params)
    n=len(Universe)
    zone=Element(pairing,Zr,value=1)
    g1=Element(pairing,G1,value=str(g1))
    beta=Element(pairing,Zr,value=int(str(beta),16))
    yq=Element(pairing,Zr,value=int(str(yq),16))
    eg1g1=Element(pairing,GT,value=str(eg1g1))
    eg1g1r=Element(pairing,GT,value=str(eg1g1r))
    Kh=Element(pairing,G1,value=str(Kh))
    Y1q=Element(pairing,GT,value=str(Y1q))
    Zid=Element(pairing,GT,value=str(Zid))

    # Verify piskid
    up=Element(pairing,GT,value=Y1q**(zone/yq))
    down=pairing.apply(Kh,g1)
    L=Element(pairing,GT,value=up/down)
    R=eg1g1r
    b=L==R
    if(not b):
        logger.info("WKeyGen Verification-1 Result is %s",b)

    flag=True
    for i in range(1,n+1):
        tiq=Element(pairing,Zr,value=int(str(tDicq[i]),16))
        Ki=Element(pairing,G1,value=str(KDic[i]))
        Tiq=Element(pairing,G1,value=str(TDicq[i]))
        temp=pairing.apply(Ki,Tiq)
        L=Element(pairing,GT,value=temp**(zone/tiq))
        R=Element(pairing,GT,value=str(eg1g1rDic[i]))
        flag=L==R
        if(not flag):
            logger.info("WKeyGen Verification-2 Result is %s",flag)
            break

        t2npiq=Element(pairing,Zr,value=int(str(tDicq[2*n+i]),16))
        Kih=Element(pairing,G1,value=str(KhDic[i]))
        T2npiq=Element(pairing,G1,value=str(TDicq[2*n+i]))
        temp=pairing.apply(Kih,T2npiq)
        L=Element(pairing,GT,value=temp**(zone/t2npiq))
        R=Element(pairing,GT,value=str(eg1g1rDic[i]))
        flag=L==R
        if(not flag):
            logger.info("WKeyGen Verification-3 Result is %s",flag)
            break
    if(b and flag):
        logger.info("WKeyGen Verification-1&2&3 Result is %s",flag)

    # Let's compute, bro
    KDicq={}
    KhDicq={}
    for i in range(1,n+1):
        tiq=Element(pairing,Zr,value=int(str(tDicq[i]),16))
        Ki=Element(pairing,G1,value=str(KDic[i]))
        Kiq=Element(pairing,G1,value=Ki**(yq/tiq))

        t2npiq=Element(pairing,Zr,value=int(str(tDicq[2*n+i]),16))
        Kih=Element(pairing,G1,value=str(KhDic[i]))
        Kihq=Element(pairing,G1,value=Kih**(yq/t2npiq))

        KDicq[i]=Kiq
        KhDicq[i]=Kihq

    Khq=Element(pairing,G1,value=Kh**yq)
    xidq=Element(pairing,Zr,value=xid*beta)
    Zidq=Element(pairing,GT,value=Zid**beta)

    eg1g1yqr=Element(pairing,GT,value=eg1g1r**yq)
    eg1g1yqrDic={}
    for i in range(1,n+1):
        eg1g1ri=Element(pairing,GT,value=str(eg1g1rDic[i]))
        eg1g1yqri=Element(pairing,GT,value=eg1g1ri**yq)
        eg1g1yqrDic[i]=eg1g1yqri

    # Return
    skidq=[xidq,Khq,KDicq,KhDicq]
    piskidq=[eg1g1,eg1g1yqr,eg1g1yqrDic]

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("WKeyGen Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

    createFile(ParameterPathFromTools+"skidq.dat",str(skid),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"skidq.dat")
    logTime.info("%s is %s KB","skidq.dat",filesize_bytes/1024)
    createFile(ParameterPathFromTools+"piskidq.dat",str(skid),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"piskidq.dat")
    logTime.info("%s is %s KB","piskidq.dat",filesize_bytes/1024)

    return [skidq,piskidq,Zidq]

def Authorize(ID,PPq,Zidq,UL):
    logger.info("==================Authorize Start==================")
    MainTimeStart=datetime.now()
    [params,g1,Y1q,Y2q,TDicq]=PPq

    pairing=Pairing(params)
    Zidq=Element(pairing,GT,value=str(Zidq))

    s=Element.random(pairing,Zr)
    Tid=Element(pairing,GT,value=Zidq**(-s))
    UL[ID]=Tid
    Token=s

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("Authorize Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

    # createFile(ParameterPathFromTools+"Token.dat",str(Token),"w")
    # filesize_bytes = os.path.getsize(ParameterPathFromTools+"Token.dat")
    # logTime.info("%s is %s KB","Token.dat",filesize_bytes/1024)
    # createFile(ParameterPathFromTools+"Tid.dat",str(Tid),"w")
    # filesize_bytes = os.path.getsize(ParameterPathFromTools+"Tid.dat")
    # logTime.info("%s is %s KB","Tid.dat",filesize_bytes/1024)

    return [Tid,Token,UL]

def WAuthorize(ID,PPq,Zidq,UL,ULq,RDO):
    logger.info("==================WAuthorize Start==================")
    MainTimeStart=datetime.now()
    [params,g1,Y1q,Y2q,TDicq]=PPq

    pairing=Pairing(params)
    Tid=Element(pairing,GT,value=str(UL[ID]))
    gamma=Element.random(pairing,Zr)
    Tidq=Element(pairing,GT,value=Tid**gamma)
    ULq[ID]=Tidq
    RDO[ID]=gamma
    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("WAuthorize Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

    return [Tidq,RDO,ULq]

def Enc(PPq,Token,AUZ,w,Universe):
    [params,g1,Y1q,Y2q,TDicq]=PPq

    pairing=Pairing(params)
    n=len(Universe)
    g1=Element(pairing,G1,value=str(g1))
    s=Element(pairing,Zr,value=int(str(Token),16))
    Y1q=Element(pairing,GT,value=str(Y1q))

    Dh=Element(pairing,G1,value=g1**s)
    Dw=Element(pairing,GT,value=Y1q**s)
    
    DDic={}
    for i in range(1,n+1):
        Tiq=Element(pairing,G1,value=str(TDicq[i]))
        Di=Element(pairing,G1,value=Tiq**s)
        Di=Element(pairing,G1,value=Tiq**(s/H(params,w)))
        DDic[i]=Di

    eg1g1=pairing.apply(g1,g1)
    eg1g1s=Element(pairing,GT,value=eg1g1**s)
    eg1g1yqys=Element(pairing,GT,value=Y1q**s)
    eTiqg1Dic={}
    eTiqg1sDic={}
    eTiqg1sWDic={}
    for i in range(1,3*n+1):
        Tiq=Element(pairing,G1,value=str(TDicq[i]))
        eTiqg1i=pairing.apply(Tiq,g1)
        eTiqg1Dic[i]=eTiqg1i

        eTiqg1si=Element(pairing,GT,value=eTiqg1i**s)
        eTiqg1sDic[i]=eTiqg1si

        eTiqg1sWi=Element(pairing,GT,value=eTiqg1i**(s/H(params,w)))
        eTiqg1sWDic[i]=eTiqg1sWi

    piD=[eg1g1,eTiqg1Dic,eg1g1s,eg1g1yqys,eTiqg1sDic,eTiqg1sWDic]
    CT=[Dh,Dw,DDic]
    return [CT,piD]

def AllEnc(PPq,Token,AUZ,Universe):
    logger.info("==================AllEnc Start==================")
    MainTimeStart=datetime.now()
    DList=GetDList("../Experiment/maildir/meyers-a")
    EDB={}
    for Doc in DList.items():
        D={}
        [filePath,WindSet]=Doc
        for key,kw in WindSet.items():
            CT,piD=Enc(PPq,Token,AUZ,kw,Universe)
            D[key]={"CT":CT,"piD":piD}
        EDB[str(filePath)]=D
    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("AllEnc Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
    
    createFile(ParameterPathFromTools+"EDB.dat",str(EDB),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"EDB.dat")
    logTime.info("%s is %s KB","EDB.dat",filesize_bytes/1024)

    return EDB

def WEnc(PPq,CT,piD,ID,RDO,Universe):
    
    [params,g1,Y1q,Y2q,TDicq]=PPq
    [Dh,Dw,DDic]=CT
    [eg1g1,eTiqg1Dic,eg1g1s,eg1g1yqys,eTiqg1sDic,eTiqg1sWDic]=piD

    pairing=Pairing(params)
    n=len(Universe)
    gamma=Element(pairing,Zr,value=int(str(RDO[ID]),16))
    g1=Element(pairing,G1,value=str(g1))
    Y2q=Element(pairing,G1,value=str(Y2q))
    Dh=Element(pairing,G1,value=str(Dh))
    Dw=Element(pairing,GT,value=str(Dw))
    eg1g1s=Element(pairing,GT,value=str(eg1g1s))
    eg1g1yqys=Element(pairing,GT,value=str(eg1g1yqys))

    # Verify
    L=pairing.apply(Dh,g1)
    R=eg1g1s
    b1=L==R
    if(not b1):
        logger.info("WEnc Verification-1 Result is %s",b1)

    L=Dw
    R=pairing.apply(Y2q,Dh)
    b2=L==R
    if(not b2):
        logger.info("WEnc Verification-2 Result is %s",b2)

    flag=True
    for i in range(1,n+1):
        Di=Element(pairing,G1,value=str(DDic[i]))
        L=pairing.apply(Di,g1)
        R=Element(pairing,GT,value=str(eTiqg1sWDic[i]))
        flag=L==R
        if(not flag):
            logger.info("WKeyGen Verification-3 Result is %s",flag)
            break

    if(b1 and b2 and flag):
        logger.info("WEnc Verification-1&2&3 Result is %s",b1)

    # Let's compute
    Dhq=Element(pairing,G1,value=Dh**gamma)
    Dwq=Element(pairing,GT,value=Dw**gamma)
    DqDic={}
    for i in range(1,n+1):
        Di=Element(pairing,G1,value=str(DDic[i]))
        Diq=Element(pairing,G1,value=Di**gamma)
        DqDic[i]=Diq

    h1=Element(pairing,GT,value=eg1g1s**gamma)
    h2=Element(pairing,GT,value=eg1g1yqys**gamma)
    #eTiqg1sDic,eTiqg1sWDic
    eTiqg1sDicq={}
    for i in range(1,3*n+1):
        eTiqg1s=Element(pairing,GT,value=str(eTiqg1sDic[i]))
        eTiqg1sgamma=Element(pairing,GT,value=eTiqg1s**gamma)
        eTiqg1sDicq[i]=eTiqg1sgamma

    eTiqg1sWDicq={}
    for i in range(1,n+1):
        eTiqg1sw=Element(pairing,GT,value=str(eTiqg1sWDic[i]))
        eTiqg1swgamma=Element(pairing,GT,value=eTiqg1sw**gamma)
        eTiqg1sWDicq[i]=eTiqg1swgamma

    CTq=[Dhq,Dwq,DqDic]
    piDq=[eg1g1,eTiqg1Dic,h1,h2,eTiqg1sDicq,eTiqg1sWDicq]

    return [CTq,piDq]

def AllWEnc(PPq,EDB,ID,RDO,Universe):
    logger.info("==================WEnc Start==================")
    MainTimeStart=datetime.now()
    EDBq={}
    for D in EDB.items():
        Dq={}
        [filePath,CTDic]=D
        for key,CTpiD in CTDic.items():
            CT=CTpiD["CT"]
            piD=CTpiD["piD"]
            CTq,piDq=WEnc(PPq,CT,piD,ID,RDO,Universe)
            Dq[key]={"CTq":CTq,"piDq":piDq}
        EDBq[str(filePath)]=Dq

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("AllWEnc Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
    
    createFile(ParameterPathFromTools+"EDBq.dat",str(EDBq),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"EDBq.dat")
    logTime.info("%s is %s KB","EDBq.dat",filesize_bytes/1024)

    return EDBq

def VerifySK(PPq,skidq,piskidq,Universe):
    logger.info("==================VerifySK Start==================")
    MainTimeStart=datetime.now()
    [params,g1,Y1q,Y2q,TDicq]=PPq
    [xidq,Khq,KDicq,KhDicq]=skidq
    [eg1g1,eg1g1yqr,eg1g1yqrDic]=piskidq

    pairing=Pairing(params)
    n=len(Universe)
    g1=Element(pairing,G1,value=str(g1))
    Y1q=Element(pairing,GT,value=str(Y1q))
    Khq=Element(pairing,G1,value=str(Khq))
    eg1g1yqr=Element(pairing,GT,value=str(eg1g1yqr))

    # Verify
    up=Y1q
    down=pairing.apply(Khq,g1)
    L=Element(pairing,GT,value=up/down)
    R=eg1g1yqr
    b=L==R
    if(not b):
        logger.info("VerifySK Verification-1 Result is %s",b)

    flag=True
    for i in range(1,n+1):
        Kiq=Element(pairing,G1,value=str(KDicq[i]))
        Tiq=Element(pairing,G1,value=str(TDicq[i])) 

        L=pairing.apply(Kiq,Tiq)
        R=Element(pairing,GT,value=str(eg1g1yqrDic[i]))

        flag=L==R
        if(not flag):
            logger.info("VerifySK Verification-2 Result is %s",flag)
            break

        Khiq=Element(pairing,G1,value=str(KhDicq[i]))
        T2npiq=Element(pairing,G1,value=str(TDicq[2*n+i]))
        L=pairing.apply(Khiq,T2npiq)
        R=Element(pairing,GT,value=str(eg1g1yqrDic[i]))
        flag=L==R
        if(not flag):
            logger.info("VerifySK Verification-3 Result is %s",flag)
            break
    if(b and flag):
        logger.info("VerifySK Verification-1&2&3 Result is %s",flag)

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("VerifySK Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

    return b and flag

def TrapGen(PPq,w,skidq,Universe):
    logger.info("==================TrapGen Start==================")
    MainTimeStart=datetime.now()
    [params,g1,Y1q,Y2q,TDicq]=PPq
    [xidq,Khq,KDicq,KhDicq]=skidq

    pairing=Pairing(params)
    n=len(Universe)
    Khq=Element(pairing,G1,value=str(Khq))
    xidq=Element(pairing,Zr,value=int(str(xidq),16))

    mu=Element.random(pairing,Zr)
    Qh=Element(pairing,G1,value=Khq**mu)
    Q1w=Element(pairing,Zr,value=mu+xidq)
    Q2w=Element(pairing,Zr,value=mu+xidq*Q1w)

    QDic={}
    QbDic={}
    for i in range(1,n+1):
        Kiq=Element(pairing,G1,value=str(KDicq[i]))
        Qi=Element(pairing,G1,value=Kiq**mu)
        Qi=Element(pairing,G1,value=Kiq**(mu*H(params,w)))
        QDic[i]=Qi

        Kihq=Element(pairing,G1,value=str(KhDicq[i]))
        Qib=Element(pairing,G1,value=Kihq**mu)
        Qib=Element(pairing,G1,value=Kihq**(mu*H(params,w)))
        QbDic[i]=Qib

    td=[Qh,Q1w,Q2w,QDic,QbDic]

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("TrapGen Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
    
    createFile(ParameterPathFromTools+"td.dat",str(td),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"td.dat")
    logTime.info("%s is %s KB","td.dat",filesize_bytes/1024)
    
    return td

def WTrapGen(PPq,td,Universe):
    logger.info("==================WTrapGen Start==================")
    MainTimeStart=datetime.now()
    [params,g1,Y1q,Y2q,TDicq]=PPq
    [Qh,Q1w,Q2w,QDic,QbDic]=td

    pairing=Pairing(params)
    n=len(Universe)
    Qh=Element(pairing,G1,value=str(Qh))
    Q1w=Element(pairing,Zr,value=int(str(Q1w),16))
    Q2w=Element(pairing,Zr,value=int(str(Q2w),16))

    theta=Element.random(pairing,Zr)
    Qhq=Element(pairing,G1,value=Qh**theta)
    Q1wq=Element(pairing,Zr,value=theta*Q1w)
    Q2wq=Element(pairing,Zr,value=theta*Q2w)

    QDicq={}
    QbDicq={}
    for i in range(1,n+1):
        Qi=Element(pairing,G1,value=str(QDic[i]))
        Qiq=Element(pairing,G1,value=Qi**theta)
        QDicq[i]=Qiq

        Qbi=Element(pairing,G1,value=str(QbDic[i]))
        Qbiq=Element(pairing,G1,value=Qbi**theta)
        QbDicq[i]=Qbiq

    tdq=[Qhq,Q1wq,Q2wq,QDicq,QbDicq]

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("WTrapGen Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
    
    createFile(ParameterPathFromTools+"tdq.dat",str(td),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"tdq.dat")
    logTime.info("%s is %s KB","tdq.dat",filesize_bytes/1024)

    return tdq

def VerifyCT(PPq,SID,CTq,piDq,Universe):
    logger.info("==================VerifyCT Start==================")
    
    [params,g1,Y1q,Y2q,TDicq]=PPq
    [Dhq,Dwq,DqDic]=CTq
    [eg1g1,eTiqg1Dic,h1,h2,eTiqg1sDicq,eTiqg1sWDicq]=piDq

    pairing=Pairing(params)
    n=len(Universe)
    g1=Element(pairing,G1,value=str(g1))
    Dhq=Element(pairing,G1,value=str(Dhq))
    Dwq=Element(pairing,GT,value=str(Dwq))
    h1=Element(pairing,GT,value=str(h1))
    h2=Element(pairing,GT,value=str(h2))

    # Verify
    L=pairing.apply(Dhq,g1)
    R=h1
    b1=L==R
    if(not b1):
        logger.info("VerifyCT Verification-1 Result is %s",b1)

    L=Dwq
    R=h2
    b2=L==R
    if(not b1):
        logger.info("VerifyCT Verification-1 Result is %s",b2)

    flag=True
    for i in range(1,n+1):
        Diq=Element(pairing,G1,value=str(DqDic[i]))
        eTiqg1sgamma=Element(pairing,GT,value=str(eTiqg1sWDicq[i]))
        L=pairing.apply(Diq,g1)
        R=eTiqg1sgamma
        flag=L==R
        if(not flag):
            logger.info("VerifyCT Verification-3 Result is %s",flag)
            break

    if(b1 and b2 and flag):
        logger.info("VerifyCT Verification-1&2&3 Result is %s",b1)

    return b1 and b2 and flag

def Test(PPq,ID,tdq,CTq,ULq,Universe):
    
    [params,g1,Y1q,Y2q,TDicq]=PPq
    [Qhq,Q1wq,Q2wq,QDicq,QbDicq]=tdq
    [Dhq,Dwq,DqDic]=CTq

    pairing=Pairing(params)
    n=len(Universe)
    Dwq=Element(pairing,GT,value=str(Dwq))
    Q2wq=Element(pairing,Zr,value=int(str(Q2wq),16))
    Tidq=Element(pairing,GT,value=str(ULq[ID]))
    Q1wq=Element(pairing,Zr,value=int(str(Q1wq),16))
    Dhq=Element(pairing,G1,value=str(Dhq))
    Qhq=Element(pairing,G1,value=str(Qhq))

    Pi=Element(pairing,GT,value=1)
    for i in range(1,n+1):
        Diq=Element(pairing,G1,value=str(DqDic[i]))
        Qiq=Element(pairing,G1,value=str(QDicq[i]))
        temp=pairing.apply(Diq,Qiq)
        Pi=Element(pairing,GT,value=Pi*temp)
    
    temp1=Element(pairing,GT,value=Dwq**Q2wq)
    temp2=Element(pairing,GT,value=Tidq**Q1wq)
    L=Element(pairing,GT,value=temp1*temp2)
    temp3=pairing.apply(Dhq,Qhq)
    R=Element(pairing,GT,value=temp3*Pi)
    b=L==R
    if(b):
        logger.info("Test result is %s",b)
    
    return b

def Search(PPq,ID,SID,tdq,EDBq,ULq,Universe):
    logger.info("==================Search Start==================")
    MainTimeStart=datetime.now()
    CTqList=[]
    for Dq in EDBq.items():
        [filePath,CTqDic]=Dq
        for key,CTqpiDq in CTqDic.items():
            CTq=CTqpiDq["CTq"]
            piDq=CTqpiDq["piDq"]
            VerifyCT(PPq,SID,CTq,piDq,Universe)
            b=Test(PPq,ID,tdq,CTq,ULq,Universe)
            if(b):
                CTqList.append(CTq)
                logger.info("We find %s",filePath)
                break
    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("Search Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
    
    createFile(ParameterPathFromTools+"CTqList.dat",str(CTqList),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"CTqList.dat")
    logTime.info("%s is %s KB","CTqList.dat",filesize_bytes/1024)
    return CTqList

def main(AttNum):
    dictAtt=getDictATT()
    Universe=dictAtt[AttNum]
    ID="User"
    w="../Experiment/maildir/meyers-a/inbox/4."
    UL={}
    ULq={}
    RDO={}
    AUZ={}
    SID=dictAtt[AttNum]

    # Phase 1
    [PP,MK]=GlobalSetup(qbits=512, rbits=160, Universe=Universe)
    [PPq,RKGC]=WSetup(PP,Universe)
    [skid,piskid,Zid]=KeyGen(ID,SID,PPq,MK,Universe)
    [skidq,piskidq,Zidq]=WKeyGen(PPq,skid,piskid,Zid,RKGC,Universe)
    
    # Phase 2
    [Tid,Token,UL]=Authorize(ID,PPq,Zidq,UL)
    [Tidq,RDO,ULq]=WAuthorize(ID,PPq,Zidq,UL,ULq,RDO)
    EDB=AllEnc(PPq,Token,AUZ,Universe)
    EDBq=AllWEnc(PPq,EDB,ID,RDO,Universe)

    # Phase 3
    bSK=VerifySK(PPq,skidq,piskidq,Universe)
    td=TrapGen(PPq,w,skidq,Universe)
    tdq=WTrapGen(PPq,td,Universe)

    # Phase 4
    Res=Search(PPq,ID,SID,tdq,EDBq,ULq,Universe)

def vice(AttNum):
    dictAtt=getDictATT()
    Universe=dictAtt[AttNum]
    ID="User"
    w="word"
    UL={}
    ULq={}
    RDO={}
    AUZ={}
    SID=dictAtt[AttNum]

    # Phase 1
    [PP,MK]=GlobalSetup(qbits=512, rbits=160, Universe=Universe)
    [PPq,RKGC]=WSetup(PP,Universe)
    [skid,piskid,Zid]=KeyGen(ID,SID,PPq,MK,Universe)
    [skidq,piskidq,Zidq]=WKeyGen(PPq,skid,piskid,Zid,RKGC,Universe)
    
    # Phase 2
    [Tid,Token,UL]=Authorize(ID,PPq,Zidq,UL)
    [Tidq,RDO,ULq]=WAuthorize(ID,PPq,Zidq,UL,ULq,RDO)
    [CT,piD]=Enc(PPq,Token,AUZ,w,Universe)
    [CTq,piDq]=WEnc(PPq,CT,piD,ID,RDO,Universe)

    # Phase 3
    bSK=VerifySK(PPq,skidq,piskidq,Universe)
    td=TrapGen(PPq,w,skidq,Universe)
    tdq=WTrapGen(PPq,td,Universe)

    # Phase 4
    VerifyCTTimeStart=datetime.now()
    bCT=VerifyCT(PPq,SID,CTq,piDq,Universe)
    VerifyCTTimeEnd=datetime.now()
    timeleapVerifyCT=VerifyCTTimeEnd-VerifyCTTimeStart
    logTime.info("VerifyCT Time: %s s","{:}.{:06}".format(timeleapVerifyCT.seconds,timeleapVerifyCT.microseconds))

    bT=Test(PPq,ID,tdq,CTq,ULq,Universe)

def getDictATT():
    """[获得100组属性]

    Returns:
        [type]: [description]
    """
    dictATT={}
    i=1
    while(i<=100):
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

        # f=open(filepath, "rb+")
        # byt = f.read()
        # data=byt.decode("ISO-8859-1")
        #data=f.read()
        # email = Parser().parsestr(data)

        # D['Message-ID']=email['Message-ID']
        # D['Date']=email['Date']
        # D['From']=email['From']
        # D['X-FileName']=email['X-FileName']
        # D['X-Origin']=email['X-Origin']
        # D['X-From']=email['X-From']
        # D['X-Folder']=email['X-Folder']
        # toMails=email['To']
        # toMailsList=re.split('[,\s]',str(toMails))
        # #toMailsList=str(toMails).split(",")
        # for mail in toMailsList:
        #     #keywordCount+=1
        #     D[mail]=mail
        
        # #针对文件subject实现模糊搜索
        # subject=email['subject']
        # words= word_tokenize(subject)
        # for word in words:
        #     #keywordCount+=1
        #     D[word]=word

        D[str(filepath)]=str(filepath)

        DList[filepath]=D
        # for key,value in D.items():
        #     print(value)
        #print(len(D))

    logger.info("==================GetDList End==================")
    return DList

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
            #logger.info("Creating %s",temp)
            f=open(temp,type)
            f.write(data)
        i+=1
    
    return 0

if __name__ == '__main__':
    MainTimeStart=datetime.now()
    for i in range(10,100+1,10):
        logTime.info("~~~~~~~~~~~~~~~~~~Now Attribute Num=%s~~~~~~~~~~~~~~~~~~",i)
        main(i)
    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("Main Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

    MainTimeStart=datetime.now()
    for i in range(10,100+1,10):
        logTime.info("~~~~~~~~~~~~~~~~~~Now Attribute Num=%s~~~~~~~~~~~~~~~~~~",i)
        logTime.info("~~~~~~~~~~~~~~~~~~Pay Attention, Only recite VerifyTime~~~~~~~~~~~~~~~~~~")
        vice(i)
    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("Main Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
