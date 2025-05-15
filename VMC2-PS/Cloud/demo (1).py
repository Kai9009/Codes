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
    
    egg=pairing.apply(g,g)
    y=Element.random(pairing,Zr)
    Y=Element(pairing,GT,value=egg**y)

    n=len(Universe)

    tDic={}
    TDic={}
    for i in range(1,3*n+1):
        ti=Element.random(pairing,Zr)
        tDic[i]=ti
        Ti=Element(pairing,G1,value=g**ti)
        TDic[i]=Ti

    PK=[params,g,Y,TDic]
    MK=[y,tDic]

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("GlobalSetup Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

    createFile(ParameterPathFromTools+"PK.dat",str(PK),"w")
    createFile(ParameterPathFromTools+"MK.dat",str(MK),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"PK.dat")
    logTime.info("%s is %s KB","PK.dat",filesize_bytes/1024)
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"MK.dat")
    logTime.info("%s is %s KB","MK.dat",filesize_bytes/1024)

    return [PK,MK]

def CreateUL(PK,MK,ID,Universe={},UL={}):
    logger.info("==================CreateUL Start==================")
    MainTimeStart=datetime.now()
    [params,g,Y,TDic]=PK
    [y,tDic]=MK
    pairing=Pairing(params)

    xf=Element.random(pairing,Zr)
    Yfq=Element(pairing,GT,value=Y**xf)

    s=H(params,ID)
    y=Element(pairing,Zr,value=int(str(y),16))
    Dfb=Element(pairing,GT,value=Yfq**-s)
    UL[ID]=Dfb

    n=len(Universe)
    r=Element(pairing,Zr,value=0)
    rDic={}
    for i in range(1,n+1):
        ri=Element.random(pairing,Zr)
        rDic[i]=ri
        r=Element(pairing,Zr,value=r+ri)

    Kh=Element(pairing,G1,value=g**(y-r))

    KDic={}
    FDic={}
    for i in range(1,n+1):
        ri=rDic[i]
        ti=tDic[i]
        Ki=Element(pairing,G1,value=g**(ri/ti))
        KDic[i]=Ki # Assume all attributes are positive
        
        t2npi=tDic[2*n+i]
        Fi=Element(pairing,G1,value=g**(ri/t2npi))
        FDic[i]=Fi

    SK=[xf,Kh,KDic,FDic]

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("CreateUL Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

    createFile(ParameterPathFromTools+"SK.dat",str(SK),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"SK.dat")
    logTime.info("%s is %s KB","SK.dat",filesize_bytes/1024)

    return [SK,UL]

def EncIndex(PK,ID,Universe,w):
    [params,g,Y,TDic]=PK
    pairing=Pairing(params)

    s=H(params,ID)
    Y=Element(pairing,GT,value=str(Y))
    Dh=Element(pairing,G1,value=g**s)
    Dw=Element(pairing,GT,value=Y**s)

    n=len(Universe)
    DDic={}
    for i in range(1,n+1): # Assume all attributes are positive
        Ti=Element(pairing,G1,value=str(TDic[i]))
        #Di=Element(pairing,G1,value=Ti**s)
        Di=Element(pairing,G1,value=Ti**(s/H(params,w))) # Assume all positions include keyword
        DDic[i]=Di
    
    CT=[Universe,Dh,Dw,DDic]

    return CT

def AllEnc(PK,ID,Universe):
    logger.info("==================AllEnc Start==================")
    MainTimeStart=datetime.now()
    DList=GetDList("../Experiment/maildir/meyers-a")
    EDB={}
    for Doc in DList.items():
        D={}
        [filePath,WindSet]=Doc
        for key,kw in WindSet.items():
            m=str(filePath)
            CT=EncIndex(PK,ID,Universe,kw)
            D[key]=CT
        EDB[str(filePath)]=D
    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("AllEnc Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
    
    createFile(ParameterPathFromTools+"EDB.dat",str(EDB),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"EDB.dat")
    logTime.info("%s is %s KB","EDB.dat",filesize_bytes/1024)

    return EDB

def TrapGen(PK,SK,ID,w):
    logger.info("==================TrapGen Start==================")
    MainTimeStart=datetime.now()
    [params,g,Y,TDic]=PK
    [xf,Kh,KDic,FDic]=SK

    pairing=Pairing(params)
    u=Element.random(pairing,Zr)
    xf=Element(pairing,Zr,value=int(str(xf),16))
    Kh=Element(pairing,G1,value=str(Kh))

    Qh=Element(pairing,G1,value=Kh**u)
    Qw=Element(pairing,Zr,value=u+xf)
    
    QDic={}
    QfDic={}
    for i,Ki in KDic.items():
        Ki=Element(pairing,G1,value=str(Ki))
        Fi=Element(pairing,G1,value=str(FDic[i]))
        #Qi=Element(pairing,G1,value=Ki**u)
        Qi=Element(pairing,G1,value=Ki**(H(params,w)*u))
        #Qfi=Element(pairing,G1,value=Fi**u)
        Qfi=Element(pairing,G1,value=Ki**(H(params,w)*u))
        QDic[i]=Qi
        QfDic[i]=Qfi

    Trap=[ID,Qh,Qw,QDic,QfDic]

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("TokenGen Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
    
    createFile(ParameterPathFromTools+"Trap.dat",str(Trap),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"Trap.dat")
    logTime.info("%s is %s KB","Trap.dat",filesize_bytes/1024)

    return Trap

def Test(PK,UL,CT,Trap,Universe):
    [params,g,Y,TDic]=PK
    [Universe,Dh,Dw,DDic]=CT
    [ID,Qh,Qw,QDic,QfDic]=Trap
    if(ID not in UL.keys()): return False
    pairing=Pairing(params)

    n=len(Universe)
    Dfb=UL[ID]

    Dw=Element(pairing,GT,value=str(Dw))
    Qw=Element(pairing,Zr,value=int(str(Qw),16))
    Dfb=Element(pairing,GT,value=str(Dfb))
    Dh=Element(pairing,G1,value=str(Dh))
    Qh=Element(pairing,G1,value=str(Qh))

    Pi=Element(pairing,GT,value=1)
    for i in range(1,n+1):
        Di=Element(pairing,G1,value=str(DDic[i]))
        Qi=Element(pairing,G1,value=str(QDic[i]))

        eDiQi=pairing.apply(Di,Qi)
        Pi=Element(pairing,GT,value=Pi*eDiQi)
    
    temp=Element(pairing,GT,value=Dw**Qw)
    L=Element(pairing,GT,value=temp*Dfb)

    temp=pairing.apply(Dh,Qh)
    R=Element(pairing,GT,value=temp*Pi)

    b=L==R
    #logger.info("Test result is %s",b)
    return b

def AllSearch(PK,UL,EDB,Trap,Universe):
    logger.info("==================Search Start==================")
    MainTimeStart=datetime.now()
    CTList=[]
    for filepath,D in EDB.items():
        for key,CT in D.items():
            b=Test(PK,UL,CT,Trap,Universe)
            if(b):
                CTList.append(CT)
                break
    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("Search Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
    
    createFile(ParameterPathFromTools+"CTList.dat",str(CTList),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"CTList.dat")
    logTime.info("%s is %s KB","CTList.dat",filesize_bytes/1024)

    return CTList

def main(AttNum):
    dictAtt=getDictATT()
    Universe=dictAtt[AttNum]
    S=dictAtt[AttNum]
    ID="User"
    w="../Experiment/maildir/meyers-a/inbox/4."
    UL={}
    
    [PK,MK]=GlobalSetup(Universe=Universe)
    [SK,UL]=CreateUL(PK,MK,ID,S,UL)
    EDB=AllEnc(PK,ID,Universe)
    Trap=TrapGen(PK,SK,ID,w)
    CTList=AllSearch(PK,UL,EDB,Trap,Universe)

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
