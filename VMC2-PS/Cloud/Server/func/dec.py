from re import S, X
from typing import DefaultDict
from pypbc import *
import hashlib
import random
import logging
from pathlib import Path
from email.parser import Parser
# import paramiko
import os
import sys
from wolfcrypt.hashes import HmacSha256
import spacy
import pytextrank

import nltk
from nltk.tokenize import *
from nltk.corpus import stopwords
from string import punctuation
import string
from datetime import datetime, timedelta

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

logger = logging.getLogger("Caedios")
logger.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
file_handler = logging.FileHandler("log")
file_handler.setLevel(level=logging.INFO)
file_handler.setFormatter(formatter)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

logTime = logging.getLogger("logTime")
logTime.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
fileTime_handler = logging.FileHandler("logTime")
fileTime_handler.setLevel(level=logging.INFO)
fileTime_handler.setFormatter(formatter)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logTime.addHandler(fileTime_handler)
logTime.addHandler(console_handler)

Hash1 = hashlib.sha256
AttributeNumber = 10
ParameterPathFromTools = "Parameter/"

def GlobalSetup(qbits=512, rbits=160, Universe={}, n=10, ni=10):
    """[summary]

    Args:
        qbits (int, optional): [description]. Defaults to 512.
        rbits (int, optional): [description]. Defaults to 160.
        Universe (dict, optional): [description]. Defaults to {}.
    """
    logger.info("==================GlobalSetup Start==================")
    MainTimeStart = datetime.now()

    params = Parameters(qbits=qbits, rbits=rbits)  # 参数初始化
    pairing = Pairing(params)  # 根据参数实例化双线性对
    g = Element.random(pairing, G1)  # g是G1的一个生成元
    alpha = Element.random(pairing, Zr)
    b = Element.random(pairing, Zr)
    egg = pairing.apply(g, g)
    theta = Element(pairing, GT, value=egg ** alpha)
    beta = Element(pairing, G1, value=g ** b)
    Universe, X = GetUniverse(params, g, n, ni)

    # 仅用于验证
    # for key,value in Universe.items():
    #     logger.info("Now A%s",key)
    #     for k,v in value.items():
    #         logger.info("key=%s and value=%s",k,v)
    #         if(k!=0):# 注意A0的存在
    #             print(key,k)
    #             temp=Element(pairing,G1,value=g**X[key][k])
    #             print(temp==v)

    PK = [params, g, Universe, theta, beta]
    MSK = [alpha, b, X]
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("GlobalSetup Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "PK.dat")
    logTime.info("%s is %s KB", "PK.dat", filesize_bytes / 1024)
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "SK.dat")
    logTime.info("%s is %s KB", "SK.dat", filesize_bytes / 1024)
    return [PK, MSK]
def KeyGenDU(PK, MSK, ID, Att):
    logger.info("==================KeyGenDU Start==================")
    MainTimeStart = datetime.now()
    """[summary]

    Args:
        PK ([type]): [description]
        MSK ([type]): [description]
        ID ([type]): [description]
        Att ([type]): [description]
    """
    [params, g, Universe, theta, beta] = PK
    [alpha, b, X] = MSK
    pairing = Pairing(params)
    alpha = Element(pairing, Zr, value=int(str(alpha), 16))
    b = Element(pairing, Zr, value=int(str(b), 16))
    g = Element(pairing, G1, value=str(g))

    n = len(Att)  # 假定Att与Universe满偏
    gamma = Element.random(pairing, Zr)
    u = Element.random(pairing, Zr)
    zDic = {}
    for i in range(1, n + 1):
        zi = Element.random(pairing, Zr)
        zDic[i] = zi

    hash_value = Element.from_hash(pairing, G1, Hash1(str(ID).encode()).hexdigest())
    K1 = Element(pairing, G1, value=g ** ((alpha + gamma) / b))
    K2 = Element(pairing, G1, value=g ** (alpha + b * u))
    temp1 = Element(pairing, G1, value=g ** alpha)
    temp2 = Element(pairing, G1, value=hash_value ** b)
    K3 = Element(pairing, G1, value=temp1 * temp2)

    Ki1Dic = {}
    Ki2Dic = {}
    for i in range(1, n + 1):
        xij = Element(pairing, Zr, value=int(str(X[i][1]), 16))
        Ki1 = Element(pairing, G1, value=g ** (gamma + xij))
        Ki2 = Element(pairing, G1, value=g ** zDic[i])
        Ki1Dic[i] = Ki1
        Ki2Dic[i] = Ki2

    egg = pairing.apply(g, g)
    temp1 = Element(pairing, Zr, value=u * alpha)
    PKu = Element(pairing, GT, value=egg ** temp1)
    SKu = [u, K1, K2, K3, Ki1Dic, Ki2Dic]
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("KeyGenDU Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    createFile(ParameterPathFromTools + "PKu.dat", str(PKu), "w")
    createFile(ParameterPathFromTools + "SKu.dat", str(SKu), "w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "PKu.dat")
    logTime.info("%s is %s KB", "PKu.dat", filesize_bytes / 1024)
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "SKu.dat")
    logTime.info("%s is %s KB", "SKu.dat", filesize_bytes / 1024)
    return [PKu, SKu]

def Enc(PK, N):
    """[summary]

    Args:
        PK ([type]): [description]
        FileSet ([type]): [description]
        M ([type]): [假设M为d*l的矩阵,]
        P ([type]): [description]
        PKOwners ([type]): [description]
    """
    [params, g, Universe, theta, beta] = PK
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))
    l = N
    k = N
    M = GetMartix(params, l, k)
    col = 1
    vector = GetVector(M, col)
    d=N

    C = {}

    egg = pairing.apply(g, g)
    tempr = Element.random(pairing, Zr)
    kf = Element(pairing, GT, value=egg ** tempr)
    c = kf
    s = Element(pairing, Zr, value=int(str(vector[1]), 16))
    Cq = Element(pairing, GT, value=kf * theta ** s)
    Cqq = Element(pairing, G1, value=g ** s)
    CtauDic = {}
    for i in range(1, d + 1):
        lamb = RowMutCol(params, M[i], vector)
        CtauDic[i] = lamb
    # So, we get C',C'',Ctau
    CT = [c, Cq, Cqq, CtauDic]
    return CT

def Dec(PK, CT, SKu, ID,N):
    logger.info("==================dec Start==================")
    MainTimeStart = datetime.now()
    [params, g, Universe, theta, beta] = PK
    [c, Cq, Cqq, CtauDic] = CT
    [u, K1, K2, K3, Ki1Dic, Ki2Dic] = SKu
    pairing = Pairing(params)
    Cqq = Element(pairing, G1, value=str(Cqq))
    K3 = Element(pairing, G1, value=str(K3))
    up = pairing.apply(Cqq, K3)
    HID = Element.from_hash(pairing, G1, Hash1(str(ID).encode()).hexdigest())
    Aut = Element.random(pairing, G1)
    for i in range(1, N + 1):
        Ci = Element(pairing, G1, value=CtauDic[i])
        L = pairing.apply(Ci, HID)
        R = pairing.apply(Aut, Cqq)
        Pi = Element(pairing, GT, value=L * R)
        temp = Element(pairing, GT, value=up/Pi)
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("dec Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    return temp

def main(num):
    Owners = GetOwners(num)
    ID = "User1"
    Att = Owners  # 实际上我只要他的长度即可
    P = 1
    w = "../Experiment/maildir/meyers-a/inbox/4."
    DList = GetDList("../Experiment/maildir/meyers-a")

    [PK, MSK] = GlobalSetup(n=num, ni=num)
    CT=Enc(PK, N=num)
    [PKu, SKu] = KeyGenDU(PK, MSK, ID, Att)
    temp=Dec(PK, CT, SKu, ID,N=num)

def GetUniverse(params, g, n, ni):
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))
    Universe = {}

    n = n + 1
    ni = ni + 1
    for i in range(1, n):
        Ai = {}
        V0 = {}
        for j in range(1, ni):
            V0[j] = Element.random(pairing, Zr)
        Ai[0] = V0
        Universe[i] = Ai

    X = {}
    for i in range(1, n):
        Vi = {}
        Xi = {}
        for j in range(1, ni):
            xij = Element.random(pairing, Zr)
            Xi[j] = xij
            Vi[j] = Element(pairing, G1, value=g ** xij)
            Universe[i][j] = Vi[j]
        X[i] = Xi

    return [Universe, X]


def GetOwners(d):
    Owners = {}
    for i in range(1, d + 1):
        Owners[i] = "Owner" + str(i)
    return Owners


def GetMartix(params, d, l):
    pairing = Pairing(params)
    Martix = {}
    for i in range(1, d + 1):
        MartixI = {}
        for j in range(1, l + 1):
            MartixI[j] = Element.random(pairing, Zr)
        Martix[i] = MartixI
    return Martix


def GetVector(Martix, col):
    """[从Martix中选取第col列]

    Args:
        Martix ([type]): [description]
        col ([type]): [description]

    Returns:
        [type]: [description]
    """
    d = len(Martix)
    vector = {}
    for i in range(1, d + 1):
        # vectorI={}
        # vectorI[col]=Martix[i][col]
        # vector[i]=vectorI
        vector[i] = Martix[i][col]
    return vector


def RowMutCol(params, row, col):
    pairing = Pairing(params)
    res = Element(pairing, Zr, value=0)
    for i, vr in row.items():
        vc = col[i]
        temp = Element(pairing, Zr, value=vr * vc)
        res = Element(pairing, Zr, value=res + temp)
    return res


def GetDList(dir):
    """[Reading files in deep]

    Args:
        dir ([str]): [Dir]

    Returns:
        [dict]: [Email dictionary]
    """
    logger.info("==================GetDList Start==================")

    p = Path(dir)
    DList = {}
    FileList = list(p.glob("**/*."))  # 递归查询文件
    for filepath in FileList:
        logger.info("Reading %s", filepath)

        D = {}

        # f=open(filepath, "rb+")
        # byt = f.read()
        # data=byt.decode("ISO-8859-1")
        # data=f.read()
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

        D[str(filepath)] = str(filepath)

        DList[filepath] = D
        # for key,value in D.items():
        #     print(value)
        # print(len(D))

    logger.info("==================GetDList End==================")
    return DList


def createDir(dstpath):
    """[递归创建文件夹]

    Args:
        dstpath ([type]): [description]
        type ([type]): [description]
    """
    path = dstpath.split("/")
    i = 0
    temp = ""
    while (i < len(path)):
        temp += path[i]
        if (i + 1 < len(path)):  # 代表这就是个文件夹
            if (not os.path.exists(temp)):
                os.mkdir(temp)
            temp += "/"

        i += 1


def createFile(dstpath, data, type):
    """[给定一个文件路径,自动创建文件夹并新建文件]

    Args:
        data ([str|byte]): [Depends on parameter type]
        dstpath ([str]): [The file path you want to create]
        type ([str]): [r,w,x,b]

    Returns:
        [int]: [Not in use]
    """
    logger.info("Creating %s file", dstpath)
    path = dstpath.split("/")
    i = 0
    temp = ""
    while (i < len(path)):
        temp += path[i]
        if (i + 1 < len(path)):  # 代表这就是个文件夹
            if (not os.path.exists(temp)):
                os.mkdir(temp)
            temp += "/"
        else:  # 即文件
            logger.info("Create %s", temp)
            f = open(temp, type)
            f.write(data)
        i += 1

    return 0


if __name__ == '__main__':
    MainTimeStart = datetime.now()
    for i in range(5, 50 + 1, 5):
        logTime.info("!!!!!!!!!!!!!Now Attribute Num=%s", i)
        main(i)
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Main Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
