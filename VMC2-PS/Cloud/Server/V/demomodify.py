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

Hash = hashlib.sha256
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
    createFile(ParameterPathFromTools + "PK.dat", str(PK), "w")
    createFile(ParameterPathFromTools + "SK.dat", str(MSK), "w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "PK.dat")
    logTime.info("%s is %s KB", "PK.dat", filesize_bytes / 1024)
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "SK.dat")
    logTime.info("%s is %s KB", "SK.dat", filesize_bytes / 1024)
    return [PK, MSK]


def KeyGenDO(PK, Owners):
    logger.info("==================KeyGenDO Start==================")
    MainTimeStart = datetime.now()
    [params, g, Universe, theta, beta] = PK
    pairing = Pairing(params)
    d = len(Owners)
    PKOwners = {}
    SKOwners = {}
    for i in range(1, d + 1):
        sk = Element.random(pairing, Zr)
        pk = Element(pairing, G1, value=g ** sk)
        PKOwners[i] = pk
        SKOwners[i] = sk

    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("KeyGenDO Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    createFile(ParameterPathFromTools + "PKOwners.dat", str(PKOwners), "w")
    createFile(ParameterPathFromTools + "SKOwners.dat", str(SKOwners), "w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "PKOwners.dat")
    logTime.info("%s is %s KB", "PKOwners.dat", filesize_bytes / 1024)
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "SKOwners.dat")
    logTime.info("%s is %s KB", "SKOwners.dat", filesize_bytes / 1024)
    return [PKOwners, SKOwners]


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


def Enc(PK, DList, N):
    logger.info("==================Enc Start==================")
    MainTimeStart = datetime.now()
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
    l=N
    k=N
    d=N
    M = GetMartix(params, l, k)
    col = 1
    vector = GetVector(M, col)

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
    C = [c, Cq, Cqq, CtauDic]

    flag = True
    # for Windset in DList.items():
    I = {}
    for keyword, content in DList.items():
        piDic = {}
        IiDic = {}
        Iw = {}
        IijDic = {}
        PI = Element(pairing, Zr, value=0)
        for i in range(1, n + 1):
            IijiDic = {}

            pi = Element.random(pairing, Zr)
            piDic[i] = pi
            Ii = Element(pairing, G1, value=g ** pi)
            PI = Element(pairing, Zr, value=PI + pi)
            IiDic[i] = Ii

            for j in range(1, ni + 1):
                if (True):
                    temp = Universe[i][j]
                    Iij = Element(pairing, G1, value=temp ** pi)
                else:
                    Iij = Element.random(pairing, G1)
                IijiDic[j] = Iij
            IijDic[i] = IijiDic

        Iq = Element(pairing, GT, value=theta ** PI)
        hash_value = Element.from_hash(pairing, Zr, Hash1(str(content).encode()).hexdigest())
        Iqq = Element(pairing, G1, value=beta ** (PI / hash_value))

        Iw = [Iq, Iqq, IiDic, IijDic]
        I[content] = Iw
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Enc Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    createFile(ParameterPathFromTools + "C.dat", str(C), "w")
    createFile(ParameterPathFromTools + "I.dat", str(I), "w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "C.dat")
    logTime.info("%s is %s KB", "C.dat", filesize_bytes / 1024)
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "I.dat")
    logTime.info("%s is %s KB", "I.dat", filesize_bytes / 1024)
    return [C, I]


def Trap(PK, w, SKu, Att):
    logger.info("==================Trap Start==================")
    MainTimeStart = datetime.now()
    [params, g, Universe, theta, beta] = PK
    [u, K1, K2, K3, Ki1Dic, Ki2Dic] = SKu
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))

    mu = Element.random(pairing, Zr)
    Tq = Element(pairing, Zr, value=u + mu)
    hash_value = Element.from_hash(pairing, Zr, Hash1(str(w).encode()).hexdigest())
    Tqq = Element(pairing, G1, value=K1 ** (hash_value * mu))

    Ti1Dic = {}
    Ti2Dic = {}
    for i, Ki1 in Ki1Dic.items():
        Ki2 = Ki2Dic[i]
        Ti1 = Element(pairing, G1, value=Ki1 ** mu)
        Ti2 = Element(pairing, G1, value=Ki2 ** mu)
        Ti1Dic[i] = Ti1
        Ti2Dic[i] = Ti2

    Tw = [Tq, Tqq, Ti1Dic, Ti2Dic]
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Trap Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    createFile(ParameterPathFromTools + "Tw.dat", str(Tw), "w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "Tw.dat")
    logTime.info("%s is %s KB", "Tw.dat", filesize_bytes / 1024)
    return Tw


def Search(PK, Att, Tw, C, I):
    logger.info("==================Search Start==================")
    MainTimeStart = datetime.now()
    [params, g, Universe, theta, beta] = PK
    [Tq, Tqq, Ti1Dic, Ti2Dic] = Tw
    [c, Cq, Cqq, CtauDic] = C
    CT = [c, Cq, Cqq, CtauDic]
    pairing = Pairing(params)
    gtone = Element(pairing, GT, value=1)
    ph1 = Element(pairing, GT, value=1)
    ph2 = Element(pairing, GT, value=1)
    Tq = Element(pairing, Zr, value=int(str(Tq), 16))
    Tqq = Element(pairing, G1, value=str(Tqq))
    att=len(Att)

    for keyword, Iw in I.items():
        [Iq, Iqq, IiDic, IijDic] = Iw
        Iq = Element(pairing, GT, value=str(Iq))
        Iqq = Element(pairing, G1, value=str(Iqq))
        IiDic={}
        Ti1Dic={}
        for i in range(1, att):
            IiDic[i] = Element.random(pairing, Zr)
            Ti1Dic[i] = Element.random(pairing, Zr)
            Ii = Element(pairing, G1, value=str(IiDic[i]))
            Ti1 = Element(pairing, G1, value=str(Ti1Dic[i]))
            temp = pairing.apply(Ii, Ti1)
            ph1 = Element(pairing, GT, value=ph1 * temp)

            Iij = Element(pairing, G1, value=str(IijDic[i][1]))
            Ti2 = Element(pairing, G1, value=str(Ti2Dic[i]))
            temp = pairing.apply(Iij, Ti2)
            ph2 = Element(pairing, GT, value=ph2 * temp)

            if (True):
                temp = 1
            else:
                temp = 1

        phi = Element(pairing, GT, value=ph1 / ph2)

        temp = pairing.apply(Iqq, Tqq)
        L = Element(pairing, GT, value=temp * (gtone / phi))

        temp = Element(pairing, GT, value=Iq ** Tq)
        R = Element(pairing, GT, value=temp)
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Search Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    # createFile(ParameterPathFromTools + "R.dat", str(R), "w")
    # filesize_bytes = os.path.getsize(ParameterPathFromTools + "R.dat")
    # logTime.info("%s is %s KB", "R.dat", filesize_bytes / 1024)
    return 1


def AllSearch(PK, ID, P, Att, Tw, CDic, IDic, n=10, ni=10):
    logger.info("==================AllSearch Start==================")
    MainTimeStart = datetime.now()
    Res = []
    for ind, CT in CDic.items():
        I = IDic[ind]
        # for k,v in I.items():
        #     print(k)
        b = Search(PK, ID, P, Att, Tw, CT, I)
        if (b == 0):
            continue
        else:
            Res.append(CT)
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("AllSearch Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    createFile(ParameterPathFromTools + "Res.dat", str(Res), "w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "Res.dat")
    logTime.info("%s is %s KB", "Res.dat", filesize_bytes / 1024)
    return Res


def Dec(PK, CT, SKu, ID):
    [params, g, Universe, theta, beta] = PK
    [c, Cq, Cqq, CtauDic] = CT
    [u, K1, K2, K3, Ki1Dic, Ki2Dic] = SKu
    pairing = Pairing(params)
    Cqq = Element(pairing, G1, value=str(Cqq))
    K3 = Element(pairing, G1, value=str(K3))
    up = pairing.apply(Cqq, K3)
    HID = Element.from_hash(pairing, G1, Hash1(str(ID).encode()).hexdigest())
    Aut = Element.random(pairing, G1)
    Pi = Element(pairing, GT, value=1)
    for i in range(1, AttributeNumber + 1):
        Ci = Element(pairing, G1, value=g ** CtauDic[i])
        L = pairing.apply(Ci, HID)
        R = pairing.apply(Aut, Cqq)
        temp = Element(pairing, GT, value=L * R)
        Pi = Element(pairing, GT, value=temp * Pi)

    return Pi


def AllDec(PK, Res, SKu, ID):
    logger.info("==================AllDec Start==================")
    MainTimeStart = datetime.now()
    decRes = []
    for CT in Res:
        Pi = 1
        Pi = Dec(PK, CT, SKu, ID)
        decRes.append(Pi)
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("AllDec Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    createFile(ParameterPathFromTools + "decRes.dat", str(decRes), "w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "decRes.dat")
    logTime.info("%s is %s KB", "decRes.dat", filesize_bytes / 1024)
    return decRes


def main(num):
    Owners = GetOwners(num)
    ID = "User1"
    Att = Owners  # 实际上我只要他的长度即可
    P = 1
    w = "../Experiment/maildir/meyers-a/inbox/4."
    DList = GetDList("../Experiment/maildir/meyers-a")

    [PK, MSK] = GlobalSetup(n=num, ni=num)
    [PKOwners, SKOwners] = KeyGenDO(PK, Owners)
    [PKu, SKu] = KeyGenDU(PK, MSK, ID, Att)

    [C, I] = Enc(PK, DList, N=num)

    Tw = Trap(PK, w, SKu, Att)
    R=Search(PK,Att,Tw,C,I)
    # Res = AllSearch(PK, ID, P, Att, Tw, AllC, AllI, n=num, ni=num)

    # DecRes = AllDec(PK, Res, SKu, ID)


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
