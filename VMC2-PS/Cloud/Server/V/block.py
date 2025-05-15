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
file_handler = logging.FileHandler("../../log")
file_handler.setLevel(level=logging.INFO)
file_handler.setFormatter(formatter)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

logTime = logging.getLogger("logTime")
logTime.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
fileTime_handler = logging.FileHandler("../../logTime")
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


def GlobalSetup(qbits=512, rbits=160):
    """[summary]

    Args:
        qbits (int, optional): [description]. Defaults to 512.
        rbits (int, optional): [description]. Defaults to 160.
        xi (dict, optional): [description]. Defaults to {}.
    """
    logger.info("==================GlobalSetup Start==================")
    MainTimeStart = datetime.now()
    params = Parameters(qbits=qbits, rbits=rbits)  # 参数初始化,pp
    pairing = Pairing(params)  # 根据参数实例化双线性对,e
    g = Element.random(pairing, G1)  # g是G1的一个生成元,g
    g1 = Element.random(pairing, G1)  # g1是G1的一个生成元,g1
    alpha = Element.random(pairing, Zr)
    a = Element.random(pairing, Zr)
    a0 = Element.random(pairing, Zr)
    k=random.randint(1,1000)
    egg = pairing.apply(g, g)  # e(g,g)
    ali={}
    for i in range(1, k):
        ali[i] = Element.random(pairing, Zr)
        M = Element(pairing, G1, value=g ** ali[i])
        gal = Element(pairing, GT, value=egg ** ali[i])  # e(g,g)^alpha
    A = Element(pairing, G1, value=g ** a)
    A0 = Element(pairing, G1, value=g ** a0)

    PK = [params, g, g1, A, A0, gal]
    MSK = [M,k]
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("GlobalSetup Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "PK.dat")
    logTime.info("%s is %s KB", "PK.dat", filesize_bytes / 1024)
    # createFile(ParameterPathFromTools + "MSK.dat", str(MSK), "w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "MSK.dat")
    logTime.info("%s is %s KB", "MSK.dat", filesize_bytes / 1024)
    return [PK, MSK]


def KeyGen(PK, MSK, ID, Att,N):
    logger.info("==================KeyGen Start==================")
    MainTimeStart = datetime.now()
    """[summary]

    Args:
        PK ([type]): [description]
        MSK ([type]): [description]
        Att ([type]): [description]
    """
    [params, g, g1, A, A0, gal] = PK
    [M,k] = MSK
    pairing = Pairing(params)
    att=len(Att)
    chi={}
    for i in range(1,att):
        chi[i]=Element.random(pairing, G1)
        hashvalue=Element.from_hash(pairing, Zr, Hash1(str(chi[i]).encode()).hexdigest())
    kx=Element(pairing, G1, value=hashvalue ** 0)
    randomness=random.randint(1,len(chi))
    chip=chi[randomness]
    hash1_value = Element.from_hash(pairing, Zr, Hash1(str(chip).encode()).hexdigest())
    tu = {}
    for i in range(1, k):
        tu[i] = Element.random(pairing, Zr)
        k1i = Element(pairing, G1, value=g1 ** tu[i])
        ku = Element(pairing, G1, value=M * A ** tu[i])
        lu = Element(pairing, G1, value=g ** tu[i])
        kuxi = Element(pairing, G1, value=hash1_value ** tu[i])
    k1=Element(pairing, G1, value=A0 * k1i)

    # ku = Element(pairing, G1, value=1 * kui)
    # lu = Element(pairing, G1, value=1 * lui)
    kux = Element(pairing, G1, value=kx * kuxi)

    du = [k1,ku,lu,kux]
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("KeyGen Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    # createFile(ParameterPathFromTools+"PKu.dat",str(PKu),"w")
    # createFile(ParameterPathFromTools+"SKsub.dat",str(SKsub),"w")
    # filesize_bytes = os.path.getsize(ParameterPathFromTools+"PKu.dat")
    # logTime.info("%s is %s KB","PKu.dat",filesize_bytes/1024)
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "SKsub.dat")
    logTime.info("%s is %s KB", "du.dat", filesize_bytes / 1024)
    return du


def Enc(PK, Att, w, N):
    l = N
    k = N
    logger.info("==================Enc Start==================")
    MainTimeStart = datetime.now()
    """[summary]#多行注释

    Args:
        PK ([type]): [description]
        M ([type]): [假设M为l*k的矩阵,]
        P ([type]): [description]
        SKpub ([type]): [description]
    """
    [params, g, g1, A, A0, gal] = PK
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))
    g1 = Element(pairing, G1, value=str(g1))
    A0 = Element(pairing, G1, value=str(A0))
    gal = Element(pairing, GT, value=str(gal))

    v = Element.random(pairing, Zr)
    s = Element.random(pairing, Zr)
    col = 1
    M = GetMartix(params, l, k)
    vector = GetVector(M, col)  # 矩阵中取一个向量v
    g = Element(pairing, G1, value=str(g))
    r = Element.random(pairing, Zr)
    egg = pairing.apply(g, g)
    m = Element(pairing, GT, value=egg ** r)
    C = Element(pairing, GT, value=m* gal ** s)
    Cp = Element(pairing, G1, value=g ** s)
    I=Cp
    Ip=Element(pairing, G1, value=g1 ** s)
    temp = pairing.apply(A0, g)
    Ipp=Element(pairing, GT, value=temp ** s)
    Ci = {}
    for i in range(1, l + 1):
        lamb = RowMutCol(params, M[i], vector)  # λ
        Ci[i] = lamb
    randomness = random.randint(1, len(Ci))
    temp1 = Element(pairing, G1, value=A0 ** Ci[randomness])
    hash_value = Element.from_hash(pairing, Zr, Hash(str(Att).encode()).hexdigest())
    hash1_value = Element.from_hash(pairing, Zr, Hash1(str(w).encode()).hexdigest())
    temp2 = Element(pairing, Zr, value=hash_value**(-s))
    Ci = Element(pairing, G1, value=temp1*temp2)
    Ii=Element(pairing, G1, value=hash_value**(s/hash1_value))
    CT = [C, Cp, Ci]
    Index = [I,Ip,Ipp,Ii]
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart  # 计算时间
    logTime.info("Enc Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    createFile(ParameterPathFromTools+"CT.dat",str(CT),"w")
    logTime.info("CT.dat size = %s B", sys.getsizeof(str(CT)))
    createFile(ParameterPathFromTools + "Index.dat", str(CT), "w")
    logTime.info("Index.dat size = %s B", sys.getsizeof(str(CT)))
    return [CT,Index]


def Trap(PK, wp, du,Att):
    logger.info("==================Trap Start==================")
    MainTimeStart = datetime.now()
    [params, g, g1, A, A0, gal]  = PK
    [k1, ku, lu, kux]=du
    pairing = Pairing(params)
    tup = Element.random(pairing, Zr)
    k1 = Element(pairing, G1, value=str(k1))
    lu = Element(pairing, G1, value=str(lu))
    kux = Element(pairing, G1, value=str(kux))
    g = Element(pairing, G1, value=str(g))
    g1 = Element(pairing, G1, value=str(g1))
    hash_value = Element.from_hash(pairing, G1, Hash(str(tup).encode()).hexdigest())
    hash1_value = Element.from_hash(pairing, Zr, Hash1(str(wp).encode()).hexdigest())
    T0=Element(pairing, G1, value=lu * g** tup)
    one = Element(pairing, Zr, value=1)
    t = {}
    fp=Element.one(pairing, G1)
    att = len(Att)
    for i in range(1, att):
        f = Element(pairing, G1, value=k1 * g1 ** tup)
        ft = Element(pairing, G1, value=kux * hash_value ** tup)
        ftp = Element(pairing, G1, value=ft ** (one / hash1_value))
        fp=Element(pairing, G1, value=fp * ftp)
        T1=Element(pairing, G1, value=f * ftp)
    TG = [T0, T1]

    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Trap Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    logTime.info("TG.dat size = %s B", sys.getsizeof(str(TG)))
    createFile(ParameterPathFromTools+"TG.dat",str(TG),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"TG.dat")
    logTime.info("%s is %s KB","TG.dat",filesize_bytes/1024)
    return TG


def Search(PK, CT, Index, TG, Att):
    logger.info("==================Search Start==================")
    MainTimeStart = datetime.now()
    [params, g, g1, A, A0, gal]  = PK
    [C, Cp, Ci]=CT
    [I, Ip, Ipp, Ii]=Index
    [T0, T1]=TG
    pairing = Pairing(params)
    T0 = Element(pairing, G1, value=str(T0))
    T1 = Element(pairing, G1, value=str(T1))
    Ii = Element(pairing, G1, value=str(Ii))
    Ip = Element(pairing, G1, value=str(Ip))
    Ipp = Element(pairing, GT, value=str(Ipp))
    Cp = Element(pairing, G1, value=str(Cp))
    temp=Element(pairing, G1, value=1)
    att=len(Att)
    for i in range(1, att):
        temp=Element(pairing, G1, value=temp*Ii)
    temp1 = pairing.apply(T0, Ip*temp)
    temp2 = pairing.apply(Cp, T1)
    temp2p = Element(pairing, GT, value=temp2/Ipp)

    if temp1 == temp2p:
        logger.info("1")

    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Search Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    logTime.info("Search.dat size = %s B", sys.getsizeof(str(Search)))
    # createFile(ParameterPathFromTools+"Policytest.dat",str(Tdsub),"w")
    # filesize_bytes = os.path.getsize(ParameterPathFromTools+"Policytest.dat")
    # logTime.info("%s is %s KB","Policytest.dat",filesize_bytes/1024)
    return temp1


def Dec(PK, CT, du):
    logger.info("==================Dec Start==================")
    MainTimeStart = datetime.now()
    [params, g, g1, A, A0, gal] = PK
    [C, Cp, Ci] = CT
    [k1, ku, lu, kux] = du
    pairing = Pairing(params)
    Pi = Element(pairing, G1, value=1)
    Ci = Element(pairing, G1, value=str(Ci))
    lu = Element(pairing, G1, value=str(lu))
    C = Element(pairing, GT, value=str(C))
    Cp= Element(pairing, G1, value=str(Cp))
    ku = Element(pairing, G1, value=str(ku))
    kux = Element(pairing, G1, value=str(kux))
    oi={}
    for i in range(1, AttributeNumber + 1):
        oi[i]=Element.random(pairing, Zr)
        tem2 = Element(pairing, G1, value=Pi* kux**(-oi[i]))
    temp1 = pairing.apply(Pi * Ci**(-oi[i]),lu)
    temp2 = pairing.apply(Cp , ku*tem2)
    E=Element(pairing, GT, value=temp1 * temp2 )
    m = Element(pairing, GT, value=C / E)

    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Dec Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    # logTime.info("PreDec.dat size = %s B", sys.getsizeof(str(PreDec)))
    # createFile(ParameterPathFromTools+"CTm.dat",str(Tdsub),"w")
    # filesize_bytes = os.path.getsize(ParameterPathFromTools+"CTm.dat")
    # logTime.info("%s is %s KB","CTm.dat",filesize_bytes/1024)
    return m



def main(num):
    subs = Getsubs(num)
    ID = "pub1"
    Att = subs  # 实际上我只要他的长度即可
    w = "../Experiment/maildir/meyers-a/inbox/4."  # 直接用
    wp = "../Experiment/maildir/meyers-a/inbox/4."
    # RList=GetRList("../Experiment/maildir/meyers-a")

    [PK, MSK] = GlobalSetup()
    du = KeyGen(PK, MSK, ID, Att,N=num)
    [CT,Index] = Enc(PK, Att, w, N=num)
    TG = Trap(PK, wp, du,Att)
    search = Search(PK, CT, Index, TG, Att)
    m = Dec(PK, CT, du)


def GetUniverse(params, g, N):  # 生成xi,域，二叉树
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))
    xi = {}
    N = N + 1
    for i in range(1, N):
        x = Element.random(pairing, Zr)
        xi[i] = x
    return xi


def Getsubs(d):  # 得到订阅者数量
    subs = {}
    for i in range(1, d + 1):
        subs[i] = "sub" + str(i)  # owner1，owner2...
    return subs


def GetMartix(params, l, k):  # 生成矩阵
    pairing = Pairing(params)
    Martix = {}
    for i in range(1, l + 1):
        MartixI = {}  # 初始化
        for j in range(1, k + 1):
            MartixI[j] = Element.random(pairing, Zr)  # j
        Martix[i] = MartixI  # i
    return Martix


def GetVector(Martix, col):  # 从矩阵中取一个向量v
    """[从Martix中选取第col列]

    Args:
        Martix ([type]): [description]
        col ([type]): [description]

    Returns:
        [type]: [description]
    """
    l = len(Martix)
    vector = {}
    for i in range(1, l + 1):
        # vectorI={}
        # vectorI[col]=Martix[i][col]
        # vector[i]=vectorI
        vector[i] = Martix[i][col]  # 第col列
    return vector


def RowMutCol(params, row, col):  # 求策略中λ
    pairing = Pairing(params)
    res = Element(pairing, Zr, value=0)  # 初始化
    for i, vr in row.items():  # 遍历每行  row中的数
        vc = col[i]  # 每行的col列值
        temp = Element(pairing, Zr, value=vr * vc)
        res = Element(pairing, Zr, value=res + temp)  # 矩阵相乘
    return res


def add_to_16(text):
    """[Append text to be enough for times of 16]

    Args:
        text ([str]): [Original text]

    Returns:
        [str]: [Qualified text]
    """
    # text=text.encode()
    if len(text) % 16:
        add = 16 - (len(text) % 16)
    else:
        add = 0
    text = text + ('\0' * add)
    return text


def encrypt(text, key, iv):
    """[Encrypt data by AES]

    Args:
        text ([str]): [Plain data]
        key ([str]): [AES key must be times of 16]
        iv ([str]): [iv must be times of 16]

    Returns:
        [byte]: [Encrypted data]
    """
    key = str(key).encode('utf-8')
    mode = AES.MODE_CBC
    # iv = b'qqqqqqqqqqqqqqqq'
    iv = str(iv).encode('utf-8')
    text = add_to_16(str(text))
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(text)
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
    return b2a_hex(cipher_text)


def generate_random_str(randomlength=16):
    """[生成一个指定长度的随机字符串]

    Args:
        randomlength (int, optional): [description]. Defaults to 16.

    Returns:
        [str]: [String in random]
    """
    random_str = ''
    base_str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    length = len(base_str) - 1
    for i in range(randomlength):
        random_str += base_str[random.randint(0, length)]
    return random_str


def decrypt(text, key, iv):
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
    # iv = b'qqqqqqqqqqqqqqqq'
    iv = iv.encode('utf-8')
    cryptos = AES.new(key, mode, iv)
    plain_text = cryptos.decrypt(a2b_hex(text))
    return bytes.decode(plain_text).rstrip('\0')  # 解密后，去掉补足的空格用strip() 去掉


def GetRList(dir):  # 用户撤销列表
    """[Reading files in deep]

    Args:
        dir ([str]): [Dir]

    Returns:
        [dict]: [Email dictionary]
    """
    logger.info("==================GetRList Start==================")

    p = Path(dir)
    RList = {}
    FileList = list(p.glob("**/*."))  # 递归查询文件
    for filepath in FileList:
        logger.info("Reading %s", filepath)

        R = {}

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

        R[str(filepath)] = str(filepath)

        RList[filepath] = R
        # for key,value in D.items():
        #     print(value)
        # print(len(D))

    logger.info("==================GetRList End==================")
    return RList


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
