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
Hash2 = hashlib.sha256

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
    alpha = Element.random(pairing, Zr)
    beta = Element.random(pairing, Zr)
    a = Element.random(pairing, Zr)
    egg = pairing.apply(g, g)  # e(g,g)
    theta = Element(pairing, GT, value=egg ** a)  # e(g,g)^a
    gal = Element(pairing, G1, value=g ** alpha)
    gbe = Element(pairing, G1, value=g ** beta)
    ga = Element(pairing, G1, value=g ** a)

    PK = [params, g, theta, gal, gbe]
    MSK = [ga, alpha, beta]
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("GlobalSetup Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "PK.dat")
    logTime.info("%s is %s KB", "PK.dat", filesize_bytes / 1024)
    # createFile(ParameterPathFromTools + "MSK.dat", str(MSK), "w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "MSK.dat")
    logTime.info("%s is %s KB", "MSK.dat", filesize_bytes / 1024)
    return [PK, MSK]


def KeyGenpub(PK, MSK, pub):
    logger.info("==================KeyGenpub Start==================")
    MainTimeStart = datetime.now()
    [params, g, theta, gal, gbe] = PK
    [ga, alpha, beta] = MSK
    pairing = Pairing(params)

    rp = Element.random(pairing, Zr)
    ek1 = Element(pairing, G1, value=gal ** rp)
    ek2 = Element(pairing, G1, value=gbe*g ** (rp))
    SKpub = [ek1, ek2]
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("KeyGenpub Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    # createFile(ParameterPathFromTools+"PKOwners.dat",str(PKpub),"w")
    # createFile(ParameterPathFromTools+"SKpub.dat",str(SKpub),"w")
    # filesize_bytes = os.path.getsize(ParameterPathFromTools+"PKOwners.dat")
    # logTime.info("%s is %s KB","PKOwners.dat",filesize_bytes/1024)
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "SKpub.dat")
    logTime.info("%s is %s KB", "SKpub.dat", filesize_bytes / 1024)
    return SKpub


def KeyGensub(PK, MSK, ID, Att,N):
    logger.info("==================KeyGensub Start==================")
    MainTimeStart = datetime.now()
    """[summary]

    Args:
        PK ([type]): [description]
        MSK ([type]): [description]
        Att ([type]): [description]
    """
    [params, g, theta, gal, gbe] = PK
    [ga, alpha, beta] = MSK
    pairing = Pairing(params)
    rs = Element.random(pairing, Zr)

    dk1 = Element(pairing, G1, value=gal ** rs)
    dk2 = Element(pairing, G1, value=gbe ** rs)
    dk3 = Element(pairing, G1, value=ga*gal ** rs)
    dk4 = Element(pairing, G1, value=g ** rs)
    att=len(Att)
    chi={}
    for i in range(1,att):
        chi[i]=Element.random(pairing, G1)
    # print(chi)
    randomness=random.randint(1,len(chi))
    chip=chi[randomness]
    hash1_value = Element.from_hash(pairing, Zr, Hash1(str(chip).encode()).hexdigest())
    dkatt = Element(pairing, G1, value=hash1_value**rs)
    SKsub = [dk1,dk2,dk3,dk4,dkatt]
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("KeyGensub Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    # createFile(ParameterPathFromTools+"PKu.dat",str(PKu),"w")
    # createFile(ParameterPathFromTools+"SKsub.dat",str(SKsub),"w")
    # filesize_bytes = os.path.getsize(ParameterPathFromTools+"PKu.dat")
    # logTime.info("%s is %s KB","PKu.dat",filesize_bytes/1024)
    filesize_bytes = os.path.getsize(ParameterPathFromTools + "SKsub.dat")
    logTime.info("%s is %s KB", "SKsub.dat", filesize_bytes / 1024)
    return SKsub


def Enc(PK, Att, SKpub,N):
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
    [params, g, theta, gal, gbe] = PK
    pairing = Pairing(params)

    r = Element.random(pairing, Zr)
    v = Element.random(pairing, Zr)
    s1 = Element.random(pairing, Zr)
    col = 1
    M = GetMartix(params, l, k)
    vector = GetVector(M, col)  # 矩阵中取一个向量v
    g = Element(pairing, G1, value=str(g))
    egg = pairing.apply(g, g)
    m = Element(pairing, GT, value=egg ** r)
    # s1 = Element(pairing, Zr, value=int(str(vector[1]), 16))
    # s_hash = Element.from_hash(pairing, Zr, Hash2(str(vector[1]).encode()).hexdigest())
    # s=Element(pairing,Zr,value=s_hash)#秘密s
    # s = Element(pairing, Zr, value=int(str(vector[1]), 16))
    C0 = Element(pairing, GT, value=m * theta ** s1)
    C1 = Element(pairing, G1, value=g ** s1)
    C2 = Element(pairing, G1, value=g ** v)

    Ci = {}
    for i in range(1, l + 1):
        lamb = RowMutCol(params, M[i], vector)  # λ
        Ci[i] = lamb
    randomness = random.randint(1, len(Ci))
    temp1 = Element(pairing, G1, value=gal ** Ci[randomness])
    hash1_value = Element.from_hash(pairing, Zr, Hash1(str(Att).encode()).hexdigest())
    temp2 = Element(pairing, Zr, value=hash1_value**(-v))
    Ci = Element(pairing, G1, value=temp1*temp2)
    CT = [C0, C1, C2, Ci]
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart  # 计算时间
    logTime.info("AllEnc Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    createFile(ParameterPathFromTools+"CT.dat",str(CT),"w")
    logTime.info("CT.dat size = %s B", sys.getsizeof(str(CT)))
    return CT


def Tag(PK, MSK, pub, w, SKpub,N):
    logger.info("==================Tag Start==================")
    MainTimeStart = datetime.now()
    [params, g, theta, gal, gbe] = PK
    [ek1, ek2] = SKpub
    pairing = Pairing(params)
    v = Element.random(pairing, Zr)

    l = N
    mu = {}
    ri={}
    rix={}
    for i in range(1, l + 1):
        mu[i] = Element.random(pairing, Zr)
        ri[i] = Element.random(pairing, Zr)
    randomness = random.randint(1, len(ri))

    hash2_value = Element.from_hash(pairing, G1, Hash1(str(w).encode()).hexdigest())
    T1i = Element(pairing, G1, value=(ek1* hash2_value) ** ri[randomness])
    T1ip = Element(pairing, G1, value=T1i * gbe**v)
    T2i = Element(pairing, G1, value=ek2**ri[randomness])
    T3i = Element(pairing, G1, value=gal ** ri[randomness])
    T4i = Element(pairing, G1, value=g ** ri[randomness])
    Ti = [T1ip, T2i, T3i, T4i]

    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Tag Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    # createFile(ParameterPathFromTools+"Wi.dat",str(Wi),"w")
    createFile(ParameterPathFromTools+"Ti.dat",str(Ti),"w")
    logTime.info("Ti.dat size = %s B", sys.getsizeof(str(Ti)))
    # filesize_bytes = os.path.getsize(ParameterPathFromTools+"Wi.dat")
    # logTime.info("%s is %s KB","Wi.dat",filesize_bytes/1024)
    # filesize_bytes = os.path.getsize(ParameterPathFromTools+"Ti.dat")
    # logTime.info("%s is %s KB","Ti.dat",filesize_bytes/1024)
    return Ti


def Trap(PK, w, SKsub,N):
    logger.info("==================Trap Start==================")
    MainTimeStart = datetime.now()
    [params, g, theta, gal, gbe] = PK
    [dk1,dk2,dk3,dk4,dkatt] = SKsub
    pairing = Pairing(params)
    lt = N
    kt = lt
    Mt = GetMartix(params, lt, kt)
    col = 1
    vector = GetVector(Mt, col)  # 矩阵中取一个向量v
    s2 = Element(pairing, Zr, value=int(str(vector[1]), 16))  # 秘密st

    hash2_value = Element.from_hash(pairing, G1, Hash1(str(w).encode()).hexdigest())
    col = 1
    vector = GetVector(Mt, col)
    Tdi = {}
    for j in range(1, lt + 1):
        lambt = RowMutCol(params, Mt[j], vector)
        Tdi[j] = lambt
    randomness = random.randint(1, len(Tdi))
    temp1 = Element(pairing, G1, value=dk1 * hash2_value)
    Td1j = Element(pairing, G1, value=temp1 ** Tdi[randomness])
    Td2j = Element(pairing, G1, value=dk2 ** Tdi[randomness])
    Td3j = Element(pairing, G1, value=gal ** Tdi[randomness])
    Td4j = Element(pairing, G1, value=g ** Tdi[randomness])

    Tdsub = [Td1j, Td2j, Td3j, Td4j]

    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Trap Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    logTime.info("Tdsub.dat size = %s B", sys.getsizeof(str(Tdsub)))
    # createFile(ParameterPathFromTools+"Tdsub.dat",str(Tdsub),"w")
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"Tdsub.dat")
    logTime.info("%s is %s KB","Tdsub.dat",filesize_bytes/1024)
    return Tdsub


def Search(PK, Ti, Tdsub):
    logger.info("==================Search Start==================")
    MainTimeStart = datetime.now()
    [params, g, theta, gal, gbe] = PK
    [Td1j, Td2j, Td3j, Td4j] = Tdsub
    [T1ip, T2i, T3i, T4i]=Ti
    pairing = Pairing(params)
    Td1j = Element(pairing, G1, value=str(Td1j))
    Td2j = Element(pairing, G1, value=str(Td2j))
    Td3j = Element(pairing, G1, value=str(Td3j))
    Td4j = Element(pairing, G1, value=str(Td4j))
    T1ip = Element(pairing, G1, value=str(T1ip))
    T2i = Element(pairing, G1, value=str(T2i))
    T3i = Element(pairing, G1, value=str(T3i))
    T4i = Element(pairing, G1, value=str(T4i))

    temp1 = pairing.apply(T1ip, Td4j)
    temp2 = pairing.apply(Td2j, T3i)
    temp3 = pairing.apply(Td1j, T4i)
    temp4 = pairing.apply(T2i, Td3j)
    temp12 = Element(pairing, GT, value=temp1 * temp2)
    temp34 = Element(pairing, GT, value=temp3 * temp4)
    temp = Element(pairing, GT, value=temp12 / temp34)

    if temp == 1:
        logger.info("1")

    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Search Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    logTime.info("Search.dat size = %s B", sys.getsizeof(str(Search)))
    # createFile(ParameterPathFromTools+"Policytest.dat",str(Tdsub),"w")
    # filesize_bytes = os.path.getsize(ParameterPathFromTools+"Policytest.dat")
    # logTime.info("%s is %s KB","Policytest.dat",filesize_bytes/1024)
    return temp


def Dec(PK, CT, Ti, Tdsub, SKsub):
    logger.info("==================Dec Start==================")
    MainTimeStart = datetime.now()
    [params, g, theta, gal, gbe] = PK
    [C0, C1, C2, Ci] = CT
    [T1ip, T2i, T3i, T4i] = Ti
    [Td1j, Td2j, Td3j, Td4j] = Tdsub
    [dk1,dk2,dk3,dk4,dkatt] = SKsub
    pairing = Pairing(params)
    Pi = Element(pairing, GT, value=1)
    T1ip = Element(pairing, G1, value=str(T1ip))
    T2i = Element(pairing, G1, value=str(T2i))
    T3i = Element(pairing, G1, value=str(T3i))
    T4i = Element(pairing, G1, value=str(T4i))
    Td1j = Element(pairing, G1, value=str(Td1j))
    Td2j = Element(pairing, G1, value=str(Td2j))
    Td3j = Element(pairing, G1, value=str(Td3j))
    Td4j = Element(pairing, G1, value=str(Td4j))
    C0= Element(pairing, GT, value=str(C0))
    C1 = Element(pairing, G1, value=str(C1))
    Ci = Element(pairing, G1, value=str(Ci))
    C2 = Element(pairing, G1, value=str(C2))
    dk3 = Element(pairing, G1, value=str(dk3))
    dk4 = Element(pairing, G1, value=str(dk4))
    dkatt = Element(pairing, G1, value=str(dkatt))

    temp1 = pairing.apply(T1ip, Td4j)
    temp2 = pairing.apply(Td2j,T3i)
    temp3 = pairing.apply(Td1j, T4i)
    temp4 = pairing.apply(T2i, Td3j)
    temp12 = Element(pairing, GT, value=temp1 * temp2)
    temp34 = Element(pairing, GT, value=temp3 * temp4)
    temp = Element(pairing, GT, value=temp12 / temp34)

    tem1 = pairing.apply(C1, dk3)
    tem2 = pairing.apply(Ci, dk4)
    tem3 = pairing.apply(C2, dkatt)
    tem23 = Element(pairing, GT, value=tem2 * tem3)
    ci={}
    cj={}
    for i in range(1, AttributeNumber + 1):
        ci[i]=Element.random(pairing, Zr)
        cj[i]=Element.random(pairing, Zr)
    TK1 = Element(pairing, GT, value=temp * Pi** cj[i])
    tem= Element(pairing, GT, value=tem23 * Pi ** ci[i])
    TK2 = Element(pairing, GT, value=tem1 / tem)
    TK = Element(pairing, GT, value=TK1*TK2)
    m = Element(pairing, GT, value=C0 / TK)

    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Dec Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    # logTime.info("PreDec.dat size = %s B", sys.getsizeof(str(PreDec)))
    # createFile(ParameterPathFromTools+"CTm.dat",str(Tdsub),"w")
    # filesize_bytes = os.path.getsize(ParameterPathFromTools+"CTm.dat")
    # logTime.info("%s is %s KB","CTm.dat",filesize_bytes/1024)
    return m


# def Dec(PK, CT, CTm, dksub):
#     logger.info("==================Dec Start==================")
#     MainTimeStart = datetime.now()
#     [params, g, var, n, theta, gal, gbe, yi] = PK
#     [C, C0, C1, Ci1, Ci2, Ci3, Tl] = CT
#     [F, G] = CTm
#     pairing = Pairing(params)
#     C = Element(pairing, GT, value=str(C))
#     F = Element(pairing, GT, value=str(F))
#     G = Element(pairing, GT, value=str(G))
#     dksub = Element(pairing, Zr, value=int(str(dksub), 16))
#
#     z = dksub
#     one = Element.one(pairing, Zr)
#     m = Element(pairing, GT, value=C * F / (G ** (one / z)))
#     MainTimeEnd = datetime.now()
#     timeleapMain = MainTimeEnd - MainTimeStart
#     logTime.info("Dec Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
#     logTime.info("m.dat size = %s B", sys.getsizeof(str(m)))
#     # createFile(ParameterPathFromTools+"m.dat",str(m),"w")
#     # filesize_bytes = os.path.getsize(ParameterPathFromTools+"m.dat")
#     # logTime.info("%s is %s KB","m.dat",filesize_bytes/1024)
#     return m



def main(num):
    subs = Getsubs(num)
    ID = "pub1"
    Att = subs  # 实际上我只要他的长度即可
    w = "../Experiment/maildir/meyers-a/inbox/4."  # 直接用
    # RList=GetRList("../Experiment/maildir/meyers-a")

    [PK, MSK] = GlobalSetup()
    SKpub = KeyGenpub(PK, MSK, ID)
    SKsub = KeyGensub(PK, MSK, ID, Att,N=num)
    CT = Enc(PK, Att, SKpub,N=num)  #
    Ti = Tag(PK, MSK, ID, w, SKpub,N=num)
    Tdsub = Trap(PK, w, SKsub,N=num)
    search = Search(PK, Ti, Tdsub)
    m = Dec(PK, CT, Ti, Tdsub, SKsub)


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
