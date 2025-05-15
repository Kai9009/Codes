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

def GlobalSetup(qbits=512, rbits=160,N=10):
    """[summary]

    Args:
        qbits (int, optional): [description]. Defaults to 512.
        rbits (int, optional): [description]. Defaults to 160.
    """
    logger.info("==================GlobalSetup Start==================")
    MainTimeStart=datetime.now()
    params = Parameters(qbits=qbits, rbits=rbits)   #参数初始化,pp
    pairing = Pairing(params)  # 根据参数实例化双线性对,e
    g = Element.random(pairing, G1)  # g是G1的一个生成元,g
    theta = Element.random(pairing, Zr)
    alpha = Element.random(pairing, Zr)
    a = Element.random(pairing, Zr)
    k = Element.random(pairing, Zr)
    h = Element.random(pairing, Zr)
    v = Element.random(pairing, Zr)
    ga = Element(pairing, G1, value=g ** a)
    gk = Element(pairing, G1, value=g ** k)
    egg=pairing.apply(g, g)
    eggal = Element(pairing, GT, value=egg ** alpha)
    H = Element(pairing, G1, value=g**h)
    x = N
    f={}
    mu={}
    for i in range(1, x+1):
        fx=Element(pairing, Zr, value=theta * i + alpha)
        f[i]=fx
        mu[i]=Element.random(pairing, Zr)
    fkx=f[x]
    randomness = random.randint(1, len(mu))
    gmu = Element(pairing, G1, value=g ** mu[randomness])


    PK=[params,g,H,fkx,ga,eggal,gk,gmu,v]
    MSK=[alpha,a,k,theta]

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("GlobalSetup Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"PK.dat")
    logTime.info("%s is %s KB","PK.dat",filesize_bytes/1024)
    #logger.info("==================Point3==================")
    return [PK,MSK]

def KeyGen(PK,MSK,Att,N):
    logger.info("==================KeyGen Start==================")
    MainTimeStart=datetime.now()

    [params,g,H,fkx,ga,eggal,gk,gmu,v]=PK
    [alpha,a,k,theta]=MSK
    pairing=Pairing(params)
    g = Element(pairing, G1, value=str(g))
    H = Element(pairing, G1, value=str(H))
    gmu = Element(pairing, G1, value=str(gmu))
    fkx = Element(pairing, Zr, value=int(str(fkx), 16))
    a = Element(pairing, Zr, value=int(str(a), 16))
    k = Element(pairing, Zr, value=int(str(k), 16))

    r = Element.random(pairing, Zr)
    R = Element.random(pairing, Zr)
    v = Element.random(pairing, Zr)
    c = Element.random(pairing, Zr)
    t = Element.random(pairing, Zr)
    Ru = Element(pairing, G1, value=g ** R)
    cp = Element.random(pairing, Zr)
    tid =t/cp
    n=N
    id=N

    T=Element(pairing, Zr, value=g**id*r**n)
    temp1=Element(pairing, G1, value=g**(fkx/(a+T)))
    temp2=Element(pairing, G1, value=g**(t*(k/(a+T))))
    temp3=Element(pairing, G1, value=gmu**tid*v**c*R)
    K = Element(pairing, G1, value=temp1 *temp2 * temp3)
    L=Element(pairing, G1, value=g**c*R)
    LP = Element(pairing, Zr, value=g ** (a+c) * R)
    mu={}
    for i in range(1,n):
        mu[i]=Element.random(pairing, Zr)
    mui = mu[N-1]
    Ki = Element(pairing, G1, value=mui**((a+T)*c)*R)
    Dd1=Element(pairing, G1, value=g ** fkx * H**r*R)
    Dd2=Element(pairing, G1, value=g ** r * R)

    sk=[T,K,L,LP,Ki,Dd1,Dd2,Ru,tid]
    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("KeyGensub Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
    # createFile(ParameterPathFromTools+"PKu.dat",str(PKu),"w")
    # createFile(ParameterPathFromTools+"SKsub.dat",str(SKsub),"w")
    # filesize_bytes = os.path.getsize(ParameterPathFromTools+"PKu.dat")
    # logTime.info("%s is %s KB","PKu.dat",filesize_bytes/1024)
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"SKsub.dat")
    logTime.info("%s is %s KB","SKsub.dat",filesize_bytes/1024)
    return sk
def Trace(PK,sk,ID,N):
    logger.info("==================Trace Start==================")
    MainTimeStart=datetime.now()

    [params,g,H,fkx,ga,eggal,gk,gmu,v]=PK
    [T,K,L,LP,Ki,Dd1,Dd2,Ru,tid]=sk
    pairing=Pairing(params)
    v = Element(pairing, Zr, value=int(str(v), 16))
    g = Element(pairing, G1, value=str(g))
    H = Element(pairing, G1, value=str(H))
    ga = Element(pairing, G1, value=str(ga))
    gk = Element(pairing, G1, value=str(gk))
    gmu = Element(pairing, G1, value=str(gmu))
    eggal = Element(pairing, GT, value=str(eggal))
    T = Element(pairing, Zr,  value=int(str(T), 16))
    K = Element(pairing, G1, value=str(K))
    L = Element(pairing, G1, value=str(L))
    LP = Element(pairing, Zr, value=int(str(T), 16))
    Ki = Element(pairing, G1, value=str(Ki))
    Ki1={}
    for i in range(N):
        Ki1[i]=Element.random(pairing,G1)
    randomness = random.randint(1, len(Ki1))
    ki=Ki1[randomness]
    Dd1 = Element(pairing, G1, value=str(Dd1))
    Dd2 = Element(pairing, G1, value=str(Dd2))
    Ru = Element(pairing, G1, value=str(Ru))
    tid = Element(pairing, Zr, value=int(str(tid), 16))


    temp1 = pairing.apply(LP, g)
    temp2 = pairing.apply(L, ga)
    temp3 = pairing.apply(K, g**T*ga)
    temp4 = pairing.apply(L**T*LP, v)
    temp4 = pairing.apply(L ** T * LP, v)
    temp5 = pairing.apply(Ru, gk)
    temp6 = pairing.apply(ga, g**T)
    temp7 =  Element(pairing, GT, value=temp6**tid)
    temp8 = pairing.apply(temp7, gmu)
    temp9=Element(pairing, GT, value=temp3/(temp4*temp5*temp8))
    temp10=Element(pairing, GT, value=temp9*temp9)
    temp01=pairing.apply(Dd1, g)
    temp02 = pairing.apply(Dd2, H)
    temp03=Element(pairing, GT, value=temp01/temp02)
    one = Element.one(pairing, GT)
    temp04 = Element(pairing, GT, value=one/temp03)
    temp1004=Element(pairing, GT, value=temp10*temp04)
    temp05=pairing.apply(gmu, L**T*LP)
    temp06 = pairing.apply(Ki1[randomness], g)

    if temp1==temp2:
        logger.info("1")
    if eggal==temp1004:
        logger.info("1")
    if temp05==temp06:
        logger.info("1")

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("Trace Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
    # createFile(ParameterPathFromTools+"PKu.dat",str(PKu),"w")
    # createFile(ParameterPathFromTools+"SKsub.dat",str(SKsub),"w")
    # filesize_bytes = os.path.getsize(ParameterPathFromTools+"PKu.dat")
    # logTime.info("%s is %s KB","PKu.dat",filesize_bytes/1024)
    # filesize_bytes = os.path.getsize(ParameterPathFromTools+"SKsub.dat")
    # logTime.info("%s is %s KB","SKsub.dat",filesize_bytes/1024)
    return 1


def main(num):
    subs=Getsubs(num)
    ID="pub1"
    Att=subs # 实际上我只要他的长度即可
    w="../Experiment/maildir/meyers-a/inbox/4."#直接用
    [PK,MSK]=GlobalSetup(N=num)
    sk=KeyGen(PK, MSK, Att,N=num)
    trace=Trace(PK,sk,ID,N=num)


def GetUniverse(params,g,N):#生成xi,域，二叉树
    pairing = Pairing(params)
    g=Element(pairing,G1,value=str(g))
    xi={}
    N=N+1
    for i in range(1,N):
        x=Element.random(pairing,Zr)
        xi[i]=x
    return xi
def GetMartix(params,l,k):#生成矩阵
    pairing=Pairing(params)
    Martix={}
    for i in range(1,l+1):
        MartixI={}#初始化
        for j in range(1,k+1):
            MartixI[j]=Element.random(pairing,Zr)#j
        Martix[i]=MartixI#i
    return Martix

def GetVector(Martix,col):#从矩阵中取一个向量v
    """[从Martix中选取第col列]

    Args:
        Martix ([type]): [description]
        col ([type]): [description]

    Returns:
        [type]: [description]
    """
    l=len(Martix)
    vector={}
    for i in range(1,l+1):
        # vectorI={}
        # vectorI[col]=Martix[i][col]
        # vector[i]=vectorI
        vector[i]=Martix[i][col]#第col列
    return vector
def Getsubs(d):#得到订阅者数量
    subs={}
    for i in range(1,d+1):
        subs[i]="sub"+str(i)#owner1，owner2...
    return subs
def RowMutCol(params,row,col):#求策略中λ
    pairing=Pairing(params)
    res=Element(pairing,Zr,value=0)#初始化
    for i,vr in row.items():#遍历每行  row中的数
        vc=col[i]#每行的col列值
        temp=Element(pairing,Zr,value=vr*vc)
        res=Element(pairing,Zr,value=res+temp)#矩阵相乘
    return res
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
    key = str(key).encode('utf-8')
    mode = AES.MODE_CBC
    #iv = b'qqqqqqqqqqqqqqqq'
    iv=str(iv).encode('utf-8')
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

if __name__ == '__main__':
    MainTimeStart = datetime.now()
    for i in range(5, 50 + 1, 5):
        logTime.info("!!!!!!!!!!!!!Now Attribute Num=%s", i)
        main(i)
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Main Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
