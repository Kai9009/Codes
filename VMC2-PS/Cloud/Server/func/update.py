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
    h = Element.random(pairing, Zr)
    H = Element(pairing, G1, value=g**h)
    x = N
    f={}
    for i in range(1, x+1):
        fx=Element(pairing, Zr, value=theta * i + alpha)
        f[i]=fx
    fkx=f[x]
    PK=[params,g,H,fkx,theta]

    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("GlobalSetup Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
    filesize_bytes = os.path.getsize(ParameterPathFromTools+"PK.dat")
    logTime.info("%s is %s KB","PK.dat",filesize_bytes/1024)
    #logger.info("==================Point3==================")
    return PK

def Update(PK,N):

    logger.info("==================Update Start==================")
    MainTimeStart=datetime.now()
    [params,g, H, fkx,theta]=PK
    x = N
    pairing = Pairing(params)  # 根据参数实例化双线性对,e
    g = Element(pairing, G1, value=str(g))
    H = Element(pairing, G1, value=str(H))
    theta = Element(pairing, Zr, value=int(str(theta), 16))
    fkx = Element(pairing, Zr, value=int(str(fkx), 16))
    rd = Element.random(pairing, Zr)
    Rd1 = Element.random(pairing, G1)
    Rd2 = Element.random(pairing, G1)
    temp1=Element(pairing, G1, value=g**fkx)
    temp = Element(pairing, G1, value=H ** x)
    temp2=Element(pairing, G1, value=temp**rd)
    temp3=Element(pairing, G1, value=temp2*Rd1)
    Dd1=Element(pairing, G1, value=temp1*temp3)
    temp4 = Element(pairing, G1, value=g ** rd)
    Dd2=Element(pairing, G1, value=temp4*Rd2)
    Ukey=[Dd1,Dd2]


    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("Update Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
    logTime.info("Ukey.dat size = %s B", sys.getsizeof(str(Ukey)))
    return Ukey

def main(num):

    PK=GlobalSetup(N=num)
    Ukey=Update(PK, N=num)


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


if __name__ == '__main__':
    MainTimeStart = datetime.now()
    for i in range(5, 50 + 1, 5):
        logTime.info("!!!!!!!!!!!!!Now Attribute Num=%s", i)
        main(i)
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Main Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
