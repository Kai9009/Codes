from pypbc import *
import hashlib
import random
import logging
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)
from pathlib import Path
from email.parser import Parser
# import paramiko
# import os
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
import sys

Hash1 = hashlib.sha256
Hash2 = hashlib.sha256
Hash3 = hashlib.sha256

logger = logging.getLogger("Caedios")
logger.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
file_handler = logging.FileHandler("log")
file_handler.setLevel(level=logging.INFO)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

logTime = logging.getLogger("logTime")
logTime.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
fileTime_handler = logging.FileHandler("logTime")
fileTime_handler.setLevel(level=logging.INFO)
fileTime_handler.setFormatter(formatter)
logTime.addHandler(fileTime_handler)

ParameterPathFromTools = "Parameter/"
ServerPathFromTools = "Server/"
ClientPathFromTools = "Client/"
MailEncPathFromTools = "MailEnc/"
MailDecPathFromTools = "MailDec/"

stored_params = """type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1"""

poly = []
TDS = []
TDSJ=[]
VTDS = []
VTDSJ=[]
td1 = []
tdJ1=[]
td2 = []
tdJ2=[]
FI = []
numda = []
Cipherlist = []
Cdict={}
CipherJianlist = []
CJdict={}
taglist = []
tagJianlist = []
Mlist = []
MJlist = []
decMlist = []
decMjlist = []
WE = []
WD = []
WEWD=[]
T = []
TJ = []
buy1_data = []
sell1_data = []
buy2_data = []
sell2_data = []
cnumber=5000
def PRF_F(key, msg):
    """[PRF_F]

    Args:
        key ([type]): [description]
        msg ([type]): [description]

    Returns:
        [type]: [Random number]
    """
    random.seed(key + msg)
    final = random.random() * 1000000000000000000
    return final


def PRF_Fp(params, key, msg):
    """[PRF_Fp]

    Args:
        params ([type]): [description]
        key ([str]): [description]
        msg ([str]): [description]

    Returns:
        [type]: [Random hash value in group Zr]
    """
    pairing = Pairing(params)
    hash_value = Element.from_hash(pairing, Zr, Hash2((key + msg)).hexdigest())
    # hash_value = Element.from_hash(pairing, Zr, Hash2(("1".encode())).hexdigest())
    return hash_value

def polyvalue(x):
    ans = poly[0]
    temp = x
    for i in range(len(poly)-1):
        ans += temp * poly[i+1]
        temp *= x
    return ans

def Lagrange(PP,k):
    [params, g] = PP
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))
    for i in range(k):
        fenzi = Element.one(pairing, Zr)
        fenmu = Element.one(pairing, Zr)
        xi = i+1
        xi = Element(pairing,Zr,value=int(str(xi),16))
        for j in range(k):
            if j == i:
                continue
            xj = -(j+1)
            xj = Element(pairing,Zr,value=int(str(xi),16))
            fenzi = Element(pairing,Zr,value=fenzi*xi)
            temp = Element(pairing,Zr,value=xi-xj)
            fenmu = Element(pairing,Zr,value=fenmu*temp)
        xishu = Element(pairing,Zr,value=fenzi/fenmu)
        numda.append(xishu)
    beta = Element.zero(pairing,Zr)
    for i in range(k):
        fi = FI[i]
        fi = Element(pairing,Zr,value=int(str(fi),16))
        xishu = numda[i]
        xishu = Element(pairing,Zr,value=int(str(xishu),16))
        temp = Element(pairing,Zr,value=xishu*fi)
        beta = Element(pairing,Zr,value=beta + temp)
    return beta

def GlobalSetup(k, n):
    logger.info("==================GlobalSetup Start==================")
    params = Parameters(param_string=stored_params)
    # params = Parameters(qbits=qbits, rbits=rbits)
    pairing = Pairing(params)

    g = Element.random(pairing, G1)
    PP = [params, g]
    for i in range(n):
        fi = random.randint(0,1000000000000)
        fi = Element(pairing,Zr,value=int(str(fi),16))
        FI.append(fi)

    z =  Lagrange(PP,k)
    # beta = Element.random(pairing,Zr)
    z = Element(pairing,Zr,value=int(str(z),16))
    x = Element.random(pairing,Zr)
    y=Element.random(pairing,Zr)
    # print("x,y:" + str(x)+ str(y))
    g1 = Element(pairing, G1, value=g ** x)
    g2 = Element(pairing, G1, value=g ** y)
    g3=Element(pairing, G1, value=g ** z)
    pair = pairing.apply(g, g)
    for i in range(n):
        # fi = polyvalue(i+1)
        fi = FI[i]
        fi_zr = Element(pairing,Zr, value=int(str(fi),16))
        tdsi = Element(pairing,G1,value=g**fi_zr)
        vtdsi = Element(pairing,GT,value=pair**fi_zr)
        TDS.append(tdsi)
        VTDS.append(vtdsi)
    PK = [g1,g2,g3]
    SK = [x,y,z]
    # PPCopy=[str(params),str(g)]
    # createFile(ServerPathFromTools + ParameterPathFromTools + "PP.dat", str(PP), "w")
    # createFile(ServerPathFromTools + ParameterPathFromTools + "MSK.dat", str(MSK), "w")
    # file_stats = os.stat(ServerPathFromTools + ParameterPathFromTools + "PP.dat")
    # logTime.info("PP.dat size = %s B", file_stats.st_size)
    # file_stats = os.stat(ServerPathFromTools + ParameterPathFromTools + "MSK.dat")
    # logTime.info("MSK.dat size = %s B", file_stats.st_size)
    logTime.info("pk_ts.dat size = %s B",sys.getsizeof(str(PK)))
    logTime.info("sk_ts.dat size = %s B",sys.getsizeof(str(SK)))
    logTime.info("PP.dat size = %s B", sys.getsizeof(str(PP)))
    logTime.info("PK.dat size = %s B", sys.getsizeof(str(PK)))
    logTime.info("SK.dat size = %s B", sys.getsizeof(str(SK)))
    logTime.info("TK.dat size = %s B", sys.getsizeof(str(TDS)))
    logTime.info("VK.dat size = %s B", sys.getsizeof(str(VTDS)))
    logger.info("==================GlobalSetup End==================")
    return PP, PK, SK


def Encrypt(PP, PK, tag, M): #M in GT; tag in Zr
    logger.info("==================Encrypt Start==================")
    [params, g] = PP
    [g1,g2,g3] = PK
    pairing = Pairing(params)

    M = Element(pairing,G1,value=str(M))
    tag = Element(pairing,Zr,value=int(str(tag),16))
    g = Element(pairing, G1, value=str(g))
    g1 = Element(pairing, G1, value=str(g1))
    g2 = Element(pairing, G1, value=str(g2))
    g3 = Element(pairing, G1, value=str(g3))
    s = Element.random(pairing,Zr)
    r = Element.random(pairing, Zr)
    t=Element(pairing, Zr,value=s/r)

    pair=pairing.apply(g,g)

    Mstring =str(M).encode()
    c1 = Element(pairing,G1,value=g**r)
    c2 = Element(pairing,G1,value=g1**s)
    c3 = Element(pairing,G1,value=(g2**(r+s))*M)
    c4 = Element(pairing,GT,value=pairing.apply(g,(g3**r)*g2**(r+s)))
    c5 = Element(pairing,G1,value=((g3**tag)*g1)**r)
    c6 = Element(pairing,G1,value=g*(g1**t))

    C = {"c1":c1, "c2":c2, "c3":c3, "c4":c4, "c5":c5, "c6":c6}
    logger.info("==================Encrypt End==================")
    return C

def decrypt(PP, SK , tag, C):
    logger.info("==================Decrypt Start==================")
    [params, g] = PP
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))
    [x, y, z] = SK
    c1 = C["c1"]
    c2 = C["c2"]
    c3 = C["c3"]
    c4 = C["c4"]
    c5 = C["c5"]
    c6 = C["c6"]


    x = Element(pairing, Zr, value=int(str(x), 16))
    y = Element(pairing, Zr, value=int(str(y), 16))
    z = Element(pairing, Zr, value=int(str(z), 16))

    c1 = Element(pairing, G1, value=str(c1))
    c2 = Element(pairing, G1, value=str(c2))
    c3 = Element(pairing, G1, value=str(c3))
    c4 = Element(pairing, GT, value=str(c4))
    c5 = Element(pairing, G1, value=str(c5))
    c6 = Element(pairing, G1, value=str(c6))
    tag = Element(pairing, Zr , value=int(str(tag),16))

    t1=Element(pairing, GT, value=pairing.apply(g,(c1**y)*(c2**(y/x)))*pairing.apply(c1,g**z))
    t2=Element(pairing, GT, value=c4)
    t3=Element(pairing, GT, value=pairing.apply(c1,c6))
    t4=Element(pairing, GT, value=pairing.apply(g,c1*c2))
    t5=Element(pairing, GT, value=pairing.apply(c1,((g**z)**tag)*(g**x)))
    t6=Element(pairing, GT, value=pairing.apply(g,c5))
    # if t1==t2:
    #     flag1 = True
    # else:
    #     flag1 = False
    # if t3==t4:
    #     flag2 = True
    # else:
    #     flag2 = False
    #
    # if not flag1 or not flag2:
    #     logger.info("==================Ciphertext not valid!==================")
    # else:
    if((t1==t2)&(t3==t4)&(t5==t6)):
        message = Element(pairing,G1,value=c3/((c1**y)*(c2**(y/x))))
        Mstring = str(message).encode()

    logger.info("==================Decrypt End==================")
    return message

def validateCT(PP,PK,tag,C):
    logger.info("==================CT validate Start==================")
    [params, g] = PP
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))
    [g1,g2,g3] = PK
    c1 = C["c1"]
    c2 = C["c2"]
    c3 = C["c3"]
    c4 = C["c4"]
    c5 = C["c5"]
    c6 = C["c6"]

    tag = Element(pairing, Zr, value=int(str(tag), 16))
    g1 = Element(pairing, G1, value=str(g1))
    g2 = Element(pairing, G1, value=str(g2))
    g3 = Element(pairing, G1, value=str(g3))
    c1 = Element(pairing, G1, value=str(c1))
    c2 = Element(pairing, G1, value=str(c2))
    c3 = Element(pairing, G1, value=str(c3))
    c4 = Element(pairing, GT, value=str(c4))
    c5 = Element(pairing, G1, value=str(c5))
    c6 = Element(pairing, G1, value=str(c6))
    t1=Element(pairing, GT, value=pairing.apply(c1,(g3**tag)*g1))
    t2=Element(pairing, G1, value=pairing.apply(g,c5))
    if t1 == t2:
        return True
    else:
        return False

    logger.info("==================CT validate End==================")


def shareTagKey(PP,PK,i,TDSi,tag):
    logger.info("==================ShareTagKey Start==================")
    [params, g] = PP
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))
    [g1,g2,g3] = PK

    g1 = Element(pairing, G1, value=str(g1))
    g2 = Element(pairing, G1, value=str(g2))
    g3 = Element(pairing, G1, value=str(g3))
    tag = Element(pairing, Zr, value=int(str(tag), 16))
    TDSi = Element(pairing, G1, value= str(TDSi))

    eta= Element.random(pairing,Zr)
    temp1 = Element(pairing,G1,value=((g3**tag)*g1)**eta)
    alphai0 = Element(pairing,G1,value=TDSi*temp1)
    alphai1 = Element(pairing,G1,value=g**eta)
    logger.info("==================ShareTagKey Start==================")
    return alphai0,alphai1


def ShareTKVerify(PP,PK,i,VTDSi,tag,td1i):
    logger.info("==================ShareTKVerify Start==================")
    [params, g] = PP
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))
    [g1,g2,g3] = PK
    [alphai0,alphai1] = td1i

    g1 = Element(pairing, G1, value=str(g1))
    g2 = Element(pairing, G1, value=str(g2))
    g3 = Element(pairing, G1, value=str(g3))
    tag = Element(pairing, Zr, value=int(str(tag), 16))
    VTDSi = Element(pairing, G1, value= str(VTDSi))
    alphai0 = Element(pairing,G1,value=str(alphai0))
    alphai1 = Element(pairing, G1, value=str(alphai1))

    pair1 = pairing.apply(g,alphai0)
    pair2 = pairing.apply(alphai1,(g3**tag)*g1)
    falg = Element(pairing,GT,pair1-VTDSi*pair2)
    logger.info("==================ShareTKVerify End==================")
    if falg:
        return True
    else:
        return False

def ShareCipherKey(PP,PK,i,TDSi,tag,C):
    logger.info("==================ShareCipherKey Start==================")
    [params, g] = PP
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))
    [g1,g2,g3] = PK
    c1 = C["c1"]
    c2 = C["c2"]
    c3 = C["c3"]
    c4 = C["c4"]
    c5 = C["c5"]
    c6 = C["c6"]

    g1 = Element(pairing, G1, value=str(g1))
    g2 = Element(pairing, G1, value=str(g2))
    g3 = Element(pairing, G1, value=str(g3))
    tag = Element(pairing, Zr, value=int(str(tag), 16))
    TDSi = Element(pairing, G1, value=str(TDSi))
    c1 = Element(pairing, G1, value=str(c1))
    c2 = Element(pairing, G1, value=str(c2))
    c3 = Element(pairing, G1, value=str(c3))
    c4 = Element(pairing, GT, value=str(c4))
    c5 = Element(pairing, G1, value=str(c5))
    c6 = Element(pairing, G1, value=str(c6))
    eta = Element.random(pairing,Zr)
    betai0 = Element(pairing,G1,value=TDSi*(c6**eta))
    betai1 = Element(pairing,G1,value=g**eta)
    logger.info("==================ShareCipherKey End==================")
    return betai0,betai1



def ShareCKVerify(PP,PK,i,VTDSi,tag,C,td2i):
    logger.info("==================ShareCKVerify Start==================")
    [params, g] = PP
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))
    [g1,g2,g3] = PK
    [betai0,betai1] = td2i
    c1 = C["c1"]
    c2 = C["c2"]
    c3 = C["c3"]
    c4 = C["c4"]
    c5 = C["c5"]
    c6 = C["c6"]

    g1 = Element(pairing, G1, value=str(g1))
    g2 = Element(pairing, G1, value=str(g2))
    g3 = Element(pairing, G1, value=str(g3))
    tag = Element(pairing, Zr, value=int(str(tag), 16))
    VTDSi = Element(pairing, G1, value=str(VTDSi))
    betai0 = Element(pairing, G1, value=str(betai0))
    betai1 = Element(pairing, G1, value=str(betai1))
    c1 = Element(pairing, G1, value=str(c1))
    c2 = Element(pairing, G1, value=str(c2))
    c3 = Element(pairing, G1, value=str(c3))
    c4 = Element(pairing, GT, value=str(c4))
    c5 = Element(pairing, G1, value=str(c5))
    c6 = Element(pairing, G1, value=str(c6))

    pair1 = pairing.apply(g, betai0)
    pair2 = pairing.apply(betai1, c6)
    falg = Element(pairing, GT, pair1 - pair2*VTDSi)
    logger.info("==================ShareCKVerify End==================")
    if falg:
        return True
    else:
        return False

def Delta_t(PP,PK,tag,C,k,td):
    logger.info("==================Delta_t Start==================")
    [params, g] = PP
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))
    [g1,g2,g3] = PK
    c1 = C["c1"]
    c2 = C["c2"]
    c3 = C["c3"]
    c4 = C["c4"]
    c5 = C["c5"]
    c6 = C["c6"]

    g1 = Element(pairing, G1, value=str(g1))
    g2 = Element(pairing, G1, value=str(g2))
    g3 = Element(pairing, G1, value=str(g3))
    tag = Element(pairing, Zr, value=int(str(tag), 16))
    c1 = Element(pairing, G1, value=str(c1))
    c2 = Element(pairing, G1, value=str(c2))
    c3 = Element(pairing, G1, value=str(c3))
    c4 = Element(pairing, GT, value=str(c4))
    c5 = Element(pairing, G1, value=str(c5))
    c6 = Element(pairing, G1, value=str(c6))

    # if validateCT(PP,PK,tag,C):
    alpha0 = Element.one(pairing,G1)
    alpha1 = Element.one(pairing,G1)
    talpha0 = Element(pairing,G1,value=g3)
    talpha1 = Element.one(pairing,G1)

    for i in range(k):
        [alphai0,alphai1] = td[i]
        alphai0 = Element(pairing,G1,value=str(alphai0))
        alphai1 = Element(pairing,G1,value=str(alphai1))
        numdai = numda[i]
        numdai = Element(pairing,Zr,value=int(str(numdai),16))
        alphai0 = Element(pairing,G1,value=alphai0**numdai)
        alphai1 = Element(pairing,G1,value=alphai1**numdai)
        alpha0 = Element(pairing,G1,value=alpha0 * alphai0)
        alpha1 = Element(pairing,G1,value=alpha1 * alphai1)
    for i in range(k):
        numdai = numda[i]
        numdai = Element(pairing, Zr, value=int(str(numdai), 16))
        temp0=Element(pairing,G1,value=((g3**tag)*g1)**numdai)
        temp1=Element(pairing,G1,value=g**numdai)
        talpha0 =Element(pairing,G1,value=talpha0*temp0)
        talpha1 = Element(pairing,G1,value=talpha1*temp1)

    # print("alpha0:",alpha0)
    # print("talpha1:", talpha0)

    pair1 = pairing.apply(g,c3)
    pair2 = pairing.apply(c1,alpha0)
    pair3 = pairing.apply(alpha1,c5)
    Delta = Element(pairing,GT,value=((pair1*pair2)/(c4*pair3)))
    logger.info("==================Delta_t End==================")
    return Delta


def Delta_c(PP,PK,tag,C,k,td):
    logger.info("==================Delta_c Start==================")
    [params, g] = PP
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))
    [g1,g2,g3] = PK
    c1 = C["c1"]
    c2 = C["c2"]
    c3 = C["c3"]
    c4 = C["c4"]
    c5 = C["c5"]
    c6 = C["c6"]

    g1 = Element(pairing, G1, value=str(g1))
    g2 = Element(pairing, G1, value=str(g2))
    g3 = Element(pairing, G1, value=str(g3))
    tag = Element(pairing, Zr, value=int(str(tag), 16))
    c1 = Element(pairing, G1, value=str(c1))
    c2 = Element(pairing, G1, value=str(c2))
    c3 = Element(pairing, G1, value=str(c3))
    c4 = Element(pairing, GT, value=str(c4))
    c5 = Element(pairing, G1, value=str(c5))
    c6 = Element(pairing, G1, value=str(c6))

    # if validateCT(PP, PK, tag, C):
    beta0 = Element.one(pairing, G1)
    beta1 = Element.one(pairing, G1)
    for i in range(k):
        [betai0, betai1] = td[i]
        betai0 = Element(pairing, G1, value=str(betai0))
        betai1 = Element(pairing, G1, value=str(betai1))
        numdai = numda[i]
        numdai = Element(pairing, Zr, value=int(str(numdai), 16))
        betai0 = Element(pairing, G1, value=betai0 ** numdai)
        betai1 = Element(pairing, G1, value=betai1 ** numdai)
        beta0 = Element(pairing, G1, value=beta0 * betai0)
        beta1 = Element(pairing, G1, value=beta1 * betai1)
    pair1 = pairing.apply(g, c3)
    pair2 = pairing.apply(c1, beta0)
    pair3 = pairing.apply(beta1, c1*c2)
    Delta = Element(pairing, GT, value=(pair1*pair2) / (c4*pair3))
    logger.info("==================Delta_c Start==================")
    return Delta

def Test_tt(PP,PK1,tag,C,td,PK2,tagj,CJ,tdj,k):
    logger.info("==================Test_tt Start==================")
    for i in range(cnumber):
        ti= Delta_t(PP, PK1, tag[i], C[i], k,td)
        tji=Delta_t(PP, PK2, tagj[i], CJ[i], k,tdj)
        T.append(ti)
        TJ.append(tji)

    # for i in range(cnumber):
    #     Cdict[T[i]]=C[i]
    #     CJdict["TJ[i]"]=CJ[i]

    result = [x for x in T if x in TJ]
    for i in range(cnumber):
        for j in range(len(result)):
            if(T[i]==result[j]):
                WE.append(C[i])
            if(TJ[i]==result[j]):
                WD.append(CJ[i])

    WEWD=WE+WD
    # i=0
    # while(i<len(result)):
    #     WE.append(Cdict["result[i]"])
    #     WD.append(CJdict["result[i]"])
    #     i += 1
    # WEWD=WE+WD
    return WEWD


def Test_cc(PP,PK1,tag,C,td2,PK2,tagj,CJ,tdJ2,k):
    logger.info("==================Test_cc Start==================")
    for i in range(cnumber):
        ti = Delta_c(PP, PK1, tag[i], C[i], k,td2)
        tji = Delta_c(PP, PK2, tagj[i], CJ[i], k,tdJ2)
        T.append(ti)
        TJ.append(tji)


    result = [x for x in T if x in TJ]
    for i in range(cnumber):
        for j in range(len(result)):
            if(T[i]==result[j]):
                WE.append(C[i])
            if(TJ[i]==result[j]):
                WD.append(CJ[i])

    WEWD=WE+WD
    return WEWD


def Test_tc(PP,PK1,tag,C,td1,PK2,tagj,CJ,td2,k):
    logger.info("==================Test_tc Start==================")
    for i in range(cnumber):
        ti = Delta_t(PP, PK1, tag[i], C[i], k,td1)
        tji = Delta_c(PP, PK2, tagj[i], CJ[i], k,td2)
        T.append(ti)
        TJ.append(tji)
    result = [x for x in T if x in TJ]
    for i in range(cnumber):
        for j in range(len(result)):
            if (T[i] == result[j]):
                WE.append(C[i])
            if (TJ[i] == result[j]):
                WD.append(CJ[i])

    WEWD = WE + WD
    return WEWD


# def TTest_tt(PP,PK1,tag1,C1,td1,PK2,tag2,C2,td2,k):
#     logger.info("==================Test_tt Start==================")
#     if Delta_t(PP, PK1, tag1, C1, k,td1) == Delta_t(PP, PK2, tag2, C2, k,td2):
#         return True
#     else:
#         return False
#
# def TTest_cc(PP,PK1,tag1,C1,td1,PK2,tag2,C2,td2,k):
#     logger.info("==================Test_cc Start==================")
#     if Delta_c(PP, PK1, tag1, C1, k,td1) == Delta_c(PP, PK2, tag2, C2, k,td2):
#         return True
#     else:
#         return False

def main():
    print("Setup Start")
    k = 2
    n = 2
    MainTimeStart = datetime.now()
    PP, PK, SK = GlobalSetup(k,n)
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("GlobalSetup Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    print("Setup Down")
    print("Setup Time:",timeleapMain,"s")




    [params, g] = PP
    pairing = Pairing(params)
    g = Element(pairing, G1, value=str(g))


    data = pd.read_csv('./ftr_bids_buy.csv', low_memory=False)
    column_data = data['quoted_mw']
    # print("buylen",len(column_data))
    for i in range(cnumber):
        buyi = str(column_data[i]).encode()
        buyi_hash = Element.from_hash(pairing, G1, Hash1(buyi).hexdigest())
        buy1_data.append(buyi_hash)
    # print("buy:",buy1_data[0])
    dataj = pd.read_csv('./ftr_bids_sell.csv', low_memory=False)
    columnj_data = dataj['quoted_mw']
    # print("selllen",len(columnj_data))
    for i in range(cnumber):
        selli = str(columnj_data[i]).encode()
        selli_hash = Element.from_hash(pairing, G1, Hash1(selli).hexdigest())
        sell1_data.append(selli_hash)
    # print("sell:",sell1_data[0])
    # resultm = [x for x in buy1_data if x in sell1_data]
    # print("resultm:",resultm)
    data = pd.read_csv('./ftr_bids_buy.csv', low_memory=False)
    column_data = data['quoted_price']
    # print("buylen",len(column_data))
    for i in range(cnumber):
        buyi = str(column_data[i]).encode()
        buyi_hash = Element.from_hash(pairing, G1, Hash1(buyi).hexdigest())
        buy2_data.append(buyi_hash)
    # print("buy:", buy2_data[0])
    dataj = pd.read_csv('./ftr_bids_sell.csv', low_memory=False)
    columnj_data = dataj['quoted_price']
    # print("selllen",len(columnj_data))
    for i in range(cnumber):
        selli = str(columnj_data[i]).encode()
        selli_hash = Element.from_hash(pairing, G1, Hash1(selli).hexdigest())
        sell2_data.append(selli_hash)
    # print("sell:", sell2_data[0])

    MainTimeStart = datetime.now()
    print("Encryption Start")
    tagZ=Element.random(pairing, Zr)
    tagz=Element.random(pairing, Zr)
    for i in range(int(cnumber/2)):
        tag = tagZ
        taglist.append(tag)
        M = buy1_data[i]
        Mlist.append(M)
        Cipher = Encrypt(PP, PK , tag , M)
        Cipherlist.append(Cipher)
    for i in range(int(cnumber / 2)):
        tag2 = tagz
        taglist.append(tag2)
        M = buy2_data[i-1+int(cnumber / 2)]
        Mlist.append(M)
        Cipher = Encrypt(PP, PK, tag2, M)
        Cipherlist.append(Cipher)
        # tag = Element.random(pairing, Zr)
        # M = Element.random(pairing, G1)
        # Mlist.append(M)
        # taglist.append(tag)
        # Cipher = Encrypt(PP, PK, tag, M)
        # Cipherlist.append(Cipher)
    for i in range(int(cnumber/2)):
        tagJ = tagZ
        M = sell1_data[i]
        MJlist.append(M)
        tagJianlist.append(tagJ)
        CipherJ = Encrypt(PP, PK, tagJ, M)
        CipherJianlist.append(CipherJ)
    for i in range(int(cnumber / 2)):
        tagj2=tagz
        M = sell2_data[i-1+int(cnumber / 2)]
        MJlist.append(M)
        tagJianlist.append(tagj2)
        CipherJ = Encrypt(PP, PK, tagj2, M)
        CipherJianlist.append(CipherJ)
    print("Encryption Down")
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Encrypt Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    print("Encryption Time:", timeleapMain, "s")

    MainTimeStart = datetime.now()
    print("Decryption Start")
    for i in range(cnumber):
        # [params, g] = PP
        # pairing = Pairing(params)
        # g = Element(pairing, G1, value=str(g))
        # print(i)

        # print(tag)
        decM = decrypt(PP,SK,taglist[i],Cipherlist[i])
        # print("decM:",decM)
        # M = Element.random(pairing,GT)
        decMlist.append(decM)

    for i in range(cnumber):
        # [params, g] = PP
        # pairing = Pairing(params)
        # g = Element(pairing, G1, value=str(g))
        # print(i)

        # print(tag)
        decMj = decrypt(PP,SK,tagJianlist[i],CipherJianlist[i])
        # print("decM:",decMj)
        # M = Element.random(pairing,GT)
        decMjlist.append(decMj)
    print("Decryption Down")
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Decrypt Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    print("Decryption Time:", timeleapMain, "s")



    MainTimeStart = datetime.now()
    print("td1 generation")
    for i in range(n):
        TDSi = TDS[i]
        TDSi = Element(pairing,G1,value=str(TDSi))
        tag = taglist[i]
        tag = Element(pairing,Zr,value=int(str(tag),16))
        [alphai0,alphai1] = shareTagKey(PP,PK,i,TDSi,tag)
        td1.append([alphai0,alphai1])
        tagJ = tagJianlist[i]
        tagJ = Element(pairing, Zr, value=int(str(tagJ), 16))
        [alphaJi0, alphaJi1] = shareTagKey(PP, PK, i, TDSi, tagJ)
        tdJ1.append([alphaJi0, alphaJi1])

    print("td1 generation end")
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("ShareTagKey Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    print("ShareTagKey Time:", timeleapMain, "s")

    MainTimeStart = datetime.now()
    print("td2 generation")
    for i in range(n):

        TDSi = Element(pairing,G1,value=str(TDSi))
        tag = taglist[i]
        tag = Element(pairing,Zr,value=int(str(tag),16))
        C = Cipherlist[i]
        [betai0,betai1] = ShareCipherKey(PP,PK,i,TDSi,tag,C)
        td2.append([betai0,betai1])
        tagJ = tagJianlist[i]
        tagJ = Element(pairing, Zr, value=int(str(tagJ), 16))
        CJ = CipherJianlist[i]
        [betaJi0, betaJi1] = ShareCipherKey(PP, PK, i, TDSi, tagJ, CJ)
        tdJ2.append([betaJi0, betaJi1])
    print("td2 generation end")
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("ShareCipherKey Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    print("ShareCipherKey Time:", timeleapMain, "s")


    # test
    # print("M0:",Mlist[0])
    # print("Cipher0:",Cipherlist[0])
    # message=decrypt(PP, SK , taglist[0],Cipherlist[0] )
    # print("dec message:",message)
    # res1=TTest_tt(PP,PK,taglist[0],Cipherlist[0],td1,PK,taglist[0],Cipherlist[0],td1,k)
    # res0=TTest_tt(PP,PK,taglist[1],Cipherlist[1],td1,PK,taglist[0],Cipherlist[0],td1,k)
    # print("ressame1,resdif0,:",res1,res0)
    # res2=TTest_cc(PP,PK,taglist[0],Cipherlist[0],td2,PK,taglist[0],Cipherlist[0],td2,k)
    # res3=TTest_cc(PP,PK,taglist[1],Cipherlist[1],td2,PK,taglist[0],Cipherlist[0],td2,k)
    # print("ressame2,resdif:", res2,res3)
    # tdetal=Element(pairing, GT, value=pairing.apply(g,message))
    # print("tdetal",tdetal)

    #test_tt
    MainTimeStart = datetime.now()
    # print("c0,t0", Cipherlist[0],taglist[0])
    # T=Delta_t(PP,PK,taglist[0],Cipherlist[0],k,td1)
    # print("T",T)
    WEWD=Test_tt(PP,PK,taglist,Cipherlist,td1,PK,tagJianlist,CipherJianlist,tdJ1,k)
    # print("WEWD:",WEWD)
    print("Test End")
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Test Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    print("Test_tt Time:", timeleapMain, "s")
    
    #test_cc
    MainTimeStart = datetime.now()
    # print("c0,t0", Cipherlist[0],taglist[0])
    # T=Delta_t(PP,PK,taglist[0],Cipherlist[0],k,td1)
    # print("T",T)
    WEWD = Test_cc(PP, PK, taglist, Cipherlist, td2, PK, tagJianlist, CipherJianlist, tdJ2, k)
    
    # print("WEWD:", WEWD)
    print("Test End")
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Test Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    print("Test_cc Time:", timeleapMain, "s")
    
    #test_tc
    MainTimeStart = datetime.now()
    # print("c0,t0", Cipherlist[0],taglist[0])
    # T=Delta_t(PP,PK,taglist[0],Cipherlist[0],k,td1)
    # print("T",T)
    WEWD = Test_tc(PP, PK, taglist, Cipherlist, td1, PK, tagJianlist, CipherJianlist, tdJ2, k)
    
    # print("WEWD:", WEWD)
    print("Test End")
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Test Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    print("Test_tc Time:", timeleapMain, "s")
    



if __name__ == '__main__':
    MainTimeStart = datetime.now()
    main()
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    # logTime.info("Main Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
