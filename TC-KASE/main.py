from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from KAE import KAE

from typing import DefaultDict
# from pypbc import *
from functools import partial
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
import sys

import nltk
from nltk.tokenize import *
from nltk.corpus import stopwords
from string import punctuation
import string
from datetime import datetime, timedelta

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

ParameterPathFromTools = "Parameter/"
ServerPathFromTools = "Server/"
ClientPathFromTools = "Client/"
MailEncPathFromTools = "MailEnc/"
MailDecPathFromTools = "MailDec/"

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

Hash = hashlib.sha256
WSet = {}
Inds = {}
IndsCopy = {}

# expDir = "../../Crypto/maildir/corman-s"
expDir="../../Crypto/maildir/corman-s/osha"
firstQueryKeyword='stephen.allen@enron.com'
secondQueryKeyword="russell.tucker@enron.com"
expmail=[firstQueryKeyword,secondQueryKeyword]
# expmail=[firstQueryKeyword,"russell.tucker@enron.com",'marc.phillips@enron.com','maryann.meza@enron.com','frank.smith@enron.com','Frank Smith','Russell Tucker','shelley.corman@enron.com','marc.phillips@enron.com','Plan']
# expmail = ['randy.lebeau@enron.com', "jerry.graves@enron.com", 'Outage', 'Coordination', 'Commercial', 'Review','Meeting', 'Corman-S', 'Fri, 8 Mar 2002 08:26:38 -0800 (PST)', 'shelley.corman@enron.com']

def Get(delta, w, WSet):
    """[The number of keyword w in DB]

    Args:
        delta ([type]): [description]
        w ([type]): [description]

    Returns:
        [type]: [The number of keyword w]
    """
    c = 0
    if w in WSet.keys():
        c = WSet[w]
    else:
        WSet[w] = 0
    return c

def Update(delta, w, c, WSet):
    """[Update DB[w] for its number]

    Args:
        delta ([type]): [description]
        w ([type]): [Keyword]
        c ([type]): [description]

    Returns:
        [type]: [Success or not]
    """
    state = 0
    if w in WSet.keys():
        WSet[w] = c
        state = 1
    return state

def PRF_F(key, msg):
    """[PRF_F]

    Args:
        key ([type]): [description]
        msg ([type]): [description]

    Returns:
        [type]: [Random number]
    """
    random.seed(str(key) + str(msg))
    final = random.random() * 1000000000000000000
    return final

def PRF_Fp(pp, key, msg):
    """[PRF_Fp]

    Args:
        params ([type]): [description]
        key ([str]): [description]
        msg ([str]): [description]

    Returns:
        [type]: [Random hash value in group Zr]
    """
    group = pp["group"]
    hash_value = group.hash(str(key) + str(msg), ZR)
    #Element.from_hash(pairing, Zr, Hash2((key + msg)).hexdigest())
    # hash_value = Element.from_hash(pairing, Zr, Hash2(("1".encode())).hexdigest())
    return hash_value

def Setup(group,lamb,n,L):
    logger.info("==================GlobalSetup Start==================")
    alpha = group.random(ZR)
    VLs=[group.random(G1) for j in range(L+1)]
    g=group.random(G1)
    g2ns=[g**(alpha**group.init(ZR,j)) for j in range(2*n+1)]
    g2ns[n+1]=""

    kae = KAE(group)
    upp = kae.Setup(lamb, n)

    pp={"upp":upp,"g":g,"g2ns":g2ns,"VLs":VLs,"kae":kae,"group":group,"n":n,"L":L}
    logTime.info("PP.dat: %s B", sys.getsizeof(str(pp)))
    logger.info("==================GlobalSetup End==================")
    return pp

def KeyGen(lamb,pp):
    logger.info("==================KeyGen Start==================")
    group=pp["group"]

    gamma=group.random(ZR)
    upk,usk=pp["kae"].KeyGen(lamb,pp["upp"])

    ggma=pp["g"]**gamma
    g1gma = pp["g2ns"][1] ** gamma

    Kx = str(Hash(('1' + str(group.random(ZR))).encode()))
    Kz = str(Hash(('2' + str(group.random(ZR))).encode()))
    Kt = str(Hash(('3' + str(group.random(ZR))).encode()))
    Kl = str(Hash(('4' + str(group.random(ZR))).encode()))
    Ku = str(Hash(('5' + str(group.random(ZR))).encode()))


    pk={"upk":upk,"ggma":ggma,"g1gma":g1gma}
    sk = {"usk": usk, "gamma": gamma, "Kx": Kx, "Kz": Kz, "Kt": Kt, "Kl": Kl,"Ku":Ku}

    logTime.info("sk.dat: %s B", sys.getsizeof(str(sk)))
    logTime.info("pk.dat: %s B", sys.getsizeof(str(pk)))

    logger.info("==================KeyGen End==================")
    return pk,sk

def Extract(pp,sk,S,T):
    group=pp["group"]
    n = pp["n"]
    L=pp["L"]
    g=pp["g"]

    Kx = sk["Kx"]
    Kl = sk["Kl"]
    Kt = sk["Kt"]
    Kz = sk["Kz"]
    Ku = sk["Ku"]
    kae=pp["kae"]

    s = group.random(ZR)
    pi = g/g
    for j in S:
        pi = pi * pp["g2ns"][n + 1 - j]
    KS = g**(-s) * (pi ** sk["gamma"])
    KT=[]
    for j in range(len(T)):
        vtau=group.random(ZR)
        pi = g/g
        for k in range(len(T[j])):
            tauk=group.hash(T[j][k],ZR)
            pi=pi*pp["VLs"][k+1]**tauk
        Ktau=g**s * (pp["VLs"][0]*pi)**vtau
        KtauHat=g**vtau
        KtauBar=[]
        for k in range(len(T[j]),L+1):
            KtauBar.append(pp["VLs"][k]**vtau)

        Kta={"Ktau":Ktau,"KtauHat":KtauHat,"KtauBar":KtauBar,"time":T[j]}
        KT.append(Kta)

    uKs=kae.Extract(pp["upp"],sk["usk"],S)

    Kagg={"KS":KS,"KT":KT,"Kx": Kx, "Kz": Kz, "Kt": Kt, "Kl": Kl,"Ku":Ku,"uKs":uKs}
    logTime.info("Kagg.dat: %s B", sys.getsizeof(str(Kagg)))
    return Kagg

def EDBSetup(pp,pk,sk,documentClass,D,EDB,XSet):
    # logger.info("==================EDBSetup Start==================")

    group = pp["group"]
    n = pp["n"]
    L = pp["L"]
    g = pp["g"]
    kae = pp["kae"]

    Kx=sk["Kx"]
    Kl=sk["Kl"]
    Kt=sk["Kt"]
    Kz=sk["Kz"]
    Ku = sk["Ku"]

    [filePath, WindSet] = D
    ind = generate_random_str(32)
    try:
        fileOrigin = open(filePath, "r")
        fileData = fileOrigin.read()
    except Exception as e:
        logger.info(e)
        return [EDB, XSet]

    Kind = generate_random_str(32)
    iv = generate_random_str(16)
    fileEncrypted = encrypt(fileData, Kind, iv)

    path = ServerPathFromTools + MailEncPathFromTools
    createFile(path + ind, fileEncrypted, "wb")

    for keyword, content in WindSet.items():
        c = Get(0, content, WSet)
        Update(0, content, c + 1, WSet)

    indString = str(ind).encode()
    xind = PRF_Fp(pp, Kx, indString)

    for keyword, content in WindSet.items():
        c = Get(0, content, WSet)
        cString = str(c).encode()
        wString = str(content).encode()
        l = PRF_F(Kl, cString + wString)
        z = PRF_Fp(pp, Kz, cString + wString)
        t = PRF_Fp(pp, Kt, cString + wString)
        u = PRF_Fp(pp, Ku, cString + wString)

        # temp = group.random(ZR)
        m = group.random(GT)
        Inds[Hash(str(m).encode()).hexdigest()] = [ind, Kind, iv]
        IndsCopy[str(m)] = [str(ind), str(Kind), str(iv)]

        e0=kae.Enc(pp['upp'],pk["upk"],documentClass,m)
        e1=xind*z
        # e2=pk["ggma"]**(xind*t)
        e2 = pp["g"] ** (xind * t)
        e3=(pk["ggma"]*pp["g2ns"][documentClass])**(xind*t)
        e4=pp["g2ns"][1]**(xind*u)
        # e4=pk["g1gma"]**(xind*u)

        hashValue = group.hash(wString,ZR)
        # xtag=pair(pk["g1gma"],pp["g2ns"][n])**(hashValue*xind)
        xtag = pair(pp["g2ns"][1], pp["g2ns"][n]) ** (hashValue * xind)

        EDB[l] = {"i": documentClass, "e0": e0, "e1": e1, "e2": e2, "e3": e3, "e4": e4}
        XSet[str(xtag)] = 1

    return [EDB, XSet]

def AllSetup(pp,pk,sk,documentClass):
    DList = GetDList(expDir)
    WSet = {}
    EDB = {}
    XSet = {}

    logger.info("==================EDBSetup Start==================")
    for D in DList.items():
        [EDB, XSet] = EDBSetup(pp,pk,sk,documentClass,D,EDB,XSet)
    logger.info("==================EDBSetup End==================")

    createFile(ServerPathFromTools + ParameterPathFromTools + "EDB.dat", str(EDB), "w")
    createFile(ServerPathFromTools + ParameterPathFromTools + "XSet.dat", str(XSet), "w")
    createFile(ServerPathFromTools + ParameterPathFromTools + "WSet.dat", str(WSet), "w")
    file_stats = os.stat(ServerPathFromTools + ParameterPathFromTools + "EDB.dat")
    logTime.info("EDB.dat size = %s B", file_stats.st_size)
    file_stats = os.stat(ServerPathFromTools + ParameterPathFromTools + "XSet.dat")
    logTime.info("XSet.dat size = %s B", file_stats.st_size)

    return EDB, XSet

def TrapGen(pp,S,Kagg,Q):
    # logger.info("==================TrapGen Start==================")
    group = pp["group"]
    n = pp["n"]
    L = pp["L"]
    g = pp["g"]

    Kx = Kagg["Kx"]
    Kl = Kagg["Kl"]
    Kt = Kagg["Kt"]
    Kz = Kagg["Kz"]
    Ku = Kagg["Ku"]

    i = 1
    length = Get(0, Q[1], WSet)

    logger.info("Trap length is %s", length)
    q = len(Q)
    logger.info("Send to Front Server for %s times", length)
    logger.info("Query Keywords = %s", Q)
    logger.info("Query keyword number = %d", q - 1)

    booleanVector = {}
    i = 1
    while (i <= q - 1):
        booleanVector[i] = 1
        i += 1

    l = {}
    Trap = {}

    i = 1
    while (i <= length):
        Trap[i] = {}
        # TrapCopy[i]={}
        i = i + 1

    i = 1
    r = group.random(ZR)
    h = group.random(ZR)
    while (i <= length):
        w1 = str(Q[1]).encode()
        c = str(i).encode()
        l[i] = PRF_F(Kl, c + w1)
        z = PRF_Fp(pp, Kz, c + w1)
        t = PRF_Fp(pp, Kt, c + w1)
        u = PRF_Fp(pp, Ku, c + w1)

        j = 1
        # 因为有个Q[0]是空,所以<
        while (j < q):
            wj = str(Q[j]).encode()
            hashValue = group.hash(wj,ZR)#Element.from_hash(pairing, Zr, Hash1(wj).hexdigest())
            td1=(Kagg["KS"]*Kagg["KT"][0]["Ktau"])**(r*hashValue/z)
            td2=pp["g2ns"][n]**((group.init(ZR,1)-r*h)*hashValue/u)
            td3=r*h*hashValue/t
            td4=Kagg["KT"][0]["KtauHat"]**(r*h*hashValue/z)
            td5 = g**h

            trap={"atd1":td1,"atd2":td2,"atd3":td3,"atd4":td4,"atd5":td5}
            Trap[i][j] = trap
            j = j + 1

        i = i + 1

    token = {"S":S,"l":l,"Trap":Trap,"length":length,"q":q}#[l, Trap, tds]

    tokenCopy = [str(token), booleanVector]
    createFile(ClientPathFromTools + ParameterPathFromTools + "token.dat", str(tokenCopy), "w")

    file_stats = os.stat(ClientPathFromTools + ParameterPathFromTools + "token.dat")
    logTime.info("token.dat size = %s B", file_stats.st_size)
    return token

def Adjust(pp,S,token):
    group = pp["group"]
    n = pp["n"]
    L = pp["L"]
    g = pp["g"]

    piS=g/g
    for j in S:
        piS=piS*pp["g2ns"][n+1-j]

    Trap = {}
    i = 1
    while (i <= len(S)):
        Trap[S[i-1]] = {}
        j=1
        while (j <= token["length"]):
            Trap[i][j]={}
            # k=1
            # while (k <= token["q"]):
            #     Trap[i][j][k] = {}
            #     k=k+1
            j=j+1
        i = i + 1

    for i in S:
        piSni = g/g
        for v in S:
            if(v!=i): piSni = piSni * pp["g2ns"][n + 1 - v+i]

        c=1
        while(c<=len(token["Trap"])):
            j=1
            while(j<=len(token["Trap"][c])):
                td1=piS**token["Trap"][c][j]["atd3"]
                td2=piSni**token["Trap"][c][j]["atd3"]
                trap={"td1":td1,"td2":td2,"atd1":token["Trap"][c][j]["atd1"],"atd2":token["Trap"][c][j]["atd2"],"atd4":token["Trap"][c][j]["atd4"],"atd5":token["Trap"][c][j]["atd5"]}
                Trap[i][c][j]=trap
                j+=1
            c+=1
    tokenadj={"S":S,"l":token["l"],"Trap":Trap}
    return tokenadj

def Search(pp, S,Time, token, EDB, XSet):
    # logger.info("==================TrapGen Start==================")
    group = pp["group"]
    g=pp["g"]

    vector = {}
    booleanVector = {}
    l=token["l"]
    Trap=token["Trap"]

    pi = g/g
    for k in range(len(Time)):
        tauk = group.hash(Time[k], ZR)
        pi = pi * pp["VLs"][k + 1] ** tauk
    Ktaup = (pp["VLs"][0] * pi)

    documentClass=1
    Res = list()
    for documentClass in S:
    # while(documentClass<=len(S)):
        i = 1
        while (i <= len(l)):
            if (l[i] in EDB.keys()):
                vector = {}
                # logger.info("DocumentClass:%s==%s, Judge Trap[%s] is exist for j in XSet", EDB[l[i]]['i'],documentClass,i)

                if(EDB[l[i]]["i"]!=documentClass):
                    i+=1
                    continue

                e0 = EDB[l[i]]['e0']
                e1 = EDB[l[i]]['e1']
                e2 = EDB[l[i]]['e2']
                e3 = EDB[l[i]]['e3']
                e4 = EDB[l[i]]['e4']

                j = 1
                while (j <= len(Trap[documentClass][i])):
                    trap = Trap[documentClass][i][j]

                    p1=pair(trap["td1"],e3)
                    p2=pair(trap["atd2"],e4)
                    p3 = pair(trap["atd4"], Ktaup**e1)
                    p4=pair(trap["td2"],e2)
                    p5= pair(trap["atd1"], trap["atd5"]**e1)

                    xtagd=p1*p2*p3/(p4*p5)

                    flag = 0
                    if (str(xtagd) in XSet.keys()):
                        flag = 1

                    vector[j] = flag
                    booleanVector[j] = 1
                    logger.info("i = %s, j = %s, vector = %s", i, j, vector)
                    j = j + 1

                if (vector == booleanVector):
                    Res.append(e0)
            i += 1
        # documentClass+=1

    createFile(ClientPathFromTools + ParameterPathFromTools + "R.dat", str(Res), "w")
    file_stats = os.stat(ClientPathFromTools + ParameterPathFromTools + "R.dat")
    logTime.info("R.dat size = %s B", file_stats.st_size)
    return Res

def Retrieve(pp,Kagg,S,Res):
    kae=pp["kae"]

    res=[]
    for e0 in Res:
        m = kae.Dec(pp["upp"],Kagg["uKs"], S,e0["i"], e0)
        res.append(m)

    srcpath = ServerPathFromTools + MailEncPathFromTools
    dstpath = ClientPathFromTools + MailDecPathFromTools

    for m in res:
        has=Hash(str(m).encode()).hexdigest()
        ind = Inds[has][0]
        Kind = Inds[has][1]
        iv = Inds[has][2]
        file = open(srcpath + ind, "r")
        dataEnc = file.read()
        dataDec = decrypt(dataEnc, Kind, iv)
        createFile(dstpath + ind, dataDec, "w")

    return res

def main(lamb,n,L,S,T,documentClass):
    groupObj = PairingGroup("SS512")

    MainTimeStart = datetime.now()
    pp=Setup(groupObj,lamb,n,L)
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Setup Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))


    MainTimeStart = datetime.now()
    pk,sk=KeyGen(lamb,pp)
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("KGen Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))

    MainTimeStart = datetime.now()
    Kagg=Extract(pp,sk,S,T)
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("KeyAgg Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))

    MainTimeStart = datetime.now()
    EDB,XSet=AllSetup(pp, pk, sk, documentClass)
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("EDBSetup Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))

    Q = ['']  # russell.tucker@enron.com
    mail = expmail
    count=1
    for item in range(len(mail)):
        logTime.info("=================Query for %s time=================", count)
        count+=1
        Q.append(mail[item])

        MainTimeStart = datetime.now()
        token=TrapGen(pp,S,Kagg,Q)
        MainTimeEnd = datetime.now()
        timeleapMain = MainTimeEnd - MainTimeStart
        logTime.info("TrapGen Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))

        MainTimeStart = datetime.now()
        tokenadj=Adjust(pp,S,token)
        MainTimeEnd = datetime.now()
        timeleapMain = MainTimeEnd - MainTimeStart
        logTime.info("Adjust Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))

        MainTimeStart = datetime.now()
        res=Search(pp,S,T[0],tokenadj,EDB,XSet)
        MainTimeEnd = datetime.now()
        timeleapMain = MainTimeEnd - MainTimeStart
        logTime.info("Search Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))

        MainTimeStart = datetime.now()
        Retrieve(pp,Kagg,S,res)
        MainTimeEnd = datetime.now()
        timeleapMain = MainTimeEnd - MainTimeStart
        logTime.info("Decrypt Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))


def vice():
    groupObj = PairingGroup("SS512")
    group=groupObj
    lamb = 256
    n = 10
    L = 4
    S = [i for i in range(1, 2 + 1)]
    T = [["2016", "10", "29"], ["2016", "11"], ["2017"]]
    # T={"tau1":["2016","10","29"],"tau2":["2016","11"],"tau3":["2017"]}
    # T= [tau for tau in range(5)]#0 for year, 1 for month, 2 for day
    documentClass = 1

    pp = Setup(groupObj, lamb, n, L)
    pk, sk = KeyGen(lamb, pp)
    Kagg = Extract(pp, sk, S, T)

    g=pp["g"]

    xind = PRF_Fp(pp, sk["Kx"], "indString")
    z = PRF_Fp(pp, sk["Kz"], str(1) + "word")
    t = PRF_Fp(pp, sk["Kt"], str(1) + "word")
    u = PRF_Fp(pp, sk["Ku"], str(1) + "word")

    e1 = xind * z
    e2 = pp["g"] ** (xind * t)
    e3 = (pk["ggma"] * pp["g2ns"][documentClass]) ** (xind * t)
    e4 = pp["g2ns"][1] ** (xind * u)

    hashValue = group.hash("word", ZR)
    # xtag=pair(pk["g1gma"],pp["g2ns"][n])**(hashValue*xind)
    xtag = pair(pp["g2ns"][1], pp["g2ns"][n]) ** (hashValue * xind)

    r=group.random(ZR)
    td1 = Kagg["KS"] ** (r * hashValue / z)
    td2 = pp["g2ns"][n] ** ((group.init(ZR, 1) - r) * hashValue / u)
    td3 = r * hashValue / t
    td4 = Kagg["KT"][0]["Ktau"] ** (r * hashValue / z)
    td5 = Kagg["KT"][0]["KtauHat"] ** (r * hashValue / z)

    trap = {"td1": td1, "td2": td2, "td3": td3, "td4": td4, "td5": td5}

    piS = g / g
    for j in S:
        piS = piS * pp["g2ns"][n + 1 - j]

    piSni = g / g
    for v in S:
        if (v == documentClass): continue
        piSni = piSni * pp["g2ns"][n + 1 - v + documentClass]

    td1 = piS ** trap["td3"]
    td2 = piSni ** trap["td3"]
    trapdd = {"td1": td1, "td2": td2, "atd1": trap["td1"], "atd2": trap["td2"],
            "atd4": trap["td4"], "atd5": trap["td5"]}
    # Trap[i][c][j] = trapdd

    pi = g / g
    for k in range(len(T[0])):
        tauk = group.hash(T[0][k], ZR)
        pi = pi * pp["VLs"][k + 1] ** tauk
    Ktaup = (pp["VLs"][0] * pi)
    p1 = pair(trapdd["td1"], e3)
    p2 = pair(trapdd["atd2"], e4)
    p3 = pair(trapdd["atd5"], Ktaup ** e1)
    p4 = pair(trapdd["td2"], e2)
    p5 = pair(trapdd["atd1"], g ** e1)
    p6 = pair(trapdd["atd4"], g ** e1)

    xtagd = p1 * p2 * p3 / (p4 * p5 * p6)
    print(xtagd)






def GetD(filepath):
    logger.info("Reading %s", filepath)

    D = {}

    f = open(filepath, "rb+")
    byt = f.read()
    data = byt.decode("ISO-8859-1")
    # data=f.read()
    email = Parser().parsestr(data)

    D['Message-ID'] = email['Message-ID']
    D['Date'] = email['Date']
    D['From'] = email['From']
    D['X-FileName'] = email['X-FileName']
    D['X-Origin'] = email['X-Origin']
    D['X-From'] = email['X-From']
    D['X-Folder'] = email['X-Folder']
    toMails = email['To']
    toMailsList = re.split('[,\s]', str(toMails))
    # toMailsList=str(toMails).split(",")
    for mail in toMailsList:
        # keywordCount+=1
        D[mail] = mail

    # 针对文件subject实现模糊搜索
    subject = email['subject']
    words = word_tokenize(subject)
    for word in words:
        # keywordCount+=1
        D[word] = word

    nlp = spacy.load("en_core_web_sm")
    tr = pytextrank.TextRank()
    nlp.add_pipe(tr.PipelineComponent, name="textrank", last=True)
    doc = nlp(email.get_payload())

    # i=1
    keywordCount = len(D)
    for p in doc._.phrases:
        # print(keywordCount)r
        if (keywordCount <= 40):
            D[p.text] = p.text
        else:
            break
        keywordCount += 1

    return D


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

        f = open(filepath, "rb+")
        byt = f.read()
        data = byt.decode("ISO-8859-1")
        # data=f.read()
        email = Parser().parsestr(data)

        D['Message-ID'] = email['Message-ID']
        D['Date'] = email['Date']
        D['From'] = email['From']
        D['X-FileName'] = email['X-FileName']
        D['X-Origin'] = email['X-Origin']
        D['X-From'] = email['X-From']
        D['X-Folder'] = email['X-Folder']
        toMails = email['To']
        toMailsList = re.split('[,\s]', str(toMails))
        # toMailsList=str(toMails).split(",")
        for mail in toMailsList:
            # keywordCount+=1
            D[mail] = mail

        # 针对文件subject实现模糊搜索
        subject = email['subject']
        words = word_tokenize(subject)
        for word in words:
            # keywordCount+=1
            D[word] = word

        nlp = spacy.load("en_core_web_sm")
        tr = pytextrank.TextRank()
        nlp.add_pipe(tr.PipelineComponent, name="textrank", last=True)
        doc = nlp(email.get_payload())

        # i=1
        keywordCount = len(D)
        for p in doc._.phrases:
            # print(keywordCount)
            if (keywordCount <= 40):
                D[p.text] = p.text
            else:
                break
            keywordCount += 1

        # for p in doc._.phrases:
        #     print(p.rank,p.count,p.chunks,p.text)

        DList[filepath] = D
        # for key,value in D.items():
        #     print(value)
        # print(len(D))

    logger.info("==================GetDList End==================")
    return DList

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
    key = key.encode('utf-8')
    mode = AES.MODE_CBC
    # iv = b'qqqqqqqqqqqqqqqq'
    iv = iv.encode('utf-8')
    text = add_to_16(text)
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(text)
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
    return b2a_hex(cipher_text)

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
            logging.info("Creating %s", temp)
            f = open(temp, type)
            f.write(data)
        i += 1

    return 0

def loadFile(filePath):
    logger.info("Reading %s file", filePath)
    fileCopy = open(filePath, "r")
    Copy = eval(fileCopy.read())
    return Copy

if __name__ == '__main__':
    lamb = 256
    n = 10
    L = 4
    S = [i for i in range(1, 2 + 1)]
    # T = [["2016", "10", "29"], ["2016", "11"], ["2017"]]
    T = [["2016", "10", "29"]]
    documentClass = 1

    for n in range(10,11,10):
        # for i in range(1,10,1):
        logTime.info("===================Starting n=%s, S.length=%s", n,len(S))
        S=[j for j in range(1, n + 1)]
        WSet={}
        MainTimeStart = datetime.now()
        main(lamb,n,L,S,T,documentClass)
        # vice()
        MainTimeEnd = datetime.now()
        timeleapMain = MainTimeEnd - MainTimeStart
        logTime.info("Main Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
        logTime.info("===================Ending L=%s, S.length=%s", L, len(S))

    # vice()
