from pypbc import *
from Viete import *
from abme import *
import hashlib
import random
import logging
from pathlib import Path
from email.parser import Parser
#import paramiko
import os
import spacy
import pytextrank

from nltk.tokenize import *
from datetime import datetime

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

Hash1 = hashlib.sha256
Hash2 = hashlib.sha256
Hash3 = hashlib.sha256

logger=logging.getLogger("Caedios")
logger.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
file_handler = logging.FileHandler("../../log")
file_handler.setLevel(level=logging.INFO)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

logTime=logging.getLogger("logTime")
logTime.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
fileTime_handler = logging.FileHandler("../../logTime")
fileTime_handler.setLevel(level=logging.INFO)
fileTime_handler.setFormatter(formatter)
logTime.addHandler(fileTime_handler)

logCount=logging.getLogger("logCount")
logCount.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
fileTime_handler = logging.FileHandler("../../logCount")
fileTime_handler.setLevel(level=logging.INFO)
fileTime_handler.setFormatter(formatter)
logCount.addHandler(fileTime_handler)

ParameterPathFromTools="Parameter/"
ServerPathFromTools="Server/"
ClientPathFromTools="Client/"
MailEncPathFromTools="MailEnc/"
MailDecPathFromTools="MailDec/"

WSet={}
Inds={}
IndsCopy={}

expDir="../Experiment/maildir/corman-s"
# expDir="../CSExperiment/maildir/corman-s/osha"
# firstQueryKeyword='stephen.allen@enron.com'
# secondQueryKeyword="russell.tucker@enron.com"
# expmail=[firstQueryKeyword,secondQueryKeyword]
#expmail=[firstQueryKeyword,"russell.tucker@enron.com",'marc.phillips@enron.com','maryann.meza@enron.com','frank.smith@enron.com','Frank Smith','Russell Tucker','shelley.corman@enron.com','marc.phillips@enron.com','Plan']
expmail=['randy.lebeau@enron.com',"jerry.graves@enron.com",'Outage','Coordination','Commercial','Review','Meeting','Corman-S','Fri, 8 Mar 2002 08:26:38 -0800 (PST)','shelley.corman@enron.com']

stored_params ="""type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1"""


global N1
global n
global superlength

def Get(delta,w,WSet):
    """[The number of keyword w in DB]

    Args:
        delta ([type]): [description]
        w ([type]): [description]

    Returns:
        [type]: [The number of keyword w]
    """
    c=0
    if w in WSet.keys():
        c=WSet[w]
    else: WSet[w]=0
    return c

def Update(delta,w,c,WSet):
    """[Update DB[w] for its number]

    Args:
        delta ([type]): [description]
        w ([type]): [Keyword]
        c ([type]): [description]

    Returns:
        [type]: [Success or not]
    """
    state=0
    if w in WSet.keys():
        WSet[w]=c
        state=1
    return state

def PRF_F(key,msg):
    """[PRF_F]

    Args:
        key ([type]): [description]
        msg ([type]): [description]

    Returns:
        [type]: [Random number]
    """
    random.seed(key+msg)
    final=random.random()*1000000000000000000
    return final

def PRF_Fp(params,key,msg):
    """[PRF_Fp]

    Args:
        params ([type]): [description]
        key ([str]): [description]
        msg ([str]): [description]

    Returns:
        [type]: [Random hash value in group Zr]
    """
    pairing = Pairing(params)
    hash_value = Element.from_hash(pairing, Zr, Hash2((key+msg)).hexdigest())
    #hash_value = Element.from_hash(pairing, Zr, Hash2(("1".encode())).hexdigest())
    return hash_value

def GlobalSetup(qbits=512, rbits=160):
    """[KGC generate public parameter]

    Args:
        qbits (int, optional): [description]. Defaults to 512.
        rbits (int, optional): [description]. Defaults to 160.

    Returns:
        [type]: [description]
    """
    logger.info("==================GlobalSetup Start==================")
    params = Parameters(param_string=stored_params)
    #params = Parameters(qbits=qbits, rbits=rbits)   
    pairing = Pairing(params)  

    Kx="Kx".encode()
    Kz="Kz".encode()
    Kl="Kl".encode()

    g = Element.random(pairing, G1) 
    Delta=Element.random(pairing, Zr)
    g1=Element(pairing,G1,value=g**Delta)
    r= Element.random(pairing,Zr)
    g2=Element(pairing,G1,value=g**r)

    s1=Element.random(pairing, Zr)
    s2=Element.random(pairing, Zr)
    gamma1=Element.random(pairing, Zr)
    gamma2=Element.random(pairing, Zr)

    V1=Element(pairing,G1,value=g**gamma1)
    V2=Element(pairing,G1,value=g**gamma2)

    temp1=Element.random(pairing, Zr)

    u1=[temp1 for i in range(n)]
    #u1=[Element.random(pairing, Zr) for i in range(n)]
    temp1=Element(pairing,G1,value=g**u1[0])
    U1=[temp1 for i in range(n)]

    temp2=Element(pairing,Zr,value=(Delta+gamma2*u1[0])/gamma1)
    u2=[temp2 for i in range(n)]
    Temp2=Element(pairing,G1,value=g**u2[0])
    U2=[Temp2 for i in range(n)]

    gs1s2=Element(pairing,G1,value=g**(s1+s2))
    Y=pairing.apply(gs1s2,g2)

    tempu1s1=Element(pairing,G1,value=U1[0]**s1)
    tempu2s1=Element(pairing,G1,value=U2[0]**s1)
    U1s1=[tempu1s1 for i in range(n)]
    U2s1=[tempu2s1 for i in range(n)]

    tempu1s2=Element(pairing,G1,value=U1[0]**s2)
    tempu2s2=Element(pairing,G1,value=U2[0]**s2) 
    U1s2=[tempu1s2 for i in range(n)]
    U2s2=[tempu2s2 for i in range(n)]

    abme=ABME(stored_params)
    ppk,psk=abme.GlobalSetup(qbits=512, rbits=160)


    mpk={"g":g,"g1":g1,"V1":V1,"V2":V2,"Y":Y,"U1s1":U1s1,"U2s1":U2s1,"U1s2":U1s2,"U2s2":U2s2,"abme":abme,"ppk":ppk}
    msk={"s1":s1,"s2":s2,"g2":g2,"gamma1":gamma1,"gamma2":gamma2,"u1":u1,"u2":u2,"psk":psk,"Kx":Kx,"Kz":Kz,"Kl":Kl}


    mpkdd={"g":g,"g1":g1,"V1":V1,"V2":V2,"Y":Y,"U1s1":tempu1s1,"U2s1":tempu2s1,"U1s2":tempu1s2,"U2s2":tempu2s2,"abme":abme,"ppk":ppk}
    mskdd={"s1":s1,"s2":s2,"g2":g2,"gamma1":gamma1,"gamma2":gamma2,"u1":temp1,"u2":temp2,"psk":psk,"Kx":Kx,"Kz":Kz,"Kl":Kl}
    createFile(ServerPathFromTools+ParameterPathFromTools+"PP.dat",str(mpkdd),"w")
    createFile(ServerPathFromTools+ParameterPathFromTools+"MSK.dat",str(mskdd),"w")

    file_stats = os.stat(ServerPathFromTools+ParameterPathFromTools+"PP.dat")
    logTime.info("PP.dat size = %s B",file_stats.st_size)
    file_stats = os.stat(ServerPathFromTools+ParameterPathFromTools+"MSK.dat")
    logTime.info("MSK.dat size = %s B",file_stats.st_size)

    logger.info("==================GlobalSetup End==================")

    return mpk,msk

def SKeyGen(mpk,msk,attS,S):
    """_summary_

    Args:
        mpk (_type_): _description_
        msk (_type_): _description_
        attS (_type_): 假定S=[att1,...,attn2]
    """
    V1=mpk["V1"]
    V2=mpk["V2"]
    g=mpk["g"]
    g1=mpk["g1"]
    g2=msk["g2"]
    s1=msk["s1"]
    s2=msk["s2"]

    params = Parameters(param_string=stored_params)
    #params = Parameters(qbits=qbits, rbits=rbits)   
    pairing = Pairing(params)  

    zero=Element(pairing,Zr,value=0)
    one=Element(pairing,Zr,value=1)

    xV=[]
    for k in range(N1+1):
        k=Element(pairing,Zr,value=k)
        vk=zero
        for i in attS:
            vk=Element(pairing,Zr,value=vk+i**k)
        vk=Element(pairing,Zr,value=-vk)
        xV.append(vk)
    xV.append(one)

    # global testXV
    # testXV=xV

    f1=Element.random(pairing,Zr)
    sigma=zero
    ek1=[]
    ek2=[]
    for i in range(n):
        ri=Element.random(pairing,Zr)
        u2i=msk["u2"][i]
        u1i=msk["u1"][i]
        ek1i=Element(pairing,G1,value=V2**(-ri)*g**(f1*u2i*xV[i]))
        ek2i=Element(pairing,G1,value=V1**(ri)*g**(-f1*u1i*xV[i]))
        sigma=Element(pairing,Zr,value=sigma+ri*s1)
        ek1.append(ek1i)
        ek2.append(ek2i)

    abme=mpk["abme"]
    ppk=mpk["ppk"]
    psk=msk["psk"]
    pekS=abme.EKGen(ppk, psk, S)

    ek3=Element(pairing,G1,value=g2**s2 * g1**(-sigma))
    ekS={"ek1":ek1,"ek2":ek2,"ek3":ek3,"pek":pekS,"Kx":msk["Kx"],"Kz":msk["Kz"],"Kl":msk["Kl"]}

    createFile(ServerPathFromTools+ParameterPathFromTools+"ek.dat",str(ekS),"w")
    file_stats = os.stat(ServerPathFromTools+ParameterPathFromTools+"ek.dat")
    logTime.info("ek.dat size = %s B",file_stats.st_size)

    return ekS

def RKeyGen(mpk,msk,attR,R):
    """_summary_

    Args:
        mpk (_type_): _description_
        msk (_type_): _description_
        attS (_type_): 假定S=[att1,...,attn2]
    """
    V1=mpk["V1"]
    V2=mpk["V2"]
    g=mpk["g"]
    g1=mpk["g1"]
    g2=msk["g2"]
    s1=msk["s1"]
    s2=msk["s2"]

    params = Parameters(param_string=stored_params)
    #params = Parameters(qbits=qbits, rbits=rbits)   
    pairing = Pairing(params)  

    zero=Element(pairing,Zr,value=0)
    one=Element(pairing,Zr,value=1)

    xV=[]
    for k in range(N1+1):
        k=Element(pairing,Zr,value=k)
        vk=zero
        for i in attR:
            vk=Element(pairing,Zr,value=vk+i**k)
        vk=Element(pairing,Zr,value=-vk)
        xV.append(vk)
    xV.append(one)

    # global testXV
    # testXV=xV
    
    f1=Element.random(pairing,Zr)
    sigma=zero
    dk1=[]
    dk2=[]
    for i in range(n):
        ri=Element.random(pairing,Zr)
        u2i=msk["u2"][i]
        u1i=msk["u1"][i]
        dk1i=Element(pairing,G1,value=V2**(-ri)*g**(f1*u2i*xV[i]))
        dk2i=Element(pairing,G1,value=V1**(ri)*g**(-f1*u1i*xV[i]))
        sigma=Element(pairing,Zr,value=sigma+ri*s2)
        dk1.append(dk1i)
        dk2.append(dk2i)

    abme=mpk["abme"]
    ppk=mpk["ppk"]
    psk=msk["psk"]
    Raccess=[[Element.from_hash(pairing,Zr,Hash1((str(i)+str(j)).encode()).hexdigest()) for j in range(len(R))] for i in range(len(R))]
    pdkR=abme.DKGen(ppk,psk,R,Raccess)

    dk3=Element(pairing,G1,value=g2**s1 * g1**(-sigma))
    dkR={"dk1":dk1,"dk2":dk2,"dk3":dk3,"pdk":pdkR,"Kx":msk["Kx"],"Kz":msk["Kz"],"Kl":msk["Kl"]}

    createFile(ServerPathFromTools+ParameterPathFromTools+"dkR.dat",str(dkR),"w")
    file_stats = os.stat(ServerPathFromTools+ParameterPathFromTools+"dkR.dat")
    logTime.info("dkR.dat size = %s B",file_stats.st_size)
    return dkR

def EDBSetup(mpk,D,ekS,v,EDB,XSet,S,R):
    params = Parameters(param_string=stored_params)
    #params = Parameters(qbits=qbits, rbits=rbits)   
    pairing = Pairing(params) 

    abme=mpk["abme"]
    ppk=mpk["ppk"]

    g=Element(pairing,G1,value=mpk["g"])
    g1=Element(pairing,G1,value=mpk["g1"])
    Kx=ekS["Kx"]
    Kl=ekS["Kl"]
    Kz=ekS["Kz"]
    U1s2=mpk["U1s2"]
    U2s2=mpk["U2s2"]
    V1=Element(pairing,G1,value=mpk["V1"])
    V2=Element(pairing,G1,value=mpk["V2"])
    ek1=ekS["ek1"]
    ek2=ekS["ek2"]
    ek3=Element(pairing,G1,value=ekS["ek3"])
    Y=Element(pairing,GT,value=mpk["Y"])

    [filePath,WindSet]=D
    ind=generate_random_str(32)
    try:
        fileOrigin=open(filePath,"r")
        fileData=fileOrigin.read()
    except Exception as e:
        logger.info(e)
        return [EDB,XSet]

    Kind=generate_random_str(32)
    iv=generate_random_str(16)
    fileEncrypted=encrypt(fileData,Kind,iv)

    path=ServerPathFromTools+MailEncPathFromTools
    createFile(path+ind,fileEncrypted,"wb")

    for keyword,content in WindSet.items():
        c=Get(0,content,WSet)
        Update(0,content,c+1,WSet)

    indString=str(ind).encode()
    xind=PRF_Fp(params,Kx,indString)

    for keyword,content in WindSet.items():
        c=Get(0,content,WSet)
        cString=str(c).encode()
        wString=str(content).encode()
        l=PRF_F(Kl,cString+wString)
        z=PRF_Fp(params,Kz,cString+wString)

        temp=Element.random(pairing,Zr)
        pair=pairing.apply(g,g)
        m=Element(pairing,GT,value=pair**temp)
        Inds[str(m)]=[ind,Kind,iv]
        IndsCopy[str(m)]=[str(ind),str(Kind),str(iv)]

        alpha=Element.random(pairing,Zr)
        #xindz=Element(pairing,Zr,value=xind*z)
        e0=abme.Enc(ppk,ekS["pek"],R,S,m)
        e1=[Element(pairing,G1,value=Element(pairing,G1,value=U1s2[i])**(xind*z)*V1**(Element(pairing,Zr,value=v[i])*alpha*xind*z)) for i in range(n)]
        e2=[Element(pairing,G1,value=Element(pairing,G1,value=U2s2[i])**(xind*z)*V2**(Element(pairing,Zr,value=v[i])*alpha*xind*z)) for i in range(n)]
        e3=Element(pairing,G1,value=g**(z*xind))
        e4=[Element(pairing,G1,value=Element(pairing,G1,value=ek1[i])**(xind*z)) for i in range(n)]
        e5=[Element(pairing,G1,value=Element(pairing,G1,value=ek2[i])**(xind*z)) for i in range(n)]
        e6=Element(pairing,G1,value=ek3**(z*xind))

        hashValue=Element.from_hash(pairing, Zr, Hash1(wString).hexdigest())
        xtag=Element(pairing,GT,value=Y**(hashValue*xind))

        EDB[l]={"e0":e0,"e1":e1,"e2":e2,"e3":e3,"e4":e4,"e5":e5,"e6":e6}
        XSet[str(xtag)]=1

    return [EDB,XSet]

def AllSetup(mpk,ekS,wildcardR,policyR,S,R):
    DList=GetDList(expDir)
    WSet={}
    EDB={}
    XSet={}
    
    params = Parameters(param_string=stored_params)
    #params = Parameters(qbits=qbits, rbits=rbits)   
    pairing = Pairing(params)  

    zero=Element(pairing,Zr,value=0)
    one=Element(pairing,Zr,value=1)

    J=wildcardR
    V=policyR

    coeff=vietaFormula(J)
    piV=zero
    for i in V:
        pi=one
        for j in J:
            pi=Element(pairing,Zr,value=pi*(i-j))
        piV=Element(pairing,Zr,value=piV+pi)
    v=coeff
    for i in range(len(coeff),N1+1):
        v.append(zero)
    v.append(piV)

    # global testV
    # testV=v

    logger.info("==================EDBSetup Start==================")
    for D in DList.items():
        [EDB,XSet]=EDBSetup(mpk,D,ekS,v,EDB,XSet,S,R)
        # print()
    logger.info("==================EDBSetup End==================")

    createFile(ServerPathFromTools+ParameterPathFromTools+"EDB.dat",str(EDB),"w")
    createFile(ServerPathFromTools+ParameterPathFromTools+"XSet.dat",str(XSet),"w")
    createFile(ServerPathFromTools+ParameterPathFromTools+"WSet.dat",str(WSet),"w")
    file_stats = os.stat(ServerPathFromTools+ParameterPathFromTools+"EDB.dat")
    logTime.info("EDB.dat size = %s B",file_stats.st_size)
    file_stats = os.stat(ServerPathFromTools+ParameterPathFromTools+"XSet.dat")
    logTime.info("XSet.dat size = %s B",file_stats.st_size)

    return EDB,XSet

def TrapGen(mpk,dkR,wildcardS,policyS,Q):
    params = Parameters(param_string=stored_params)
    #params = Parameters(qbits=qbits, rbits=rbits)   
    pairing = Pairing(params) 

    Kx=dkR["Kx"]
    Kl=dkR["Kl"]
    Kz=dkR["Kz"]

    g=Element(pairing,G1,value=mpk["g"])
    g1=Element(pairing,G1,value=mpk["g1"])
    dk1=dkR["dk1"]
    dk2=dkR["dk2"]
    dk3=Element(pairing,G1,value=dkR["dk3"])

    U1s1=mpk["U1s1"]
    U2s1=mpk["U2s1"]
    V1=Element(pairing,G1,value=mpk["V1"])
    V2=Element(pairing,G1,value=mpk["V2"])

    zero=Element(pairing,Zr,value=0)
    one=Element(pairing,Zr,value=1)

    J=wildcardS
    V=policyS

    coeff=vietaFormula(J)
    piV=zero
    for i in V:
        pi=one
        for j in J:
            pi=Element(pairing,Zr,value=pi*(i-j))
        piV=Element(pairing,Zr,value=piV+pi)
    v=coeff
    for i in range(len(coeff),N1+1):
        v.append(zero)
    v.append(piV)

    # global testV
    # testV=v

    i=1
    length=Get(0,Q[1],WSet)

    logger.info("Trap length is %s",length)
    q=len(Q)
    logger.info("Send to Front Server for %s times",length)
    logger.info("Query Keywords = %s",Q)
    logger.info("Query keyword number = %d",q-1)

    booleanVector={}
    i=1
    while(i<=q-1):
        booleanVector[i]=1
        i+=1

    l={}
    Trap={}

    i=1
    while(i<=length):
        Trap[i]={}
        #TrapCopy[i]={}
        i=i+1

    i=1
    one=Element(pairing,Zr,value=1)
    s=Element.random(pairing,Zr)
    r=Element.random(pairing,Zr)
    while(i<=length):
        w1=str(Q[1]).encode()
        c=str(i).encode()
        l[i]=PRF_F(Kl,c+w1)
        z=PRF_Fp(params,Kz,c+w1)

        j=1
        #因为有个Q[0]是空,所以<
        while(j<q):
            wj=str(Q[j]).encode()
            hashValue=Element.from_hash(pairing, Zr, Hash1(wj).hexdigest())
            trap=Element(pairing,Zr,value=s*hashValue/z)
            Trap[i][j]=trap
            j=j+1

        i=i+1

    t1=[Element(pairing,G1,value=Element(pairing,G1,value=dk1[k])**(one/s)) for k in range(n)]
    t2=[Element(pairing,G1,value=Element(pairing,G1,value=dk2[k])**(one/s)) for k in range(n)]
    t3=Element(pairing,G1,value=dk3**(one/(s)))
    t4=[Element(pairing,G1,value=Element(pairing,G1,value=U1s1[k])**(one/s)*V1**(Element(pairing,Zr,value=v[k])*(one/s))) for k in range(n)]
    t5=[Element(pairing,G1,value=Element(pairing,G1,value=U2s1[k])**(one/s)*V2**(Element(pairing,Zr,value=v[k])*(one/s))) for k in range(n)]
    t6=Element(pairing,G1,value=g**(one/(s)))

    tds={"t1":t1,"t2":t2,"t3":t3,"t4":t4,"t5":t5,"t6":t6}

    token=[l,Trap,tds]

    tokenCopy=[str(token),booleanVector]
    createFile(ClientPathFromTools+ParameterPathFromTools+"token.dat",str(tokenCopy),"w")

    file_stats = os.stat(ClientPathFromTools+ParameterPathFromTools+"token.dat")
    logTime.info("token.dat size = %s B",file_stats.st_size)
    return token

def Search(mpk,token,EDB,XSet):
    params = Parameters(param_string=stored_params)
    #params = Parameters(qbits=qbits, rbits=rbits)   
    pairing = Pairing(params) 

    vector={}
    booleanVector={}
    [l,Trap,tds]=token

    i=1
    Res=list()

    while(i<=len(l)):
        if(l[i] in EDB.keys()):
            vector={}
            logger.info("Judge Trap[%s] is exist for j in XSet",i)
            e0=EDB[l[i]]['e0']
            e1=EDB[l[i]]['e1']
            e2=EDB[l[i]]['e2']
            e3=EDB[l[i]]['e3']
            e4=EDB[l[i]]['e4']
            e5=EDB[l[i]]['e5']
            e6=EDB[l[i]]['e6']

            j=1
            while(j<=len(Trap[i])):
                trap=Trap[i][j]
                t1j=[Element(pairing,G1,value=tds["t1"][k]**trap) for k in range(n)]
                t2j=[Element(pairing,G1,value=tds["t2"][k]**trap) for k in range(n)]
                t3j=Element(pairing,G1,value=tds["t3"]**trap)
                t4j=[Element(pairing,G1,value=tds["t4"][k]**trap) for k in range(n)]
                t5j=[Element(pairing,G1,value=tds["t5"][k]**trap) for k in range(n)]
                t6j=Element(pairing,G1,value=tds["t6"]**trap)
                flag=0

                # egg=pairing.apply(Element.random(pairing,G1),Element.random(pairing,G1))
                # testdelta=Element(pairing,GT,value=egg/egg)
                delta=pairing.apply(Element(pairing,G1,value=e3),Element(pairing,G1,value=t3j))
                # print(delta)
                for k in range(n):
                    pair1=pairing.apply(Element(pairing,G1,value=e1[k]),Element(pairing,G1,value=t1j[k]))
                    pair2=pairing.apply(Element(pairing,G1,value=e2[k]),Element(pairing,G1,value=t2j[k]))
                    delta=Element(pairing,GT,value=delta*pair1*pair2)
                    # testdelta=Element(pairing,GT,value=testdelta*pair1*pair2)
                # print(delta)

                theta=pairing.apply(Element(pairing,G1,value=e6),Element(pairing,G1,value=t6j))
                # print(theta)
                for k in range(n):
                    pair1=pairing.apply(Element(pairing,G1,value=e4[k]),Element(pairing,G1,value=t4j[k]))
                    pair2=pairing.apply(Element(pairing,G1,value=e5[k]),Element(pairing,G1,value=t5j[k]))
                    theta=Element(pairing,GT,value=theta*pair1*pair2)
                    # testdelta=Element(pairing,GT,value=testdelta*pair1*pair2)

                xtagd=Element(pairing,GT,value=delta*theta)

                if (str(xtagd) in XSet.keys()) :
                    flag=1

                vector[j]=flag
                booleanVector[j]=1
                logger.info("i = %s, j = %s, vector = %s",i,j,vector)
                j=j+1

            if(vector==booleanVector):
                Res.append(e0)
        i+=1

    createFile(ClientPathFromTools+ParameterPathFromTools+"R.dat",str(Res),"w")
    file_stats = os.stat(ClientPathFromTools+ParameterPathFromTools+"R.dat")
    logTime.info("R.dat size = %s B",file_stats.st_size)
    return Res

def Retrieve(mpk,dkR,Res,R):
    abme=mpk["abme"]
    ppk=mpk["ppk"]
    pdk=dkR["pdk"]
    res=[]
    for e0 in Res:
        m=abme.Dec(ppk,pdk,R,e0)
        res.append(m)

    srcpath=ServerPathFromTools+MailEncPathFromTools
    dstpath=ClientPathFromTools+MailDecPathFromTools

    for m in res:
        ind=Inds[str(m)][0]
        Kind=Inds[str(m)][1]
        iv=Inds[str(m)][2]
        file=open(srcpath+ind,"r")
        dataEnc=file.read()
        dataDec=decrypt(dataEnc,Kind,iv)
        createFile(dstpath+ind,dataDec,"w")

    return res

def main(attNum):
    params = Parameters(param_string=stored_params)
    #params = Parameters(qbits=qbits, rbits=rbits)   
    pairing = Pairing(params) 

    attS=[attHash(i) for i in range(1,attNum)] # 1 and ... and 9
    attR=[attHash(i) for i in range(1,attNum)] # 1 and 2 and 3 and 4

    wildcardR=[attHash(i) for i in range(6,8)] # 6 and 7
    policyR=[attHash(i) for i in range(1,attNum)] # 1 and 2 and 3 and 4
    wildcardS=[attHash(i) for i in range(8,10)] # 8 and 9
    policyS=[attHash(i) for i in range(1,attNum)] # 1 and ... and 11

    S=["att"+str(i) for i in range(len(attS))]
    R=["att"+str(i) for i in range(len(attR))]

    global N1
    global n

    N1=attNum
    n=N1+2

    logTime.info("=================Attnum: %d, wildcard: %d=================",attNum,N1)
    
    MainTimeStart=datetime.now()
    mpk,msk=GlobalSetup(qbits=512, rbits=160)
    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("GlobalSetup Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

    MainTimeStart=datetime.now()
    ekS=SKeyGen(mpk,msk,attS,S)
    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("SKeyGen Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

    MainTimeStart=datetime.now()
    dkR=RKeyGen(mpk,msk,attR,R)
    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("RKeyGen Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))
    
    MainTimeStart=datetime.now()
    EDB,XSet=AllSetup(mpk,ekS,wildcardR,policyR,S,R)
    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("AllSetup Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

    Q=['']#russell.tucker@enron.com
    mail=expmail
    for i in range(len(mail)):
        logTime.info("=================Query for %s time=================",i+1)
        Q.append(mail[i])

        MainTimeStart=datetime.now()
        token=TrapGen(mpk,dkR,wildcardS,policyS,Q)
        MainTimeEnd=datetime.now()
        timeleapMain=MainTimeEnd-MainTimeStart
        logTime.info("TrapGen Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

        MainTimeStart=datetime.now()
        Res=Search(mpk,token,EDB,XSet)
        MainTimeEnd=datetime.now()
        timeleapMain=MainTimeEnd-MainTimeStart
        logTime.info("Search Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

        MainTimeStart=datetime.now()
        res=Retrieve(mpk,dkR,Res,R)
        MainTimeEnd=datetime.now()
        timeleapMain=MainTimeEnd-MainTimeStart
        logTime.info("Decrypt Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))

def vice():
    print()

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

        f=open(filepath, "rb+")
        byt = f.read()
        data=byt.decode("ISO-8859-1")
        #data=f.read()
        email = Parser().parsestr(data)

        D['Message-ID']=email['Message-ID']
        D['Date']=email['Date']
        D['From']=email['From']
        D['X-FileName']=email['X-FileName']
        D['X-Origin']=email['X-Origin']
        D['X-From']=email['X-From']
        D['X-Folder']=email['X-Folder']
        toMails=email['To']
        toMailsList=re.split('[,\s]',str(toMails))
        #toMailsList=str(toMails).split(",")
        for mail in toMailsList:
            #keywordCount+=1
            D[mail]=mail
        
        #针对文件subject实现模糊搜索
        subject=email['subject']
        words= word_tokenize(subject)
        for word in words:
            #keywordCount+=1
            D[word]=word

        nlp = spacy.load("en_core_web_sm")
        tr = pytextrank.TextRank()
        nlp.add_pipe(tr.PipelineComponent, name="textrank", last=True)
        doc = nlp(email.get_payload())

        #i=1
        keywordCount=len(D)
        for p in doc._.phrases:
            #print(keywordCount)
            if(keywordCount<=40):
                D[p.text]=p.text
            else:
                break
            keywordCount+=1
        
        # for p in doc._.phrases:
        #     print(p.rank,p.count,p.chunks,p.text)

        DList[filepath]=D
        # for key,value in D.items():
        #     print(value)
        #print(len(D))

    logger.info("==================GetDList End==================")
    return DList

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
    key = key.encode()
    mode = AES.MODE_CBC
    #iv = b'qqqqqqqqqqqqqqqq'
    iv=iv.encode()
    text = add_to_16(text)
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(text)
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
    return b2a_hex(cipher_text)

def decrypt(text,key,iv):
    """[Decrypt encrypted data by AES]

    Args:
        text ([str]): [Encrypted data]
        key ([str]): [AES key must be times of 16]
        iv ([str]): [iv must be times of 16]

    Returns:
        [str]: [Decrypted data]
    """
    key = key.encode()
    mode = AES.MODE_CBC
    #iv = b'qqqqqqqqqqqqqqqq'
    iv=iv.encode()
    cryptos = AES.new(key, mode, iv)
    plain_text = cryptos.decrypt(a2b_hex(text))
    return bytes.decode(plain_text).rstrip('\0')# 解密后，去掉补足的空格用strip() 去掉

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
    path=dstpath.split("/")
    i=0
    temp=""
    while(i<len(path)):
        temp += path[i]
        if(i+1<len(path)):#代表这就是个文件夹
            if(not os.path.exists(temp)):
                os.mkdir(temp)
            temp+="/"
        
        i+=1

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
            logging.info("Creating %s",temp)
            f=open(temp,type)
            f.write(data)
        i+=1

    return 0

def loadFile(filePath):
    logger.info("Reading %s file",filePath)
    fileCopy=open(filePath,"r")
    Copy=eval(fileCopy.read())
    return Copy

def attHash(att):
    params = Parameters(param_string=stored_params)
    pairing = Pairing(params)  
    hashValue=Element.from_hash(pairing, Zr, Hash1(str(att).encode()).hexdigest())
    return hashValue

if __name__ == "__main__":
    for attNum in [5,10,15,20,25,30,35,40,45,50]:
        main(attNum)
    # for i in [1,10,20,30]:
    #     global superlength
    #     superlength=i
    #     main(2)
        
