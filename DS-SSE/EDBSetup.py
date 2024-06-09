from tools import *
from pypbc import *
from pathlib import Path
from email.parser import Parser
from nltk.tokenize import *
import re
import spacy
import pytextrank

ParameterPath=ParameterPathFromTools

# WSet=readWSet()
WSet={}
IndsCopy={}
EDBCopy={}
XSetCopy={}

def Get(delta,w):
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

def Update(delta,w,c):
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

def EDBSetup(params,g,pkfs,pkbs,pku,sku,D,EDB,XSet):
    """[User u encrypt his file and generate EDB and XSet]

    Args:
        params ([type]): [description]
        g ([type]): [description]
        D ([type]): [description]
        sku ([type]): [Secret key of user u]
        pkfs ([type]): [Public key of Front Server]
        pkbs ([type]): [Public key of Back Srever]
        EDB ([type]): [description]
        XSet ([type]): [description]

    Returns:
        [type]: [description]
    """
    #logger.info("==================EDBSetup Start==================")

    pairing = Pairing(params) 

    alpha=sku["sk"]

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
        c=Get(0,content)
        c=c+1
        Update(0,content,c)

    indByte=str(ind).encode()
    xind=PRF_Fp(params,sku["Kx"],indByte)
    for keyword,content in WindSet.items():
        r1=Element.random(pairing,Zr) 
        c=Get(0,content)

        cw=str(c).encode('utf-8')
        w=str(content).encode('utf-8')
        
        l=PRF_F(sku["Kl"],w+cw)
        z=PRF_Fp(params,sku["Kz"],w+cw)
        m=pairing.apply(Element.random(pairing,G1), Element.random(pairing,G1))
        #inds[str(m)]=[filePath,ind,Kind,iv]
        IndsCopy[str(m)]=[str(filePath),str(ind),str(Kind),str(iv)]

        a=Element(pairing, G1, value=g ** r1)   #g^r1
        hashE0 = Element.from_hash(pairing, G1, Hash1(str(pku).encode()).hexdigest())#H(g^alpha)
        temp=pairing.apply(a,Element(pairing,G1,value=hashE0 ** alpha))
        b=Element(pairing, GT, value= m * temp )
        e0={"a":a,"b": b}   #(g^r1,m*g^{alpha*r1})
        e1=Element(pairing,Zr,value=(xind * z * alpha)) #xind*z*alpha
        EDB[l]={"e0":e0,"e1":e1}
        EDBCopy[l]={"e0":{"a":str(a),"b":str(b)},"e1":str(e1)}

        hash_value = Element.from_hash(pairing, G1, Hash1(w).hexdigest())   #H1(w)
        xtag=pairing.apply(Element(pairing,G1,value=pkfs/pkbs), Element(pairing,G1,value=hash_value ** xind))   #e(g^{gamma-eta},H1(w)^xind)
        XSet[l]=xtag
        XSetCopy[l]=str(xtag)

    #logger.info("==================EDBSetup End==================")
    return [EDB,XSet]

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
            D[mail]=mail
        
        #针对文件subject实现模糊搜索
        subject=email['subject']
        words= word_tokenize(subject)
        for word in words:
            D[word]=word

        # nlp = spacy.load("en_core_web_sm")
        # tr = pytextrank.TextRank()
        # nlp.add_pipe(tr.PipelineComponent, name="textrank", last=True)
        # doc = nlp(email.get_payload())

        # i=1
        # for p in doc._.phrases:
        #     if(i<=10):
        #         D[p.text]=p.text

        DList[filepath]=D
        # for key,value in D.items():
        #     print(key,value)

    logger.info("==================GetDList End==================")
    return DList

def AllSetup():
    DList=GetDList("CSExperiment/maildir/corman-s")
    [params,g,Kx,Kz,Kl]=readPP(ServerPathFromTools)

    serverKey=readServerKey(ServerPathFromTools)
    [pkfs,skfs,pkbs,skbs]=serverKey

    uKey=readReceiverUKey(ServerPathFromTools)
    [pku,sku]=uKey
    EDB={}
    XSet={}
    logger.info("==================EDBSetup Start==================")
    for D in DList.items():
        [EDB,XSet]=EDBSetup(params,g,pkfs,pkbs,pku,sku,D,EDB,XSet)
    logger.info("==================EDBSetup End==================")
    createFile(ServerPathFromTools+"EDB.dat",str(EDBCopy),"w")
    createFile(ServerPathFromTools+"XSet.dat",str(XSetCopy),"w")
    createFile(ServerPathFromTools+ParameterPath+"Inds.dat",str(IndsCopy),"w")
    createFile(ServerPathFromTools+ParameterPath+"WSet.dat",str(WSet),"w")

if __name__ == '__main__':
    AllSetup()