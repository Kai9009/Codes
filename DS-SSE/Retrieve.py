from tools import *
from pypbc import *

ParameterPath=ParameterPathFromTools

#inds=readInds(ClientPathFromTools)

def RetrieveThroughFile():
    """[Decrypt files with ind||Kind searched from Res]

    Args:
        params ([type]): [description]
        g ([type]): [Generator of G1]
        Res ([dict]): [Searched result]
        skv ([dict]): [Secret key of User v]

    Returns:
        [type]: [description]
    """
    logger.info("==================Retrieve Start==================")
    [params,g,Kx,Kz,Kl]=readPP(ClientPathFromTools)
    pairing = Pairing(params) 
    vKey=readReceiverVKey(ClientPathFromTools)
    [pkv,skv]=vKey
    beta=skv["sk"]
    filesToReceive=[]
    ResCopy=loadFile(ClientPathFromTools+"Res.dat")
    Res=ResCopy
    inds=readInds(ClientPathFromTools)
    if(Res):
        for item in Res:
            c1=Element(pairing,G1,value=item[0])
            c2=Element(pairing,GT,value=item[1])
            c3=item[2]
            #[c1,c2,c3]=item
            a=Element(pairing,G1,value=c3[0])
            b=Element(pairing,G1,value=c3[1])
            #[a,b]=c3
            X=Element(pairing,G1,value=b/(a ** beta))
            hash_value = Element.from_hash(pairing, G1, Hash1(str(X).encode()).hexdigest())
            temp=pairing.apply(c1,hash_value)#temp=e(g^{r1},H(X))
            m=Element(pairing,GT,value=c2/temp)
            
            # logger.info("Decrypting files")
            # srcpath=ServerPathFromTools+MailEncPathFromTools
            # dstpath=ClientPathFromTools+MailDecPathFromTools

            ind=inds[str(m)][1]
            Kind=inds[str(m)][2]
            iv=inds[str(m)][3]
            
            tuple=[ind,Kind,iv]
            filesToReceive.append(tuple)

            #RetrieveDecFils(srcpath,dstpath,ind,Kind,iv)

    else:
        logger.info("Res is null")
    
    createFile(ClientPathFromTools+"passInd.dat",str(filesToReceive),"w")
    logger.info("==================Retrieve End==================")
    return 0

def RetrieveDecFiles():
    srcpath=ClientPathFromTools+MailEncPathFromTools
    dstpath=ClientPathFromTools+MailDecPathFromTools
    copy=loadFile(ClientPathFromTools+"passInd.dat")
    for tuple in copy:
        ind=tuple[0]
        Kind=tuple[1]
        iv=tuple[2]
        file=open(srcpath+ind,"r")
        dataEnc=file.read()
        dataDec=decrypt(dataEnc,Kind,iv)
        createFile(dstpath+ind,dataDec,"w")

def Retrieve(params,skv,ResCopy,inds):
    pairing = Pairing(params) 
    beta=skv["sk"]
    filesToReceive=[]
    Res=ResCopy
    if(Res):
        for item in Res:
            c1=Element(pairing,G1,value=item[0])
            c2=Element(pairing,GT,value=item[1])
            c3=item[2]
            #[c1,c2,c3]=item
            a=Element(pairing,G1,value=c3[0])
            b=Element(pairing,G1,value=c3[1])
            #[a,b]=c3
            X=Element(pairing,G1,value=b/(a ** beta))
            hash_value = Element.from_hash(pairing, G1, Hash1(str(X).encode()).hexdigest())
            temp=pairing.apply(c1,hash_value)#temp=e(g^{r1},H(X))
            m=Element(pairing,GT,value=c2/temp)
            
            # logger.info("Decrypting files")
            # srcpath=ServerPathFromTools+MailEncPathFromTools
            # dstpath=ClientPathFromTools+MailDecPathFromTools

            ind=inds[str(m)][1]
            Kind=inds[str(m)][2]
            iv=inds[str(m)][3]
            
            tuple=[ind,Kind,iv]
            filesToReceive.append(tuple)

            #RetrieveDecFils(srcpath,dstpath,ind,Kind,iv)

    else:
        logger.info("Res is null")
    
    createFile(ClientPathFromTools+"passInd.dat",str(filesToReceive),"w")
    logger.info("==================Retrieve End==================")
    return 0

if __name__ == '__main__':
    RetrieveThroughFile()
    RetrieveDecFiles()