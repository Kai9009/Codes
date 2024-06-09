from tools import *
from pypbc import *

ParameterPath=ParameterPathFromTools

#inds=readInds(ServerPathFromTools)

def SearchThroughFile():
    """[Back Server search data with tokenbs and return to User]

    Args:
        params ([type]): [description]
        g ([type]): [Generator of G1]
        tokenbs ([type]): [Token tokenbs received from Front Server]
        skbs ([type]): [description]
        rkuv ([type]): [Re-encryption key convert U->V]
        EDB ([type]): [description]
        XSet ([type]): [description]

    Returns:
        [type]: [Searched result]
    """
    logger.info("==================Search Start==================")
    [params,g,Kx,Kz,Kl]=readPP(ServerPathFromTools)
    pairing = Pairing(params) 
    serverKey=readServerKey(ServerPathFromTools)
    [pkfs,skfs,pkbs,skbs]=serverKey
    EDBCopy=loadFile(ServerPathFromTools+"EDB.dat")
    XSetCopy=loadFile(ServerPathFromTools+"XSet.dat")
    ztwo=Element(pairing,Zr,value=2)
    vector={}
    count=0#记录有几个文件符合

    tokenbsCopy=loadFile(ServerPathFromTools+"tokenbs.dat")
    [l,TrapCopy,StatusCopy,booleanVector]=tokenbsCopy

    rkuvCopy=loadFile(ServerPathFromTools+ParameterPath+"rkuv.dat")
    rkuv={}
    rkuv[1]=Element(pairing,G1,value=rkuvCopy[1])
    rkuv[2]=Element(pairing,G1,value=rkuvCopy[2])
    rkuv[3]=Element(pairing,G1,value=rkuvCopy[3])
    rkuv[4]=Element(pairing,G1,value=rkuvCopy[4])

    #[l,Trap,Status]=tokenbs
    i=1
    Res=list()
    ResCopy=list()
    #由于l是传过来的,省略0位置,此处要写<=
    while(i<=len(l)):
        print("==============")
        if(l[i] in EDBCopy.keys()):
            #print(EDB[l[i]])
            logger.info("Judge Trap[%s] UgUe is exist for j in XSet",i)
            e0Copy=EDBCopy[l[i]]['e0']
            e0={}
            e0['a']=Element(pairing,G1,value=e0Copy['a'])
            e0['b']=Element(pairing,GT,value=e0Copy['b'])
            e1Copy=EDBCopy[l[i]]['e1']
            e1=Element(pairing,Zr,value=int(str(e1Copy),16))
            #count=0
            j=1
            while(j<=len(TrapCopy[i])):
                [T1Copy,T2Copy]=TrapCopy[i][j]
                T1=Element(pairing,G1,value=T1Copy)
                T2=Element(pairing,G1,value=T2Copy)
                TgCopy=StatusCopy[i][j]
                Tg=Element(pairing,G1,value=TgCopy)
                T2e=Element(pairing,G1,value=T2 ** skbs["sk"])
                T1e=Element(pairing,G1,value=T1 ** (skbs["sk"] ** ztwo))
                Te=Element(pairing,G1,value=T2e /T1e)#  Teta=T2^{eta}  /  T1^{eta^2}
                UgUe=pairing.apply(Element(pairing,G1,value=rkuv[4] ** e1),Element(pairing,G1,value=Tg/Te))

                flag=0#判断本次关键字是否在XSet中
                for itemCopy in XSetCopy.values():
                    item=Element(pairing,GT,value=itemCopy)
                    if(UgUe==item):
                        #count=count+1 #仅用于Conjuctive Search
                        flag=1

                vector[j]=flag
                j=j+1

            if(vector==booleanVector):
            #if(count==len(TrapCopy[i])): #仅用于Conjuctive Search
                a=Element(pairing,G1,value=e0["a"])
                b=Element(pairing,GT,value=e0["b"])
                c1=Element(pairing,G1,value=a)
                temp=pairing.apply(a,rkuv[3])
                c2=Element(pairing,GT,value=b*temp)
                c3=[rkuv[1],rkuv[2]]
                e=[c1,c2,c3]
                count+=1
                Res.append(e)
                ResCopy.append([str(c1),str(c2),[str(rkuv[1]),str(rkuv[2])]])
                logger.info("Check Trap[%s] UgUe success",i)
            else:
                logger.info("Check Trap[%s] UgUe fail",i)

        i=i+1

    createFile(ServerPathFromTools+"Res.dat",str(ResCopy),"w")
    logger.info("==================Search End==================")
    return count

def Search(params,tokenbsCopy,serverKey,rkuvCopy,EDB,XSet):
    """[Back Server search data with tokenbs and return to User]

    Args:
        params ([type]): [description]
        g ([type]): [Generator of G1]
        tokenbs ([type]): [Token tokenbs received from Front Server]
        skbs ([type]): [description]
        rkuv ([type]): [Re-encryption key convert U->V]
        EDB ([type]): [description]
        XSet ([type]): [description]

    Returns:
        [type]: [Searched result]
    """
    logger.info("==================Search Start==================")
    
    pairing = Pairing(params) 
    [pkfs,skfs,pkbs,skbs]=serverKey
    ztwo=Element(pairing,Zr,value=2)
    vector={}
    count=0#记录有几个文件符合

    [l,TrapCopy,StatusCopy,booleanVector]=tokenbsCopy

    rkuv={}
    rkuv[1]=Element(pairing,G1,value=rkuvCopy[1])
    rkuv[2]=Element(pairing,G1,value=rkuvCopy[2])
    rkuv[3]=Element(pairing,G1,value=rkuvCopy[3])
    rkuv[4]=Element(pairing,G1,value=rkuvCopy[4])

    #[l,Trap,Status]=tokenbs
    i=1
    Res=list()
    ResCopy=list()
    #由于l是传过来的,省略0位置,此处要写<=
    while(i<=len(l)):
        print("==============")
        if(l[i] in EDB.keys()):
            #print(EDB[l[i]])
            logger.info("Judge Trap[%s] UgUe is exist for j in XSet",i)
            e0=EDB[l[i]]['e0']
            e1=EDB[l[i]]['e1']
            #count=0
            j=1
            while(j<=len(TrapCopy[i])):
                [T1Copy,T2Copy]=TrapCopy[i][j]
                T1=Element(pairing,G1,value=T1Copy)
                T2=Element(pairing,G1,value=T2Copy)
                TgCopy=StatusCopy[i][j]
                Tg=Element(pairing,G1,value=TgCopy)
                T2e=Element(pairing,G1,value=T2 ** skbs["sk"])
                T1e=Element(pairing,G1,value=T1 ** (skbs["sk"] ** ztwo))
                Te=Element(pairing,G1,value=T2e /T1e)#  Teta=T2^{eta}  /  T1^{eta^2}
                UgUe=pairing.apply(Element(pairing,G1,value=rkuv[4] ** e1),Element(pairing,G1,value=Tg/Te))

                flag=0#判断本次关键字是否在XSet中
                for item in XSet.values():
                    #item=Element(pairing,GT,value=itemCopy)
                    if(UgUe==item):
                        #count=count+1 #仅用于Conjuctive Search
                        flag=1

                vector[j]=flag
                j=j+1

            if(vector==booleanVector):
            #if(count==len(TrapCopy[i])): #仅用于Conjuctive Search
                a=Element(pairing,G1,value=e0["a"])
                b=Element(pairing,GT,value=e0["b"])
                c1=Element(pairing,G1,value=a)
                temp=pairing.apply(a,rkuv[3])
                c2=Element(pairing,GT,value=b*temp)
                c3=[rkuv[1],rkuv[2]]
                e=[c1,c2,c3]
                count+=1
                #Res.append(e)
                ResCopy.append([str(c1),str(c2),[str(rkuv[1]),str(rkuv[2])]])
                logger.info("Check Trap[%s] UgUe success",i)
            else:
                logger.info("Check Trap[%s] UgUe fail",i)

        i=i+1

    createFile(ServerPathFromTools+"Res.dat",str(ResCopy),"w")
    logger.info("==================Search End==================")
    return count

def Copy2UnCopy(params):
    EDB={}
    XSet={}
    pairing = Pairing(params) 
    EDBCopy=loadFile(ServerPathFromTools+"EDB.dat")
    XSetCopy=loadFile(ServerPathFromTools+"XSet.dat")
    for key in EDBCopy.keys():
        e0Copy=EDBCopy[key]['e0']
        e0={}
        e0['a']=Element(pairing,G1,value=e0Copy['a'])
        e0['b']=Element(pairing,GT,value=e0Copy['b'])
        e1Copy=EDBCopy[key]['e1']
        e1=Element(pairing,Zr,value=int(str(e1Copy),16))
        EDB[key]={"e0":e0,"e1":e1}
        itemCopy=XSetCopy[key]
        item=Element(pairing,GT,value=itemCopy)
        XSet[key]=item
    return [EDB,XSet]


if __name__ == '__main__':
    SearchThroughFile()