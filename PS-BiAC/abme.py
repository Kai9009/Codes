from pypbc import *
import hashlib
import random
import logging
from datetime import datetime,timedelta

logger=logging.getLogger("Caedios")
logger.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
file_handler = logging.FileHandler("log")
file_handler.setLevel(level=logging.INFO)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

logTime=logging.getLogger("logTime")
logTime.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
fileTime_handler = logging.FileHandler("logTime")
fileTime_handler.setLevel(level=logging.INFO)
fileTime_handler.setFormatter(formatter)
logTime.addHandler(fileTime_handler)

stored_params ="""type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1"""

Hash1 = hashlib.sha256
Hash2 = hashlib.sha256
Hash3 = hashlib.sha256

class ABME:
    def __init__(self,curve):
        params = Parameters(param_string=curve)
        self.pairing=Pairing(params)  

    def pi(self,i):
        return i

    def GlobalSetup(self, qbits=512, rbits=160):
        logger.info("==================GlobalSetup Start==================")
        pairing = self.pairing

        g = Element.random(pairing, G1)
        alpha =Element.random(pairing,Zr)
        beta=Element.random(pairing,Zr)

        galpha=Element(pairing,G1,value=g**alpha)
        gbeta=Element(pairing,G1,value=g**beta)

        eggalpha=pairing.apply(galpha,g)
        eggbeta=pairing.apply(gbeta,g)

        mpk={"g":g,"eggalpha":eggalpha,"eggbeta":eggbeta}
        msk={"galpha":galpha,"gbeta":gbeta,"beta":beta}

        logger.info("==================GlobalSetup End==================")
        return mpk,msk

    def EKGen(self, mpk, msk, S):
        pairing=self.pairing

        r=Element.random(pairing,Zr)
        k=len(S)
        ek1=[]
        ek2=Element(pairing,G1,value=mpk["g"]**r)
        for i in range(k):
            hash_value=Element.from_hash(pairing,G1,Hash1(str(S[i]).encode()).hexdigest())
            ek1i=Element(pairing,G1,value=msk["galpha"]*hash_value**r)
            ek1.append(ek1i)

        ek={"S":S,"ek1":ek1,"ek2":ek2}
        return ek

    def DKGen(self,mpk,msk,R,Raccess):
        pairing=self.pairing
        lR=len(Raccess)
        nR=len(Raccess[0])
        

        y=[Element.random(pairing,Zr) for j in range(nR)]
        lamb=[]
        for i in range(lR):
            sum=Element(pairing,Zr,value=0)
            for j in range(nR):
                sum=Element(pairing,Zr,value=sum+Raccess[i][j]*y[j])
            if(i==0): sum=Element(pairing,Zr,value=msk["beta"]-Element(pairing,Zr,value=lR-1))
            else: sum=Element(pairing,Zr,value=1)
            # print(sum)
            lamb.append(sum)
        # print(msk["beta"])
        # zero=Element(pairing,Zr,value=0)
        # for i in range(len(lamb)):
        #     zero=Element(pairing,Zr,value=zero+lamb[i])
        # print(zero)

        dk1=[]
        dk2=[]
        for i in range(lR):
            ri=Element.random(pairing,Zr)
            glambi=Element(pairing,G1,value=mpk["g"]**lamb[i])
            hash_value=Element.from_hash(pairing,G1,Hash2(str(R[i]).encode()).hexdigest())
            dk1i=Element(pairing,G1,value=glambi*hash_value**ri)
            dk2i=Element(pairing,G1,value=mpk["g"]**ri)
            dk1.append(dk1i)
            dk2.append(dk2i)
        
        dk={"R":Raccess,"dk1":dk1,"dk2":dk2}
        return dk
            
    def Enc(self,mpk,ek,R,S,m):
        pairing=self.pairing
        s=Element.random(pairing,Zr)
        rd=Element.random(pairing,Zr)
        t=Element.random(pairing,Zr)
        c0=Element(pairing,GT,value=m*mpk["eggbeta"]**s)
        c1=Element(pairing,G1,value=mpk["g"]**s)
        c2=[]
        for i in range(len(R)):
            hash_value=Element.from_hash(pairing,G1,Hash1(str(R[i]).encode()).hexdigest())
            c2i=Element(pairing,G1,value=hash_value**s)
            c2.append(c2i)
        c3=Element(pairing,G1,value=ek["ek2"]*mpk["g"]**rd)
        c4=Element(pairing,G1,value=mpk["g"]**t)
        c1to4=str(c1)
        for i in range(len(c2)):
            c1to4=c1to4+str(c2[i])
        c1to4=c1to4+str(c3)+str(c4)

        c5=[]
        hash3=Element.from_hash(pairing,G1,Hash3(str(c1to4).encode()).hexdigest())
        #print(hash3)
        for i in range(len(S)):
            hash1=Element.from_hash(pairing,G1,Hash1(str(S[i]).encode()).hexdigest())
            ek1i=Element(pairing,G1,value=ek["ek1"][i]*hash1**rd)
            c5i=Element(pairing,G1,value=ek1i*hash3**t)
            c5.append(c5i)

        c={"S":S,"R":R,"c0":c0,"c1":c1,"c2":c2,"c3":c3,"c4":c4,"c5":c5}
        return c

    def Verify(self,mpk,Saccess,S,c):
        pairing=self.pairing
        lS=len(Saccess)
        nS=len(Saccess[0])
        zone=Element(pairing,Zr,value=1)

        c0=c["c0"]
        c1=c["c1"]
        c2=c["c2"]
        c3=c["c3"]
        c4=c["c4"]
        c5=c["c5"]

        x=[Element(pairing,Zr,value=1)]
        for i in range(1,nS):
            x.append(Element.random(pairing,Zr))

        kappa=[]
        for i in range(lS):
            sum=Element(pairing,Zr,value=0)
            for j in range(nS):
                sum=Element(pairing,Zr,value=sum+Saccess[i][j]*x[j])
            kappa.append(sum)

        omega=[Element(pairing,Zr,value=zone/kappa[0])]
        for i in range(1,nS):
            omega.append(Element(pairing,Zr,value=0))

        c1to4=str(c1)
        for i in range(len(c2)):
            c1to4=c1to4+str(c2[i])
        c1to4=c1to4+str(c3)+str(c4)

        egg=pairing.apply(mpk["g"],mpk["g"])
        prod=Element(pairing,GT,value=egg/egg)
        hash3=Element.from_hash(pairing,G1,Hash3(str(c1to4).encode()).hexdigest())
        downr=pairing.apply(hash3,c4)
        for i in range(len(S)):
            exp=Element(pairing,Zr,value=omega[i]*kappa[i])

            up=pairing.apply(c5[i],mpk["g"])
            hash1=Element.from_hash(pairing,G1,Hash1(str(S[i]).encode()).hexdigest())
            downl=pairing.apply(hash1,c3)
            item=Element(pairing,GT,value=up/(downl*downr))
            prod=Element(pairing,GT,value=prod*item**exp)
        
        check=prod==mpk["eggalpha"]
        return check

    def Dec(self,mpk,dk,R,c):
        pairing=self.pairing
        zone=Element(pairing,Zr,value=1)
        Racc=dk["R"]

        egg=pairing.apply(mpk["g"],mpk["g"])
        prod=Element(pairing,GT,value=egg/egg)

        eta=[]
        for i in range(len(R)):
            eta.append(Element(pairing,Zr,value=1))

        for i in range(len(R)):
            up=pairing.apply(dk["dk2"][i],c["c2"][i])
            down=pairing.apply(dk["dk1"][i],c["c1"])
            item=Element(pairing,GT,value=(up/down)**eta[i])
            prod=Element(pairing,GT,value=prod*item)

        m=Element(pairing,GT,value=c["c0"]*prod)
        return m

def main():
    attNum=10
    lR=10
    nR=10
    params = Parameters(param_string=stored_params)
    pairing=Pairing(params)  

    S=["att"+str(i) for i in range(attNum)]
    R=["att"+str(i) for i in range(attNum)]
    Raccess=[[Element.from_hash(pairing,Zr,Hash1((str(i)+str(j)).encode()).hexdigest()) for j in range(nR)] for i in range(lR)]
    Saccess=[[Element.from_hash(pairing,Zr,Hash1((str(i)+str(j)).encode()).hexdigest()) for j in range(nR)] for i in range(lR)]

    m=pairing.apply(Element.random(pairing,G1),Element.random(pairing,G1))

    abme=ABME(stored_params)
    mpk,msk=abme.GlobalSetup(qbits=512, rbits=160)
    ek=abme.EKGen(mpk, msk, S)
    dk=abme.DKGen(mpk,msk,R,Raccess)
    c=abme.Enc(mpk,ek,R,S,m)
    check=abme.Verify(mpk,Saccess,S,c)
    md=abme.Dec(mpk,dk,R,c)

    print(check)
    print(m==md)

def vice():
    lR=3
    nR=3
    params = Parameters(param_string=stored_params)
    pairing=Pairing(params)  

    Raccess=[[Element.random(pairing,Zr) for j in range(nR)] for i in range(lR)]
    x=[Element(pairing,Zr,value=1)]
    for i in range(1,nR):
        x.append(Element.random(pairing,Zr))

    kappa=[]
    for i in range(lR):
        sum=Element(pairing,Zr,value=0)
        for j in range(nR):
            sum=Element(pairing,Zr,value=sum+Raccess[i][j]*x[j])
        kappa.append(sum)

if __name__ == '__main__':
    MainTimeStart=datetime.now()
    main()
    #vice()
    MainTimeEnd=datetime.now()
    timeleapMain=MainTimeEnd-MainTimeStart
    logTime.info("Main Time: %s s","{:}.{:06}".format(timeleapMain.seconds,timeleapMain.microseconds))