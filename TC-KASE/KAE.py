from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair

class KAE:
    def __init__(self, groupObj):
        global group, i_zr, z_zr, i_gt
        group = groupObj

        temp = group.random()
        i_zr = temp/temp
        z_zr = temp-temp

        i_gt = group.random(GT)
        i_gt = i_gt/i_gt

    def Setup(self, lamb, n):
        alpha = group.random(ZR)
        g = group.random(G1)

        g2n=[g**(alpha**group.init(ZR, i)) for i in range(2*n+1)]
        g2n[n+1]=g

        pp={"g":g,"g2n":g2n,"n":n}

        return pp

    def KeyGen(self,lamb,pp):
        gamma=group.random(ZR)
        v=pp["g"]**gamma

        pk=v
        sk=gamma

        return pk,sk

    def Enc(self,pp,pk,i,m):
        n=pp["n"]
        if(i not in range(1,n+1)):
            raise Exception("i not in {1,...,n}")

        t=group.random(ZR)
        c1=pp["g"]**t
        c2=(pk*pp["g2n"][i])**t
        c3=m*pair(pp["g2n"][1],pp["g2n"][n])**t

        ct={"c1":c1,"c2":c2,"c3":c3,"i":i}
        return ct

    def Extract(self,pp,sk,S):
        n=pp["n"]

        pi=group.init(G1,1)
        for j in S:
            pi=pi*pp["g2n"][n+1-j]
        KS=pi**sk
        return KS

    def Dec(self,pp,KS,S,i,ct):
        n=pp["n"]

        pi1 = group.init(G1, 1)
        for j in S:
            if(j==i): continue
            pi1=pi1*pp["g2n"][n+1-j+i]

        pi2 = group.init(G1, 1)
        for j in S:
            pi2 = pi2 * pp["g2n"][n + 1 - j]

        m=ct["c3"]*pair(KS*pi1,ct["c1"])/pair(pi2,ct["c2"])
        return m

def main():
    groupObj = PairingGroup("SS512")
    lamb=512
    n=10

    m = groupObj.random(GT)
    i=5
    S=[j for j in range(1,5+1)]

    kae = KAE(groupObj)
    pp=kae.Setup(lamb,n)
    pk, sk=kae.KeyGen(lamb,pp)
    ct=kae.Enc(pp,pk,i,m)
    KS=kae.Extract(pp,sk,S)
    md=kae.Dec(pp, KS, S, i, ct)
    print("m=m': ",m==md)

if __name__ == '__main__':
    main()
