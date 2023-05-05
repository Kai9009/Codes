# Python3 program to implement
# Vieta's formula to calculate
# polynomial coefficients.
from pypbc import *
import hashlib
Hash1 = hashlib.sha256

stored_params ="""type a
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1"""

def vietaFormula(roots):
    params = Parameters(param_string=stored_params)
    pairing = Pairing(params)  

    n=len(roots)

    coeff = [Element(pairing,Zr,value=0)] * (n + 1)

    # Set Highest Order
    # Coefficient as 1
    one=Element(pairing,Zr,value=1)
    coeff[n] = one
    for i in range(1, n + 1):
        for j in range(n - i - 1, n):
            temp=Element(pairing,Zr,value=-one*roots[i - 1]*coeff[j + 1])
            coeff[j] = Element(pairing,Zr,value=coeff[j]+temp)
            #coeff[j] += ((-1) * roots[i - 1] * coeff[j + 1])

    # Reverse Array
    #coeff = coeff[::-1]

    # print("Polynomial Coefficients : ", end = "")

    # # Print Coefficients
    # for i in coeff:
    #     print(i)

    return coeff

def attHash(att):
    params = Parameters(param_string=stored_params)
    pairing = Pairing(params)  
    hashValue=Element.from_hash(pairing, Zr, Hash1(str(att).encode()).hexdigest())
    return hashValue


def main():
    params = Parameters(param_string=stored_params)
    pairing = Pairing(params)  
    # roots = [Element.random(pairing,Zr) for i in range(3)]
    # # Function call
    # coeff=vietaFormula(roots)
    L=4
    N1=2

    zero=Element(pairing,Zr,value=0)
    one=Element(pairing,Zr,value=1)

    

    J=[attHash(3),attHash(4)]
    V=[attHash(1)]

    coeff=vietaFormula(J)
    piV=zero
    for i in V:
        pi=one
        for j in J:
            pi=Element(pairing,Zr,value=pi*(i-j))
        piV=Element(pairing,Zr,value=piV+pi)
    v=coeff
    v.append(piV)
    print(v)

    Alice=[attHash(1),attHash(4)]
    xV=[]
    for k in range(N1+1):
        print(k)
        k=Element(pairing,Zr,value=k)
        vk=zero
        for i in Alice:
            vk=Element(pairing,Zr,value=vk+i**k)
        vk=Element(pairing,Zr,value=-vk)
        xV.append(vk)
    xV.append(one)
    print(xV)

    sigma=zero
    for i in range(len(v)):
        sigma=Element(pairing,Zr,value=sigma+v[i]*xV[i])
    print(sigma)
            



    


    # sigma=Element(pairing,Zr,value=0)
    # for i in range(len(coeff)):
    #     zpI=Element(pairing,Zr,value=i)
    #     sigma=Element(pairing,Zr,value=sigma+coeff[i]*roots[0]**(zpI))
    # print("sigma",sigma)

if __name__ == "__main__":
    main()

# This code is contributed
# by Arihant Joshi
