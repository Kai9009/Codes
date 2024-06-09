from tools import *
from pypbc import *

ParameterPath=ParameterPathFromTools

def GlobalSetupThroughFile(qbits=512, rbits=160):
    """[KGC generate public parameter]

    Args:
        qbits (int, optional): [description]. Defaults to 512.
        rbits (int, optional): [description]. Defaults to 160.

    Returns:
        [type]: [description]
    """
    logger.info("==================GlobalSetup Start==================")
    params = Parameters(qbits=qbits, rbits=rbits)   #参数初始化
    pairing = Pairing(params)  # 根据参数实例化双线性对
    g = Element.random(pairing, G1)  # g是G1的一个生成元
    Kx=generate_random_str(16).encode('utf-8')
    Kz=generate_random_str(16).encode('utf-8')
    Kl=generate_random_str(16).encode('utf-8')

    paramsCopy = str(params)
    gCopy = str(g)
    KxCopy = str(Kx)
    KzCopy = str(Kz)
    KlCopy = str(Kl)

    ppCopy = [paramsCopy,gCopy,KxCopy,KzCopy,KlCopy]

    createFile(ServerPathFromTools+ParameterPath+"pp.dat",str(ppCopy),"w")
    logger.info("==================GlobalSetup End==================")
    return [params,g,Kx,Kz,Kl]

if __name__ == '__main__':
    GlobalSetupThroughFile()