from demo import *


def main():
    """[summary]

    Returns:
        [Attention]: [注意一下ATT必须排序之后进行lagrange]
        [User1]: [设定User1拥有属性ATT1]
        [User2]: [设定User1拥有属性ATT2]
    """
    ATT0=['NoAtt1','NoAtt2']
    dictATT=getDictATT()
    #ATT1=["Att1","Att2","Att3"]
    ATT1=dictATT[3]
    
    DB={}

    GolbalSetupTimeStart=datetime.now()
    [PP,MK]=GlobalSetup()
    GolbalSetupTimeEnd=datetime.now()
    timeleapGolbalSetup=GolbalSetupTimeEnd-GolbalSetupTimeStart
    logTime.info("GolbalSetup Time: %s s","{:}.{:06}".format(timeleapGolbalSetup.seconds,timeleapGolbalSetup.microseconds))

    PP=readPP(ServerPathFromTools)
    MK=readMK(ServerPathFromTools)

    KeyGenSTimeStart=datetime.now()
    KeyGenS(PP,MK)
    KeyGenSTimeEnd=datetime.now()
    timeleapKeyGenS=KeyGenSTimeEnd-KeyGenSTimeStart
    logTime.info("KeyGenS Time: %s s","{:}.{:06}".format(timeleapKeyGenS.seconds,timeleapKeyGenS.microseconds))

    [pks,sks]=readServerKey(ServerPathFromTools)

    KeyGenCTimeStart=datetime.now()
    KeyGenC(PP,MK,ATT1)
    KeyGenCTimeEnd=datetime.now()
    timeleapKeyGenC=KeyGenCTimeEnd-KeyGenCTimeStart
    logTime.info("KeyGenC Time: %s s","{:}.{:06}".format(timeleapKeyGenC.seconds,timeleapKeyGenC.microseconds))


    skc=readClientKey(ServerPathFromTools)

    AllSetupDB(PP,skc,pks,sks,ATT0,dictATT)

if __name__ == '__main__':
    main()



