from GlobalSetup import *
from KeyGenServer import *
from KeyGenReceiverU import *
from KeyGenReceiverV import *
from ReKeyGen import *
from EDBSetup import *
from tools import logTime
from datetime import datetime

def Init():
    GlobalSetupTimeStart=datetime.now()
    GlobalSetupThroughFile()
    GlobalSetupTimeEnd=datetime.now()
    timeleapGlobalSetup=GlobalSetupTimeEnd-GlobalSetupTimeStart
    logTime.info("GlobalSetup Time: %s s","{:}.{:06}".format(timeleapGlobalSetup.seconds,timeleapGlobalSetup.microseconds))
    
    KeyGenTimeStart=datetime.now()
    KeyGenServerThroughFile()
    KeyGenReceiverUThroughFile()
    KeyGenReceiverVThroughFile()
    KeyGenTimeEnd=datetime.now()
    timeleapKeyGen=KeyGenTimeEnd-KeyGenTimeStart
    logTime.info("KeyGen Time: %s s","{:}.{:06}".format(timeleapKeyGen.seconds,timeleapKeyGen.microseconds))

    ReKeyGenTimeStart=datetime.now()
    ReKeyGenThroughFile()
    ReKeyGenTimeEnd=datetime.now()
    timeleapReKeyGen=ReKeyGenTimeEnd-ReKeyGenTimeStart
    logTime.info("ReKeyGen Time: %s s","{:}.{:06}".format(timeleapReKeyGen.seconds,timeleapReKeyGen.microseconds))

    EDBSetupTimeStart=datetime.now()
    AllSetup()
    EDBSetupTimeEnd=datetime.now()
    timeleapEDB=EDBSetupTimeEnd-EDBSetupTimeStart
    logTime.info("EDBSetup Time: %s s","{:}.{:06}".format(timeleapEDB.seconds,timeleapEDB.microseconds))
    


if __name__ == '__main__':
    Init()