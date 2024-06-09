from socket import*
import struct
import json
import os
import sys
import time
from datetime import datetime

from TrapGen import *
from Retrieve import *
# 用户的文件夹路径
FILEPATH = "Client/"

# 创建客户端
client = socket(AF_INET, SOCK_STREAM)
ip_port = ('114.116.16.120', 21575)
#ip_port = ('127.0.0.1', 21575)
buffSize = 1024
client.connect(ip_port)
print("connecting...")

def Client():
    # 开始通信
    while True:
        # 用户选择要进行的服务，将选择发送给服务器
        select = input("请输入要选择的服务： 1--获得pp 2--查询文件ind  3--下载文件ind  0--退出系统")
        client.send(bytes(select, "utf-8"))

        # 查询文件
        if select == "1":
            time.sleep(1)
            i=1
            ReceivePPStart=datetime.now()
            while(i<=6):
                receiveFile()
                i+=1
            ReceivePPEnd=datetime.now()
            receiveFile()#receive inds.dat
            timeleapReceivePP=ReceivePPEnd-ReceivePPStart
            logTime.info("Client receive public parameter Time: %s s","{:}.{:06}".format(timeleapReceivePP.seconds,timeleapReceivePP.microseconds))

        # 下载文件
        elif select == "2":
            
            # 因为跑实验,下面代码注释掉,互动版再加回
            # Q=["","carl.fink@neg.pge.com","rmfmckinne@aol.com","Lifting","the","Rate"]
            # V=[0,1,1,1,1,1]
            # Copy=[Q,V]
            # createFile(ClientPathFromTools+"para.dat",str(Copy),"w")

            Copy=loadFile(ClientPathFromTools+"para.dat")
            [Q,V]=Copy
            logTime.info("Generate Trap for %s",Q)
            print(Q)

            # 仅用于做实验
            i=1
            V={}
            V[0]=1
            while(i<len(Q)):
                V[i]=1
                i+=1
            [params,g,Kx,Kz,Kl]=readPP(ClientPathFromTools)
            pairing = Pairing(params) 
            serverKey=readServerKey(ClientPathFromTools)
            [pkfs,skfs,pkbs,skbs]=serverKey
            vKey=readReceiverVKey(ClientPathFromTools)
            [pkv,skv]=vKey
            WSet=readWSet(ClientPathFromTools)

            TrapGenTimeStart=datetime.now()
            TrapGen(params,g,pkfs,pkbs,skv,WSet,Q,V)
            #TrapGenThroughFile()
            TrapGenTimeEnd=datetime.now()
            timeleapTrapGen=TrapGenTimeEnd-TrapGenTimeStart
            logTime.info("Client TrapGen Time: %s s","{:}.{:06}".format(timeleapTrapGen.seconds,timeleapTrapGen.microseconds))
            
            #fileName = input("请输入要上传的文件名加后缀：").strip()
            fileName = "tokenfs.dat"
            SendTokenfsStart=datetime.now()
            sendFile(fileName)
            SendTokenfsEnd=datetime.now()
            timeleapSendTokenfs=SendTokenfsEnd-SendTokenfsStart
            logTime.info("Client send tokenfs Time: %s s","{:}.{:06}".format(timeleapSendTokenfs.seconds,timeleapSendTokenfs.microseconds))
            
            ReceiveResStart=datetime.now()
            receiveFile()
            ReceiveResEnd=datetime.now()
            timeleapReceiveRes=ReceiveResEnd-ReceiveResStart
            logTime.info("Client receive Res.dat Time: %s s","{:}.{:06}".format(timeleapReceiveRes.seconds,timeleapReceiveRes.microseconds))


            vKey=readReceiverVKey(ClientPathFromTools)
            [pkv,skv]=vKey
            ResCopy=loadFile(ClientPathFromTools+"Res.dat")
            inds=readInds(ClientPathFromTools)

            ReceiveRetStart=datetime.now()
            Retrieve(params,skv,ResCopy,inds)
            #RetrieveThroughFile()
            ReceiveRetEnd=datetime.now()
            timeleapReceiveRet=ReceiveRetEnd-ReceiveRetStart
            logTime.info("Client Retrieve Time: %s s","{:}.{:06}".format(timeleapReceiveRet.seconds,timeleapReceiveRet.microseconds))

        elif select == "3":
            fileName = "passInd.dat"

            SendFileStart=datetime.now()
            sendFile(fileName)
            SendFileEnd=datetime.now()
            timeleapSend=SendFileEnd-SendFileStart
            logTime.info("Client Send passInd.dat files Time: %s s","{:}.{:06}".format(timeleapSend.seconds,timeleapSend.microseconds))
            
            copy=loadFile(ClientPathFromTools+"passInd.dat")
            count=0
            for tuple in copy:
                count+=1
            i=1
            totalSize=0
            ReceiveFileStart=datetime.now()
            while(i<=count):
                print(i)
                totalSize+=receiveFile()
                i+=1
            logTime.info("Client receive total size is %s KB",totalSize/1024)
            ReceiveFileEnd=datetime.now()
            timeleapReceive=ReceiveFileEnd-ReceiveFileStart
            logTime.info("Client receive Real files Time: %s s","{:}.{:06}".format(timeleapReceive.seconds,timeleapReceive.microseconds))
            
            RetrieveTimeStart=datetime.now()
            RetrieveDecFiles()
            RetrieveTimeEnd=datetime.now()
            timeleapRetrieve=RetrieveTimeEnd-RetrieveTimeStart
            logTime.info("Client Decrypt Time: %s s","{:}.{:06}".format(timeleapRetrieve.seconds,timeleapRetrieve.microseconds))
        #退出客户端
        else:
            print("退出系统！")
            client.close()
            break

def sendFile(fileName):
    fileInfor = FILEPATH + fileName
    # 得到文件的大小
    filesize_bytes = os.path.getsize(fileInfor)
    logTime.info("Client send %s and its size is %s KB",fileName,filesize_bytes/1024)


    # 创建复制文件
    #fileName = "new" + fileName

    # 创建字典用于报头
    dirc = {"fileName": fileName,
            "fileSize": filesize_bytes}

    # 将字典转为JSON字符，再将字符串的长度打包
    head_infor = json.dumps(dirc)
    head_infor_len = struct.pack('i', len(head_infor))

    # 先发送报头长度，然后发送报头内容
    client.send(head_infor_len)
    client.send(head_infor.encode("utf-8"))

    # 发送真实文件
    with open(fileInfor, 'rb') as f:
        data = f.read()
        client.sendall(data)
        f.close()

    # 服务器若接受完文件会发送信号，客户端接收
    # completed = client.recv(buffSize).decode("utf-8")
    # if completed == "1":
    #     print("上传成功")

def receiveFile():
    # 默认文件存在，接受并解析报头的长度，接受报头的内容
    head_struct = client.recv(4)
    head_len = struct.unpack('i', head_struct)[0]
    data = client.recv(head_len)

    # 解析报头字典
    try:
        head_dir = json.loads(data.decode('utf-8'))
    except:
        print(data.decode('utf-8'))
        return 
    filesize_b = head_dir["fileSize"]
    filename = head_dir["fileName"]

    logTime.info("Client receive %s and its size is %s KB",filename,filesize_b/1024)

    # 接受真实的文件内容
    recv_len = 0
    recv_mesg = b''

    createDir(FILEPATH+filename)
    f = open("%s%s" % (FILEPATH, filename), "wb")

    while recv_len < filesize_b:
        if filesize_b - recv_len > buffSize:
            # 假设未上传的文件数据大于最大传输数据
            recv_mesg = client.recv(buffSize)
            f.write(recv_mesg)
            recv_len += len(recv_mesg)
        else:
            # 需要传输的文件数据小于最大传输数据大小
            recv_mesg = client.recv(filesize_b - recv_len)
            recv_len += len(recv_mesg)
            try:
                f.write(recv_mesg)
            except:
                f = open("%s%s" % (FILEPATH, filename), "ab")
                f.write(recv_mesg)
            f.close()
            print(filename+"文件接收完毕！")

    # # 向服务器发送信号，文件已经上传完毕
    # completed = "1"
    # client.send(bytes(completed, "utf-8"))
    return filesize_b

if __name__ == '__main__':
    Client()
