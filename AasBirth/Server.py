# 完整服务器端（面对单用户）
from socket import*
import json
import os
import struct
import time
from datetime import datetime

from demo import *

# 服务器端文件夹位置
FILEPATH = "Server/"

# 创建sever服务器
sever = socket(AF_INET, SOCK_STREAM)
ip_port = ('',21575)
buffSize = 1024

# 监听
sever.bind(ip_port)
sever.listen(5)

# 创建sever服务器
sever2 = socket(AF_INET, SOCK_STREAM)
ip_port2 = ('',21576)

# 监听
sever2.bind(ip_port2)
sever2.listen(5)

def Server():
    while True:
        # 预加载文件
        

        # 连接客户端
        print("waiting for connection......\n")
        clientSock, addr = sever.accept()
        print("connected with ", end = '')
        print(addr)
        print()

        # 开始通信
        while True:
            # 接收客户端的选择信息，上传，下载？
            print("waiting for order......\n")
            funcSelect = clientSock.recv(buffSize).decode("utf-8")  # 把数据从bytes类型转换为str
            print("用户的选择是：", end='')
            print(funcSelect)
            print()

            # 客户端上传文件
            if funcSelect == "1":
                i=0
                SendPPStart=datetime.now()
                parameter=["PP.dat","skc.dat","sks.dat","WSet.dat"]
                while(i<len(parameter)):
                    sendFile(clientSock,ParameterPathFromTools+parameter[i])
                    i+=1
                SendPPEnd=datetime.now()
                sendFile(clientSock,ParameterPathFromTools+"Inds.dat")
                timeleapSendPP=SendPPEnd-SendPPStart
                logTime.info("Server Send public parameter files Time: %s s","{:}.{:06}".format(timeleapSendPP.seconds,timeleapSendPP.microseconds))
            # 客户端下载文件   
            elif funcSelect == "2":
                PP=readPP(ServerPathFromTools)
                DB=readDB(ServerPathFromTools)

                ReceiveStart=datetime.now()
                receiveFile(clientSock)#Receive policy.dat
                ReceiveEnd=datetime.now()
                timeleapReceive=ReceiveEnd-ReceiveStart
                logTime.info("Server receieve token.dat Time: %s s","{:}.{:06}".format(timeleapReceive.seconds,timeleapReceive.microseconds))

                SearchTimeStart=datetime.now()
                token=readToken(ServerPathFromTools)
                SearchDB(PP,token,DB)
                SearchTimeEnd=datetime.now()
                timeleapSearch=SearchTimeEnd-SearchTimeStart
                logTime.info("Server Search Time: %s s","{:}.{:06}".format(timeleapSearch.seconds,timeleapSearch.microseconds))

                SendResTimeStart=datetime.now()
                sendFile(clientSock,ParameterPathFromTools+"Res.dat")
                SendResTimeEnd=datetime.now()
                timeleapSendRes=SendResTimeEnd-SendResTimeStart
                logTime.info("Server Send Res.dat Time: %s s","{:}.{:06}".format(timeleapSendRes.seconds,timeleapSendRes.microseconds))

            elif funcSelect == "3":
                print("Not in use")

            elif funcSelect == "4":
                ReceiveStart=datetime.now()
                receiveFile(clientSock)#Receive policy.dat
                ReceiveEnd=datetime.now()
                timeleapReceive=ReceiveEnd-ReceiveStart
                logTime.info("Server receieve policy.dat Time: %s s","{:}.{:06}".format(timeleapReceive.seconds,timeleapReceive.microseconds))

                [sigma,Tag]=readPolicy(ServerPathFromTools)
                PP=readPP(ServerPathFromTools)
                DB=readDB(ServerPathFromTools)

                
                

                DBCopy=getDBCopy(PP,DB)
                [pks,sks]=readServerKey(ServerPathFromTools)

                PolicyAdpTimeStart=datetime.now()
                DB=PolicyAdpDB(PP,sks,sigma,Tag,DB,DBCopy)
                PolicyAdpTimeEnd=datetime.now()
                timeleapPolicyAdp=PolicyAdpTimeEnd-PolicyAdpTimeStart
                logTime.info("Execute 1 PolicyAdp Time: %s s","{:}.{:06}".format(timeleapPolicyAdp.seconds,timeleapPolicyAdp.microseconds))

                
                DBCopy=getDBCopy(PP,DB)
                createFile(ServerPathFromTools+ParameterPathFromTools+"DB.dat",str(DBCopy),"w")
            # 客户端退出
            else:
                print("用户退出！")
                clientSock.close()
                break

def sendFile(clientSock,fileName):
    fileInfor = FILEPATH + fileName
    # 得到文件的大小
    filesize_bytes = os.path.getsize(fileInfor)
    logTime.info("Server send %s and its size is %s KB",fileName,filesize_bytes/1024)

    # 创建复制文件
    #fileName = "new" + fileName

    # 创建字典用于报头
    dirc = {"fileName": fileName,
            "fileSize": filesize_bytes}

    # 将字典转为JSON字符，再将字符串的长度打包
    head_infor = json.dumps(dirc)
    head_infor_len = struct.pack('i', len(head_infor))

    # 先发送报头长度，然后发送报头内容
    clientSock.send(head_infor_len)
    clientSock.send(head_infor.encode("utf-8"))

    # 发送真实文件
    with open(fileInfor, 'rb') as f:
        data = f.read()
        clientSock.sendall(data)
        f.close()

    # 服务器若接受完文件会发送信号，客户端接收
    # completed = clientSock.recv(buffSize).decode("utf-8")
    # if completed == "1":
    #     print("Send {1} Success",fileName)

def receiveFile(clientSock):
    # 默认文件存在，接受并解析报头的长度，接受报头的内容
    head_struct = clientSock.recv(4)
    head_len = struct.unpack('i', head_struct)[0]
    data = clientSock.recv(head_len)

    # 解析报头字典
    head_dir = json.loads(data.decode('utf-8'))
    filesize_b = head_dir["fileSize"]
    filename = head_dir["fileName"]

    logTime.info("Server receive %s and its size is %s KB",filename,filesize_b/1024)

    # 接受真实的文件内容
    recv_len = 0
    recv_mesg = b''

    createDir(FILEPATH+filename)
    f = open("%s%s" % (FILEPATH, filename), "wb")

    while recv_len < filesize_b:
        if filesize_b - recv_len > buffSize:
            # 假设未上传的文件数据大于最大传输数据
            recv_mesg = clientSock.recv(buffSize)
            f.write(recv_mesg)
            recv_len += len(recv_mesg)
        else:
            # 需要传输的文件数据小于最大传输数据大小
            recv_mesg = clientSock.recv(filesize_b - recv_len)
            recv_len += len(recv_mesg)
            try:
                f.write(recv_mesg)
            except:
                f = open("%s%s" % (FILEPATH, filename), "ab")
                f.write(recv_mesg)
            print("Receive {1} Success",filename)
            f.close()

    # # 向服务器发送信号，文件已经上传完毕
    # completed = "1"
    # clientSock.send(bytes(completed, "utf-8"))

if __name__ == '__main__':
    Server()
    sever.close()