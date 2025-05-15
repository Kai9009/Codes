
from re import S, X
from typing import DefaultDict
from pypbc import *
import hashlib
import random
import logging
from pathlib import Path
from email.parser import Parser
# import paramiko
import os
import sys
from wolfcrypt.hashes import HmacSha256
import spacy
import pytextrank

import nltk
from nltk.tokenize import *
from nltk.corpus import stopwords
from string import punctuation
import string
from datetime import datetime, timedelta

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

logger = logging.getLogger("Caedios")
logger.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
file_handler = logging.FileHandler("../../log")
file_handler.setLevel(level=logging.INFO)
file_handler.setFormatter(formatter)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

logTime = logging.getLogger("logTime")
logTime.setLevel(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')
fileTime_handler = logging.FileHandler("../../logTime")
fileTime_handler.setLevel(level=logging.INFO)
fileTime_handler.setFormatter(formatter)
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logTime.addHandler(fileTime_handler)
logTime.addHandler(console_handler)

Hash = hashlib.sha256

# 构建 Merkle 树

# build_merkle_tree() 函数用于构建 Merkle 树，

# 它的参数是叶子节点的列表。verify_data_integrity() 函数用于验证数据完整性，

# 它的参数是数据列表和根哈希值。在示例数据中，我们构建了一个包含四个元素的列表，

# 并通过 build_merkle_tree() 函数生成了一棵 Merkle 树。然后使用根哈希值验证了数据的完整性。


def build_merkle_tree(leaves):

    tree = [list(map(lambda x: hashlib.sha256(x.encode()).hexdigest(), leaves))]

    print("tree is :", tree)

    # 当tree列表的最后一行只有一个元素时，停止循环hash计算

    while len(tree[-1]) > 1:

        level = []

        for i in range(0, len(tree[-1]), 2):

            if i + 1 == len(tree[-1]):

                level.append(tree[-1][i])

            else:

                level.append(hashlib.sha256((tree[-1][i] + tree[-1][i + 1]).encode()).hexdigest())

        tree.append(level)

    return tree


# 验证数据完整性

def verify_data_integrity(data, root_hash):
    tree = build_merkle_tree(data)

    # 进行对比，返回真假

    return root_hash == tree[-1][0]
def GlobalSetup(qbits=512, rbits=160):
    """[summary]

    Args:
        qbits (int, optional): [description]. Defaults to 512.
        rbits (int, optional): [description]. Defaults to 160.
        xi (dict, optional): [description]. Defaults to {}.
    """
    logger.info("==================GlobalSetup Start==================")
    MainTimeStart = datetime.now()
    params = Parameters(qbits=qbits, rbits=rbits)  # 参数初始化,pp
    pairing = Pairing(params)  # 根据参数实例化双线性对,e
    g = Element.random(pairing, G1)  # g是G1的一个生成元,g
    alpha = Element.random(pairing, Zr)
    beta = Element.random(pairing, Zr)
    a = Element.random(pairing, Zr)
    egg = pairing.apply(g, g)  # e(g,g)
    theta = Element(pairing, GT, value=egg ** a)  # e(g,g)^a
    gal = Element(pairing, G1, value=g ** alpha)
    gbe = Element(pairing, G1, value=g ** beta)
    ga = Element(pairing, G1, value=g ** a)

    PK = [params, g, theta, gal, gbe]
    MSK = [ga, alpha, beta]
    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("GlobalSetup Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
    return [PK, MSK]


# def main(num):
#     # logger.info("==================main=================")
#     # print(num)
#     # MainTimeStart = datetime.now()
#     # [PK, MSK] = GlobalSetup()
#     # [params, g, theta, gal, gbe]=PK
#     # pairing = Pairing(params)
#     # x={}
#     # str_var="hello"
#     # for i in range(1,num):
#     #     x[i]=Element.random(pairing, Zr)
#     #     data=str_var+x[i]
#     # logger.info("==================data=================")
#     # print(data)
#     #
#     # # data1 = len(x)
#     # # data=str(data1)
#     #
#     # #
#     # # # # 示例数据
#     # # #
#     data = ["hello", "world", "1234", "5678"]
#
#     # 构建 Merkle 树
#
#     tree = build_merkle_tree(data)
#
#     print("Merkle Tree:", tree)
#
#     # 验证数据完整性
#
#     root_hash = tree[-1][0]
#
#     print("Root Hash:", root_hash)
#
#     print("Data is Valid:", verify_data_integrity(data, root_hash))

if __name__ == '__main__':
    logger.info("==================main=================")
    MainTimeStart = datetime.now()
    data = ["hello", "world", "1234", "5678","hello", "world", "1234", "5678","hello", "world", "world", "1234", "5678","hello", "world", "world", "1234", "5678","hello", "world", "world", "1234", "5678","hello", "world"]

    # 构建 Merkle 树

    tree = build_merkle_tree(data)

    print("Merkle Tree:", tree)

    # 验证数据完整性

    root_hash = tree[-1][0]

    print("Root Hash:", root_hash)

    print("Data is Valid:", verify_data_integrity(data, root_hash))

    MainTimeEnd = datetime.now()
    timeleapMain = MainTimeEnd - MainTimeStart
    logTime.info("Main Time: %s s", "{:}.{:06}".format(timeleapMain.seconds, timeleapMain.microseconds))
