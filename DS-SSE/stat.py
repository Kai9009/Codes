import os
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from pandas.core.frame import DataFrame
import xlsxwriter
from tools import *
import seaborn as sns
from matplotlib import ticker
import matplotlib.ticker as mtick


def dict2Excel(dic,fileName):
    """[实现字典到Excel的转换]

    Args:
        dic ([type]): [description]
        fileName ([type]): [description]
    """
    workbook = xlsxwriter.Workbook(fileName+'.xlsx')
    worksheet = workbook.add_worksheet()
 
    # 设定格式，等号左边格式名称自定义，字典中格式为指定选项
    # bold：加粗，num_format:数字格式
    bold_format = workbook.add_format({'bold': True})
    #money_format = workbook.add_format({'num_format': '$#,##0'})
    #date_format = workbook.add_format({'num_format': 'mmmm d yyyy'})
 
    # 将二行二列设置宽度为15(从0开始)
    worksheet.set_column(1, 1, 15)
 
    # 用符号标记位置，例如：A列1行
    worksheet.write('A1', 'name', bold_format)
    worksheet.write('B1', 'quantity', bold_format)
    # worksheet.write('C1', 'id_1', bold_format)
    # worksheet.write('D1', 'id_1_doc', bold_format)
    # worksheet.write('E1', 'id_2_doc', bold_format)
    # worksheet.write('F1', 'id_2_doc', bold_format)
    row = 1
    col = 0
    for key,value in dic.items():
            # 使用write_string方法，指定数据格式写入数据
            worksheet.write_string(row, col, str(key))
            worksheet.write_string(row, col + 1, str(value))
            # worksheet.write_string(row, col + 2, str(item['id_1']))
            # worksheet.write_string(row, col + 3, item['id_1_doc'])
            # worksheet.write_string(row, col + 4, str(item['id_2']))
            # worksheet.write_string(row, col + 5, item['id_2_doc'])
            row += 1
    workbook.close()

def getSubFloderList(dir):
    """[获取指定目录下的所有文件夹路径]

    Args:
        dir ([type]): [description]

    Returns:
        [type]: [description]
    """
    p = Path(dir) 
    FileList=list(p.glob("*/"))
    return FileList

def FloderFilesNumber(dir):
    """[获取目录(递归)下所有文件数量]

    Args:
        dir ([type]): [description]

    Returns:
        [type]: [description]
    """
    dic={}
    sortedDic={}
    for path in getSubFloderList(dir):
        count =0
        for root, dirs, files in os.walk(path):
            for file in files:
                count+=1
        dic[path]=count
    for k in sorted(dic,key=dic.__getitem__):
        if(dic[k]>100000):
            continue
        sortedDic[k]=dic[k]
    return sortedDic

def statFolder():
    """[统计文件数量]
    """
    sortedDic=FloderFilesNumber("maildir")
    data=[]
    for key,value in sortedDic.items():
        data.append(value)
    df=DataFrame(data,columns=['value'])
    fig = plt.figure(figsize = (10,6))
    ax1 = fig.add_subplot(2,1,1)  # 创建子图1
    ax1.scatter(df.index, df.values)
    plt.grid()

    ax2 = fig.add_subplot(2,1,2)  # 创建子图2
    df.hist(bins=30,alpha = 0.5,ax = ax2)
    df.plot(kind = 'kde', secondary_y=True,ax = ax2)
    plt.grid()
    plt.show()
    
def getMailSet():
    """[获取WSet字典]

    Returns:
        [type]: [description]
    """
    MailSet={}
    SortMailSet={}
    WSet=readWSet(ClientPathFromTools)
    for key,value in WSet.items():
        if("@" in key and "<" not in key):
            MailSet[key]=value
    
    for k in sorted(MailSet,key=MailSet.__getitem__):
        if(MailSet[k]>3000 or MailSet[k]<1):
            continue
        SortMailSet[k]=MailSet[k]
    return SortMailSet

def statWSet():
    """[统计关键字数量]
    """
    SortMailSet=getMailSet()
    print(SortMailSet)
    data=[]
    for key,value in SortMailSet.items():
        data.append(value)
    
    df=DataFrame(data,columns=['value'])
    fig = plt.figure(figsize = (10,6))
    ax1 = fig.add_subplot(2,1,1)  # 创建子图1
    ax1.scatter(df.index, df.values)
    plt.grid()

    ax2 = fig.add_subplot(2,1,2)  # 创建子图2
    df.hist(bins=30,alpha = 0.5,ax = ax2)
    df.plot(kind = 'kde', secondary_y=True,ax = ax2)
    plt.grid()
    plt.show()

def countWSet():
    SortMailSet=getMailSet()
    n=len(SortMailSet)
    countBefroe={}
    countSingle={}
    countPercent={}
    
    for key,value in SortMailSet.items():
        if(value not in countSingle.keys()):
            countSingle[value]=1
        else:
            countSingle[value]=countSingle[value]+1
            
    for key,value in countSingle.items():
        if(key not in countBefroe.keys()):
            countBefroe[key]=value
        for key2,value2 in countSingle.items():
            if(key2<key):
                countBefroe[key]=countBefroe[key]+value2

    for key,value in countBefroe.items():
        countPercent[key]=countBefroe[key]/n
            

    print(countSingle)
    print(countBefroe)
    print(countPercent)
    dict2Excel(countPercent,"temp")

def drawSetupPhoto():
    mytime = pd.read_csv('csv/setupTime.csv')
    mytime.head()
    custom_params = {"axes.spines.right": False,"axes.spines.left": False, "axes.spines.top": False}
    sns.set_theme(style="whitegrid",rc=custom_params)
    sns.barplot(x="Project", y="Time Cost (seconds)",hue="Procedure",alpha=0.8,dodge=True,data=mytime)
    plt.xlabel("")
    plt.legend()
    plt.ylim(0, 0.05)
    plt.show()

def drawTrapGenPhoto():
    mydata=pd.read_csv('csv/trapGenTime.csv')
    mydata.head()
    #sns.set_theme(style="darkgrid")
    custom_params = {"axes.spines.right": False, "axes.spines.top": False}
    sns.set_theme(style="whitegrid",rc=custom_params)
    sns.lineplot(x="WSet", y="Time Cost (seconds)",hue="Project",style="Project",markers=True, dashes=False,data=mydata)
    plt.legend()
    plt.ylim(-0.2, 2.5)
    plt.show()

def drawWSetPhoto():
    mydata=pd.read_csv('csv/WSet.csv')
    mydata.head()
    
    x, y = mydata["x"], mydata["y"]
    sns.scatterplot(x=x,y=y)

    #color = ['Sienna','Coral','Crimson','GoldEnrod','ForestGreen']
    x = y = np.arange(-3, 3, 0.1)
    x, y = np.meshgrid(x,y)
    for i in range(1,40,2):
        #cmap = ListedColormap(color[i])
        plt.contour(x, y, x**2 + y**2, [i**2])#x**2 + y**2 = i的圆形

    plt.show()

def drawWSetRatePhoto():
    mydata=pd.read_csv('csv/WSetRate.csv')
    mydata.head()
    #sns.set_theme(style="darkgrid")
    custom_params = {"axes.spines.right": False, "axes.spines.top": False}
    sns.set_theme(style="whitegrid",rc=custom_params)
    
    #mydata['percent']=[]
    temp=[]
    i=0
    for rate in mydata['FileRate']:
        #a='{:.1f}%'.format(rate*100)
        a=rate*100
        temp.append(a)
    
    mydata['Percentage']=temp
    #fig = plt.figure()
    
    ax = plt.subplot()
    ax.yaxis.set_major_formatter(mtick.PercentFormatter())
    

    sns.lineplot(x="WSet", y="Percentage",hue="Project",style="Project",ax=ax,markers=True, dashes=False,data=mydata)
    plt.yticks([90,95,97.5,99,100])
    plt.ylim(90, 100.2)
    plt.legend()

    
    plt.show()

def drawFileSetDisPhoto():
    mydata=pd.read_csv('csv/FileSet.csv')
    mydata.head()
    x, y = mydata["x"], mydata["y"]
    #sns.displot(x=x,kde=True)
    #sns.set_theme()
    sns.color_palette("pastel")
    sns.jointplot(x=x, y=y, kind="hex", color="dodgerblue")
    #sns.displot(x=x,kde=True)
    plt.show()

def drawSearchPhoto():
    sns.set_theme(style="ticks", palette="pastel")

    mydata=pd.read_csv('csv/searchTime.csv')
    mydata.head()

    # Draw a nested boxplot to show bills by day and time
    sns.barplot(x="S-term", y="Time Cost (seconds)",
                hue="Query Keyword Num",
                data=mydata)
    #sns.despine(offset=10, trim=True)

    plt.xlabel("s-term")
    plt.legend()
    plt.show()

def drawSearchLtTenPhoto():
    """[查询S-term<=10且2<=Q<=10]
    """
    mydata=pd.read_csv('csv/searchLtTenTime.csv')
    mydata.head()

    # custom_params = {"axes.spines.right": False, "axes.spines.top": False}
    # sns.set_theme(style="whitegrid",rc=custom_params)
    # sns.lineplot(x="Query Keyword Num", y="Time Cost (seconds)",hue="Project",style="Project",markers=True, dashes=False,data=mydata)
    # plt.legend()
    # plt.ylim(0, 1.2)
    # plt.show()



    #sns.set_theme(style="whitegrid")
    # Initialize a grid of plots with an Axes for each walk
    grid = sns.FacetGrid(mydata, col="s-term", hue="s-term", #palette="tab20c",
                        col_wrap=5, height=3)

    # Draw a horizontal line to show the starting point
    grid.refline(y=.3, linestyle=":")
    grid.refline(y=.6, linestyle=":")
    grid.refline(y=.9, linestyle=":")

    # Draw a line plot to show the trajectory of each random walk
    grid.map(plt.plot, "WSet", "Time Cost (seconds)", marker="o")

    # Adjust the tick positions and labels
    grid.set(xticks=np.arange(11), #yticks=[-3, 3],
            xlim=(0,11), ylim=(0, 1.2))

    # Adjust the arrangement of the plots
    #grid.fig.tight_layout(w_pad=1)

    plt.show()

def drawSearchGtTenPhoto():
    """[查询S-term>=10且2<=Q<=3]
    """
    mydata=pd.read_csv('csv/searchGtTenTime.csv')
    mydata.head()
    custom_params = {"axes.spines.right": False,"axes.spines.left": False, "axes.spines.top": False}
    sns.set_theme(style="whitegrid",rc=custom_params)
    sns.barplot(x="Query Keyword Num", y="Time Cost (seconds)",hue="Project",alpha=0.8,dodge=True,data=mydata)
    plt.xlabel("")
    plt.legend()
    plt.ylim(0, 1.2)
    plt.show()

def drawRetrievePhoto():
    mydata=pd.read_csv('csv/retrieveOneTime.csv')
    mydata.head()

    # sns.regplot(x="num", y="Retrieve",data=mydata)
    # sns.lmplot(x="num", y="Retrieve",data=mydata)
    
    
    sns.set_theme(style="whitegrid")

    x=mydata["WSet"]
    y=mydata["Retrieve"]

    ax = sns.swarmplot(data=mydata, x="WSet", y="Retrieve", hue="s-term")
    plt.legend(ncol=3, fancybox=True,title="s-term")
    plt.ylim(0.01,0.04)
    ax.set(ylabel="Retrieve Time (seconds)")

    # Plot the residuals after fitting a linear model
    #sns.residplot(x=x, y=y, lowess=True, color="g")


    plt.show()

def drawReceivePhoto():
    mydata=pd.read_csv('csv/receiveTime.csv')
    mydata.head()
    
    sns.set_theme(style="whitegrid")

    ax = sns.swarmplot(data=mydata, x="WSet", y="Receive", hue="s-term")
    plt.legend(ncol=3, fancybox=True,title="s-term")
    plt.ylim(1,4.5)
    ax.set(ylabel="Receive Time (seconds)")

    # Plot the residuals after fitting a linear model
    #sns.residplot(x=x, y=y, lowess=True, color="g")


    plt.show()

def drawDecryptPhoto():
    mydata=pd.read_csv('csv/receiveTime.csv')
    mydata.head()
    
    sns.set_theme(style="whitegrid")

    ax = sns.swarmplot(data=mydata, x="WSet", y="Decrypt", hue="s-term")
    plt.legend(ncol=3, fancybox=True,title="s-term")
    #plt.ylim(1,4.5)
    ax.set(ylabel="Decrypt Time (seconds)")

    # Plot the residuals after fitting a linear model
    #sns.residplot(x=x, y=y, lowess=True, color="g")


    plt.show()

def drawTokenSizePhoto():
    mydata=pd.read_csv('csv/tokenSize.csv')
    mydata.head()
    custom_params = {"axes.spines.right": False, "axes.spines.top": False}
    sns.set_theme(style="whitegrid",rc=custom_params)
    sns.lineplot(x="WSet", y="Token Size (KB)",hue="Project",style="Project",markers=True, dashes=False,data=mydata)
    plt.legend()
    plt.ylim(0, 30)
    plt.show()

def drawTokenSendPhoto():
    mydata=pd.read_csv('csv/tokenSendTime.csv')
    mydata.head()
    
    # sns.set_theme(style="whitegrid")

    # tempY=[]
    # for item in mydata["Send Time (seconds)"]:
    #     tempY=item*1000

    # mydata["Send Time (milliseconds)"]=tempY
    # print(mydata)

    # ax = sns.swarmplot(data=mydata, x="WSet", y="Send Time (milliseconds)", hue="s-term")
    # plt.legend(ncol=3, fancybox=True,title="s-term")
    # #plt.ylim(1,4.5)
    # ax.set(ylabel="Send Time (milliseconds)")



    custom_params = {"axes.spines.right": False, "axes.spines.top": False}
    sns.set_theme(style="whitegrid",rc=custom_params)
    sns.lineplot(x="WSet", y="Send Time (seconds)",hue="s-term",style="s-term",palette="tab10",markers=True, dashes=False,data=mydata)
    plt.legend(labels=[1,6,10,49],title="s-term")
    plt.ylim(0, 0.0035)
    plt.show()

    plt.show()

def main():
    drawTokenSendPhoto()
    
    

if __name__ == '__main__':
    main()