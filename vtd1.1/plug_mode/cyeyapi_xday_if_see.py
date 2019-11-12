#! /usr/bin/python3

#persistence of energy  能量守恒v1.1

import requests,demjson,argparse
from tabulate import tabulate


def plugin(): #插件基础信息
    pluginid = '01'
    pluginname = 'cyeyapi'
    plugineffect = 'Determine whether the vulnerability is triggered' #判断漏洞是否触发
    pluginauthor = 'Greekn'
    plugintime = '2019-11-11' 
    
    plugin_info = [['插件id',pluginid],['插件名称',pluginname],['插件用途',plugineffect],['插件作者',pluginauthor],['插件编写时间',plugintime]]
    display = ['plugin_basic_info','plugin_txt']
    print(tabulate(plugin_info,headers=display,tablefmt="grid"))
    return 0


def http():
    plugin()
    ceyekey = "xxx" #ceye key
    type = 'http' #查看触发类型是http


    try:
        resp = requests.get("http://api.ceye.io/v1/records?token="+ceyekey+"&type="+type)
        respdecode = demjson.decode(resp.text)
        number=len(respdecode["data"])
        
        for i in range(number):
            resp_info = ['id',respdecode['data'][i]["id"]],['name',respdecode['data'][i]['name']],['method',respdecode['data'][i]['method']],['remote_addr',respdecode['data'][i]['remote_addr']],['user_agent',respdecode['data'][i]['user_agent']],['created_at',respdecode['data'][i]['created_at'],['data',respdecode['data'][i]['data']],['content_type',respdecode['data'][i]['content_type']]]        
            display = ['基础信息','参数']
            print(tabulate(resp_info,headers=display,tablefmt="grid"))  

    
    except:
         print("[-]请求访问失败！")
        

def dns():
    plugin()
    ceyekey = "xxx" #ceye key
    type = 'dns' #查看触发类型是 dns 
    try:
        resp = requests.get("http://api.ceye.io/v1/records?token="+ceyekey+"&type="+type)
        respdecode = demjson.decode(resp.text)
        number=len(respdecode["data"])
       
        for i in range(number):       
            resp_info = [['id',respdecode['data'][i]['id']],['name',respdecode['data'][i]['name']],['Remote Addr',respdecode['data'][i]['remote_addr']],['Created At (UTC+0)',respdecode['data'][i]['created_at']]]
            display = ['基础信息','参数']
            print(tabulate(resp_info,headers=display,tablefmt="grid"))      
        
    except:
        print("[-]请求访问失败！")
 
def set():
    output_stos = input("[*]请输入type，dns或http:")
    if output_stos == "dns":    
        dns()
    elif output_stos =="http":
        http()
        
if __name__=='__main__':
    set()

