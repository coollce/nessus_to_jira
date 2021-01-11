import requests,json,time
from log import logger
from config import global_config
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def create_target():
    '''
    在AWVS创建要扫描的目标，并且配置扫描速度为低速等基础条件,获取target_id
    :return:
    '''
    url='https://'+awvs_url+'/api/v1/targets'
    data = {
        'address': scan_address,
        'description': 'ceshilog',
        'criticality': 10,
    }
    resp_create=requests.post(url=url,data=json.dumps(data),headers=headers,verify=False)
    if resp_create.status_code==201:
        logger.info('创建目标成功，开始启动扫描')
        taget_id=resp_create.json()['target_id']
        print('target_id={}'.format(taget_id))
        url2='https://'+awvs_url+'/api/v1/targets/'+taget_id+'/configuration'
        data2={
            "scan_speed":"fast"
        }
        requests.patch(url=url2,data=json.dumps(data2),headers=headers,verify=False)
        # start_scan(taget_id)
        return taget_id
    else:
        logger.info("目标创建失败，请检查api网络和apikey的正确性")


def start_scan():
    '''
    开启扫描任务，获取scan_id
    'profile_id': "11111111-1111-1111-1111-111111111112" 扫描模式为完全扫描
    :param target_id:
    :return:
    '''
    target_id=create_target()
    url='https://'+awvs_url+'/api/v1/scans'
    data={
        'target_id': target_id,
        'profile_id': "11111111-1111-1111-1111-111111111112",
        "report_template_id": "11111111-1111-1111-1111-111111111111",
        'schedule': {"disable":False,"start_date":None,"time_sensitive":False}
    }
    resp_start=requests.post(url=url,data=json.dumps(data),headers=headers,verify=False)
    if resp_start.status_code == 201:
        logger.info('扫描任务启动成功，扫描进行中')
        scan_id=resp_start.headers['Location'].split('/')[4]
        print('扫描id：scan_id={}'.format(scan_id))
        logger.info('scan_id={}'.format(scan_id))
        # status_scan(scan_id)
        return scan_id
    else:
        logger.info("扫描任务启动失败")

def status_scan(scan_id):
    '''
    查看任务状态，获取scan_session_id值
    :param scan_id:
    :return:
    '''
    url='https://'+awvs_url+'/api/v1/scans/'+scan_id
    while True:
        resp_status=requests.get(url=url,headers=headers,verify=False).json()
        # time.sleep(10)
        status=resp_status["current_session"]["status"]
        scan_sessionid=resp_status["current_session"]["scan_session_id"]
        print('扫描状态：{}'.format(status))
        logger.info('当前任务扫描状态：{}'.format(status))
        print('scan_sessionid={}'.format(scan_sessionid))
        logger.info('当前任务的scan_sessionid={}'.format(scan_sessionid))
        if status =='completed':
            logger.info('扫描任务已完成')
            # result_scan(scan_id,scan_sessionid)
            return scan_sessionid
            # break
        else:
            logger.info('扫描正在进行中，请等待扫描完成')
            print('请等待15分钟--------')
            time.sleep(180)
            # status_scan(scan_id)


def result_scan():
    '''
     扫描完毕后查看当前扫描任务的扫描结果，获取vuln_id值,查询单个漏洞详情
    :param scan_address:
    :return:
    '''

    scan_id=start_scan()
    # scan_id='f3194222-800d-4bdb-888a-afd53684773f'
    scan_sessionid=status_scan(scan_id)
    # scan_sessionid='a63a500b-a67f-46ed-98b5-6992b7c7b863'
    url='https://'+awvs_url+'/api/v1/scans/'+scan_id+'/results/'+scan_sessionid+'/vulnerabilities'
    resp_result=requests.get(url=url,headers=headers,verify=False).json()
    vulnerabilities=resp_result['vulnerabilities']
    vuln_list=[]
    for vuln in vulnerabilities:
        # vuln_result(scan_id,scan_sessionid,vuln['vuln_id'])
        url2 = url + '/'+ vuln['vuln_id']
        resp_vuln = requests.get(url=url2, headers=headers, verify=False).json()
        vuln_dict = {"vt_name": resp_vuln['vt_name'], "request": resp_vuln['request'],'recommendation':resp_vuln['recommendation']}
        vuln_list.append(vuln_dict)
    return vuln_list
    # vuln_result(scan_id,scan_sessionid,'2476136388693591114')

    # print(type(vulnerabilities),len(vulnerabilities))
    # for i in vuln_id_list:
    #     print(i)

# def vuln_result(scan_id,scan_sessionid,vuln_id):
#     '''
#     通过vuln_id值获取漏洞的详细信息，提取每个漏洞信息中需要的字段存储到vul_list 列表中
#     :param scan_id:
#     :param scan_sessionid:
#     :param vuln_id:
#     :return:
#     '''
#
#     url='https://'+awvs_url+'/api/v1/scans/'+scan_id+'/results/'+scan_sessionid+'/vulnerabilities/'+vuln_id
#     resp_vuln=requests.get(url=url,headers=headers,verify=False).json()
#     #测试时候随便选择几个字段，使用时候修改成需要的字段存储
#     vuln_dict={"vt_name":resp_vuln['vt_name'],"status":resp_vuln['status']}
#
#     vuln_list.append(vuln_dict)

    # print(resp_vuln['vt_name'],'\n',resp_vuln['request'])
    # pass

def vuln_jira():
    a=result_scan()
    logger.info('扫描完成，扫描结果正在提交jira')
    url = "http://jira.chinac.com/rest/api/2/issue/bulk"
    auth = HTTPBasicAuth(jira_username,jira_password)
    jira_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    payloadlist=[]
    for i in a:
        ta={'fields': {
            "summary": "【{}】【安全测试】{}".format(project_name, i['vt_name']),
            "issuetype": {"id": "10104"},
            "project": {"id": "{}".format(projetc_id)},
            "customfield_10731": "【漏洞描述】\n{}\n【修复建议】{}".format(i['request'], i['recommendation']),
            "environment": "{}".format(scan_address),
            "versions": [{"id": "{}".format(affect_versions)}],
            "assignee": {"name": "{}".format(assignee)}
                 }
        }
        payloadlist.append(ta)
    payload = {'issueUpdates':payloadlist}
    logger.info('筛选后的漏洞为:{}'.format(payload))
    try:
        response = requests.post(url, data=json.dumps(payload), headers=jira_headers, auth=auth)
        if response.status_code == 201:
            logger.info('jira issue创建成功')
    except Exception as e:
        logger.info(e)

if __name__ == '__main__':

    #要被扫描的地址
    scan_address=global_config.getRaw('awvs', 'scan_address')
    # scan_address='http://testphp.vulnweb.com/'

    #AWVS服务器ip地址和端口号
    awvs_url=global_config.getRaw('awvs', 'awvs_url')
    # awvs_url='10.51.x.x:13443'

    # api调用时候使用的header，其中主要为apikey，通过页面生成
    api_key=global_config.getRaw('awvs', 'api_key')
    headers = {
        'X-Auth': '{}'.format(api_key),
        'Content-type': 'application/json'
    }
    project_name=global_config.getRaw('jira', 'projetc_name')
    projetc_id=global_config.getRaw('jira', 'projetc_id')
    affect_versions=global_config.getRaw('jira', 'affect_versions')
    jira_username=global_config.getRaw('jira', 'jira_username')
    jira_password=global_config.getRaw('jira', 'jira_password')
    assignee=global_config.getRaw('jira', 'assignee')

    # print(start_scan('32bd6e20-034d-4067-9500-c2b1591508f5'))
    a=result_scan()
    # status_scan('02d96910-c984-440b-9ee7-4f581d782087')
    print(a)
