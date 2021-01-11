import requests,json,time
from log import logger
from config import global_config
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def get_nessus_template_uuid(template_name = "advanced"):
    '''
    获取策略模板的uuid
    :param template_name:
    :return:
    '''
    url = nessus_url+'/editor/scan/templates'
    response = requests.get(url=url, headers=header, verify=False)
    templates = json.loads(response.text)['templates']

    for template in templates:
        if template['name'] == template_name:
            return template['uuid']
    return None

def create_template():
    '''
    创建扫描模板
    :return:
    '''
    uuid=get_nessus_template_uuid()
    plugins={
        "SMTP problems":{
            "status":"enabled"
        },
        "Backdoors":{
            "status":"enabled"
        },
        "Ubuntu Local Security Checks":{
            "status":"enabled"
        },
        "Gentoo Local Security Checks":{
            "status":"enabled"
        },
        "Oracle Linux Local Security Checks":{
            "status":"enabled"
        },
        "RPC":{
            "status":"enabled"
        },
        "Gain a shell remotely":{
            "status":"enabled"
        },
        "Service detection":{
            "status":"enabled"
        },
        "DNS":{
            "status":"enabled"
        },
        "Mandriva Local Security Checks":{
            "status":"enabled"
        },
        "Junos Local Security Checks":{
            "status":"enabled"
        },
        "Misc.":{
            "status":"enabled"
        },
        "FTP":{
            "status":"enabled"
        },
        "Slackware Local Security Checks":{
            "status":"enabled"
        },
        "Default Unix Accounts":{
            "status":"enabled"
        },
        "AIX Local Security Checks":{
            "status":"enabled"
        },
        "SNMP":{
            "status":"enabled"
        },
        "OracleVM Local Security Checks":{
            "status":"enabled"
        },
        "CGI abuses":{
            "status":"enabled"
        },
        "Settings":{
            "status":"enabled"
        },
        "CISCO":{
            "status":"enabled"
        },
        "Firewalls":{
            "status":"enabled"
        },
        "Databases":{
            "status":"enabled"
        },
        "Debian Local Security Checks":{
            "status":"enabled"
        },
        "Fedora Local Security Checks":{
            "status":"enabled"
        },
        "Netware":{
            "status":"enabled"
        },
        "Huawei Local Security Checks":{
            "status":"enabled"
        },
        "Windows : User management":{
            "status":"enabled"
        },
        "VMware ESX Local Security Checks":{
            "status":"enabled"
        },
        "Virtuozzo Local Security Checks":{
            "status":"enabled"
        },
        "CentOS Local Security Checks":{
            "status":"enabled"
        },
        "Peer-To-Peer File Sharing":{
            "status":"enabled"
        },
        "NewStart CGSL Local Security Checks":{
            "status":"enabled"
        },
        "General":{
            "status":"enabled"
        },
        "Policy Compliance":{
            "status":"enabled"
        },
        "Amazon Linux Local Security Checks":{
            "status":"enabled"
        },
        "Solaris Local Security Checks":{
            "status":"enabled"
        },
        "F5 Networks Local Security Checks":{
            "status":"enabled"
        },
        "Denial of Service":{
            "status":"enabled"
        },
        "Windows : Microsoft Bulletins":{
            "status":"enabled"
        },
        "SuSE Local Security Checks":{
            "status":"enabled"
        },
        "Palo Alto Local Security Checks":{
            "status":"enabled"
        },
        "Red Hat Local Security Checks":{
            "status":"enabled"
        },
        "PhotonOS Local Security Checks":{
            "status":"enabled"
        },
        "HP-UX Local Security Checks":{
            "status":"enabled"
        },
        "CGI abuses : XSS":{
            "status":"enabled"
        },
        "FreeBSD Local Security Checks":{
            "status":"enabled"
        },
        "Windows":{
            "status":"enabled"
        },
        "Scientific Linux Local Security Checks":{
            "status":"enabled"
        },
        "MacOS X Local Security Checks":{
            "status":"enabled"
        },
        "Web Servers":{
            "status":"enabled"
        },
        "SCADA":{
            "status":"enabled"
        }
    }
    #credentials中 设置了ssh扫描的登录账号和密码
    credentials={
        "add":{
            "Host":{
                "SSH":[
                    {
                        "auth_method":"password",
                        "username":"{}".format(ssh_username),
                        "password":"{}".format(ssh_password),
                        "elevate_privileges_with":"Nothing",
                        "custom_password_prompt":""
                    }
                ]
            }
        },
        "edit":{

        },
        "delete":[

        ]
    }
    settings={
        "patch_audit_over_telnet":"no",
        "patch_audit_over_rsh":"no",
        "patch_audit_over_rexec":"no",
        "snmp_port":"161",
        "additional_snmp_port1":"161",
        "additional_snmp_port2":"161",
        "additional_snmp_port3":"161",
        "http_login_method":"POST",
        "http_reauth_delay":"",
        "http_login_max_redir":"0",
        "http_login_invert_auth_regex":"no",
        "http_login_auth_regex_on_headers":"no",
        "http_login_auth_regex_nocase":"no",
        "never_send_win_creds_in_the_clear":"yes",
        "dont_use_ntlmv1":"yes",
        "start_remote_registry":"no",
        "enable_admin_shares":"no",
        "ssh_known_hosts":"",
        "ssh_port":"22",
        "ssh_client_banner":"OpenSSH_5.0",
        "attempt_least_privilege":"no",
        "region_dfw_pref_name":"yes",
        "region_ord_pref_name":"yes",
        "region_iad_pref_name":"yes",
        "region_lon_pref_name":"yes",
        "region_syd_pref_name":"yes",
        "region_hkg_pref_name":"yes",
        "microsoft_azure_subscriptions_ids":"",
        "aws_ui_region_type":"Rest of the World",
        "aws_us_east_1":"",
        "aws_us_east_2":"",
        "aws_us_west_1":"",
        "aws_us_west_2":"",
        "aws_ca_central_1":"",
        "aws_eu_west_1":"",
        "aws_eu_west_2":"",
        "aws_eu_west_3":"",
        "aws_eu_central_1":"",
        "aws_eu_north_1":"",
        "aws_ap_east_1":"",
        "aws_ap_northeast_1":"",
        "aws_ap_northeast_2":"",
        "aws_ap_northeast_3":"",
        "aws_ap_southeast_1":"",
        "aws_ap_southeast_2":"",
        "aws_ap_south_1":"",
        "aws_me_south_1":"",
        "aws_sa_east_1":"",
        "aws_use_https":"yes",
        "aws_verify_ssl":"yes",
        "log_whole_attack":"no",
        "enable_plugin_debugging":"no",
        "audit_trail":"use_scanner_default",
        "include_kb":"use_scanner_default",
        "enable_plugin_list":"no",
        "custom_find_filepath_exclusions":"",
        "custom_find_filesystem_exclusions":"",
        "reduce_connections_on_congestion":"no",
        "network_receive_timeout":"5",
        "max_checks_per_host":"5",
        "max_hosts_per_scan":"30",
        "max_simult_tcp_sessions_per_host":"",
        "max_simult_tcp_sessions_per_scan":"",
        "safe_checks":"yes",
        "stop_scan_on_disconnect":"no",
        "slice_network_addresses":"no",
        "allow_post_scan_editing":"yes",
        "reverse_lookup":"no",
        "log_live_hosts":"no",
        "display_unreachable_hosts":"no",
        "display_unicode_characters":"no",
        "report_verbosity":"Normal",
        "report_superseded_patches":"yes",
        "silent_dependencies":"yes",
        "scan_malware":"no",
        "samr_enumeration":"yes",
        "adsi_query":"yes",
        "wmi_query":"yes",
        "rid_brute_forcing":"no",
        "request_windows_domain_info":"no",
        "scan_webapps":"no",
        "test_default_oracle_accounts":"no",
        "provided_creds_only":"yes",
        "smtp_domain":"example.com",
        "smtp_from":"nobody@example.com",
        "smtp_to":"postmaster@[AUTO_REPLACED_IP]",
        "av_grace_period":"0",
        "report_paranoia":"Normal",
        "thorough_tests":"no",
        "svc_detection_on_all_ports":"yes",
        "detect_ssl":"yes",
        "ssl_prob_ports":"Known SSL ports",
        "cert_expiry_warning_days":"60",
        "enumerate_all_ciphers":"yes",
        "check_crl":"no",
        "tcp_scanner":"no",
        "tcp_firewall_detection":"Automatic (normal)",
        "syn_scanner":"yes",
        "syn_firewall_detection":"Automatic (normal)",
        "udp_scanner":"no",
        "ssh_netstat_scanner":"yes",
        "wmi_netstat_scanner":"yes",
        "snmp_scanner":"yes",
        "only_portscan_if_enum_failed":"yes",
        "verify_open_ports":"no",
        "unscanned_closed":"no",
        "portscan_range":"default",
        "wol_mac_addresses":"",
        "wol_wait_time":"5",
        "scan_network_printers":"no",
        "scan_netware_hosts":"no",
        "scan_ot_devices":"no",
        "ping_the_remote_host":"yes",
        "arp_ping":"yes",
        "tcp_ping":"yes",
        "tcp_ping_dest_ports":"built-in",
        "icmp_ping":"yes",
        "icmp_unreach_means_host_down":"no",
        "icmp_ping_retries":"2",
        "udp_ping":"no",
        "test_local_nessus_host":"yes",
        "fast_network_discovery":"no",
        "name":"通用ssh",
        "description":""
    }
    data={
            "uuid": uuid,
            "settings": settings,
            "plugins": plugins,
            "credentials": credentials
          }
    url = nessus_url+"/policies"
    response = requests.post(url=url, headers=header, data=json.dumps(data, ensure_ascii=False).encode("utf-8"), # 这里做一个转码防止在nessus端发生中文乱码
                             verify=False)
    print(response.text)
    if response.status_code == 200:
        data = response.json()
        return data["policy_id"] # 返回策略模板的id，后续可以在创建任务时使用
    else:
        return None

def create_task():
    '''

    创建扫描任务，立即执行
    :return:
    '''
    #创建自定义策略，获取策略id
    policy_id=create_template()
    logger.info('创建自定义扫描策略成功......')
    #获取自定义策略的uuid
    uuid = get_nessus_template_uuid(template_name='custom')
    logger.info("自定义uuid={}".format(uuid))
    data=    {
        "uuid": uuid,
        "settings": {
            "name": 'ceshi',
            "enabled": False,
            "launch_now": True,
            "policy_id": policy_id,
            "text_targets": hosts,

        }
    }
    url = nessus_url+"/scans"
    response = requests.post(url=url, headers=header, data=json.dumps(data),verify=False)
    if response.status_code == 200:
        data = response.json()
        if data["scan"] is not None:
            scan = data["scan"]
            # 新增任务扩展信息记录
            return scan["id"]  # 返回任务id

def get_scan_status():
    '''
    获取扫描状态status,获取host_id,hostname
    :return:
    '''
    # scan_id=create_task()
    logger.info('任务创建成功，正在执行扫描')
    # print(type(scan_id))
    scan_id = 18
    url=nessus_url+'/scans/{}'.format(scan_id)
    while True:
        response = requests.get(url, headers=header, verify=False).json()
        scan_status = response['info']['status']
        if scan_status == 'completed':
            logger.info('扫描已完成，正在获取扫描结果')
            # print(response['vulnerabilities'])
            plugin_id_list = []
            for vlun in response['vulnerabilities']:
                if vlun['severity'] >= int(risk_level):
                    plugin_id_list.append(vlun['plugin_id'])

            # for i in response['hosts']:
            #     host_dict={'host_id':i['host_id'],'hostname':i['hostname']}
            #     host_id_list.append(host_dict)
                # print(response.json()['hosts'][0]['host_id'])
                # print(response.json()['hosts'][0]['hostname'])
            return plugin_id_list,scan_id

        else:
            logger.info('扫描状态{}，请等待'.format(scan_status))
            time.sleep(180)
def get_scan_result():
    '''
    提取扫描结果，只提取低风险及以上的漏洞，info级别的丢弃
    :return:
    '''
    plugin_id,scan_id=get_scan_status()

    logger.info('plugin_id:{}'.format(plugin_id))
    logger.info('scan_id:{}'.format(scan_id))

    vlun_result_list=[]
    for plugin_id in plugin_id:
        url=nessus_url+'/scans/{}/plugins/{}'.format(scan_id,plugin_id)
        response = requests.get(url, headers=header, verify=False).json()
        vlun_name=response['info']['plugindescription']['pluginname']
        vlun_description=response['info']['plugindescription']['pluginattributes']['description']
        vlun_output=response['outputs'][0]['plugin_output']
        vlun_result={'漏洞名称':vlun_name,'漏洞描述':vlun_description,'漏洞建议':vlun_output}
        vlun_result_list.append(vlun_result)
    return vlun_result_list
    # vlun_dict={}
    # for host_id in host_id_list:
    #     url=nessus_url+'/scans/{}/hosts/{}'.format(scan_id,host_id['host_id'])
    #     response = requests.get(url, headers=header, verify=False).json()
    #     vlun_list=[]
    #     for vlun in response['vulnerabilities']:
    #         if vlun['severity']> 0:
    #             vlun_list.append(vlun)
    #     vlun_dict[host_id['hostname']]=vlun_list
    # print(vlun_dict)
    # pass
def vuln_jira():
    a=get_scan_result()
    url = "http://jira.chinac.com/rest/api/2/issue/bulk"
    auth = HTTPBasicAuth(jira_username,jira_password)
    jira_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    payloadlist=[]
    for i in a:
        ta={'fields': {
            "summary": "【{}】【安全测试】{}".format(project_name, i['漏洞名称']),
            "issuetype": {"id": "10104"},
            "project": {"id": "{}".format(projetc_id)},
            "customfield_10731": "【漏洞描述】\n{}\n【修复建议】{}".format(i['漏洞描述'], i['漏洞建议']),
            "environment": "{}".format(hosts),
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


if __name__=='__main__':
    accessKey = global_config.getRaw('nessus', 'accessKey')
    secretKey = global_config.getRaw('nessus', 'secretKey')
    nessus_url = global_config.getRaw('nessus', 'nessus_url')

    header = {
        'X-ApiKeys': 'accessKey={accesskey};secretKey={secretkey}'.format(accesskey=accessKey, secretkey=secretKey),
        "Content-Type": "application/json"
    }
    hosts = global_config.getRaw('nessus', 'hosts')
    ssh_username=global_config.getRaw('nessus', 'ssh_username')
    ssh_password=global_config.getRaw('nessus', 'ssh_password')
    risk_level=global_config.getRaw('nessus', 'risk_level')
    project_name=global_config.getRaw('jira', 'projetc_name')
    projetc_id=global_config.getRaw('jira', 'projetc_id')
    affect_versions=global_config.getRaw('jira', 'affect_versions')
    jira_username=global_config.getRaw('jira', 'jira_username')
    jira_password=global_config.getRaw('jira', 'jira_password')
    assignee=global_config.getRaw('jira', 'assignee')
    # hosts = '10.51.30.34'
    # host_id_list=[]
    vuln_jira()


