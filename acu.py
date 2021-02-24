
# make user in acunetix : tool@tool.com sdsdgQ@SFGSDg00
# make this tool use request post with option logout when run to get session_cookie :)
# now you dont need to set cookie when run tool everyday

# what is new ? 
# will send request authentication sites with mail and password 

import time
import re
import requests
import urllib3 
import argparse
from concurrent.futures import ThreadPoolExecutor as PoolExecutor
from sys import exit


#======================= Start Arguments ====================
# arguments
parser_arg_menu = argparse.ArgumentParser(prog='tool', formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=40)
)
parser_arg_menu.add_argument(
"-u" , "--urls" , help="File contain urls Ex: urls.txt",
metavar=""
)
parser_arg_menu.add_argument(
"-t", "--threads" , help="Thread number to MultiProccess [speed tool] , Default 1",
metavar=""
)
parser_arg_menu.add_argument(
"-s", "--sleep" , help="sleep after every request",
metavar=""
)
parser_arg_menu.add_argument(
"-c", "--cookie" , help="set cookie acunetix here",
metavar=""
)
parser_arg_menu.add_argument(
"-S", "--session" , help="set session_scan acunetix here [in post request when scan (ui_session_id)]",
metavar=""
)

arg_menu    = parser_arg_menu.parse_args()
max_threads = int(arg_menu.threads) if arg_menu.threads else int(1)
max_sleep   = int(arg_menu.sleep) if arg_menu.sleep else int(3)

#======================= End Arguments  =====================

# configrations 


acunetix_api_add   = 'https://localhost:3443/api/v1/targets/add'
acunetix_api_scan  = 'https://localhost:3443/api/v1/scans'
session_scan       = 'b955efc1173dce50fe90c0d61ad94553'
default_cookie     = "208c95209efb44a7ab835f73d73fd6949603459ebaf8fd24ef676433fac7134386d4826351e683e15d98d7a9b0963ce1a6052d9a20f8eafa7a259cd7f825879bf"
cookie             = str(arg_menu.cookie) if arg_menu.cookie else default_cookie
headerss = {
    'Host': 'localhost:3443',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'x-auth': '{}'.format(cookie),
    'Content-Type': 'application/json',
    'Content-Length': '124',
    'Origin': 'https://localhost:3443',
    'Connection': 'close',
    'Referer': 'https://localhost:3443/',
    'Cookie': 'ui_session={}'.format(cookie)
    }

proxy = {"http": "http://127.0.0.1:8080", 
         "https": "http://127.0.0.1:8080"}

urllib3.disable_warnings()


def run(single_url):
    

    # add target request
    try:
        single_url = single_url.strip()
        data1 = '{"targets":[{"address":"'+single_url+'","description":""}],"groups":[]}'
        response1 = requests.post(acunetix_api_add, headers=headerss, data=data1, verify=False)

        headerss3 = {
            'Host': 'localhost:3443',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Referer': 'https://localhost:3443/',
            'x-auth': '{}'.format(cookie),
            'Content-Type': 'application/json',
            'Content-Length': '596',
            'Connection': 'close',
            'Cookie': 'ui_session=' '{}'.format(cookie)
            }

        try:
            pattern   = re.compile("target_id(.*)")
            target_id = pattern.findall(str(response1.content))[0][4:40]

            x = '{"scan_speed":"fast","login":{"kind":"automatic","credentials":{"enabled":true,"username":"test","password":"test2"}},"ssh_credentials":{"kind":"none"},"default_scanning_profile_id":"11111111-1111-1111-1111-111111111111","sensor":false,"case_sensitive":"auto","limit_crawler_scope":true,"excluded_paths":[],"authentication":{"enabled":false},"proxy":{"enabled":false},"technologies":[],"custom_headers":[],"custom_cookies":[],"debug":false,"restrict_scans_to_import_files":false,"client_certificate_password":"","user_agent":"","client_certificate_url":null,"issue_tracker_id":"","excluded_hours_id":""}'

            a = requests.patch('https://localhost:3443/api/v1/targets/'+target_id+'/configuration', headers=headerss3, data=x, verify=False)
        except Exception as er:
            print('error 1 \n'+er)
            

        # scan target request
        try:
            pattern   = re.compile("target_id(.*)")
            target_id = pattern.findall(str(response1.content))[0][4:40]
            data2 = '{"profile_id":"11111111-1111-1111-1111-111111111111","ui_session_id":"'+session_scan+'","incremental":false,"schedule":{"disable":false,"start_date":null,"time_sensitive":false},"target_id":"'+target_id+'"}' 
            response2 = requests.post(acunetix_api_scan, headers=headerss, data=data2, verify=False)
        except Exception as er:
            print('error 2 \n'+er)


        # print in screen
        if response1.status_code == 200:
            response2_check = '-scan' if int(response2.status_code) == 200 or 201 else ''
            print('[add' + response2_check + '] ' + single_url)
        else:
            print('error: ' + single_url)
        
    except Exception as er:
        print('error 3 \n'+er)
        
    time.sleep(max_sleep)
        

        


if __name__ == "__main__":

    if not arg_menu.urls:
        print("-urls needed")
        exit(1)


    with open(arg_menu.urls, 'r') as f:
        urls_list = [line.rstrip() for line in f]

    with PoolExecutor(max_workers=max_threads) as executor:
        for _ in executor.map(run, urls_list):
            pass




'''
# code to store session in variable.
login = 'https://localhost:3443/api/v1/me/login'
creds = '{"email":"at7@at7.com","password":"b505a356fa385754103b09b73cd574c89196c96e1d801cba7bff4a6d1d6023e8","remember_me":false,"logout_previous":true}'
login_headers = {
    'Host': 'localhost:3443',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/json',
    'Content-Length': '121',
    'Origin': 'https://localhost:3443',
    'Connection': 'close',
    'Referer': 'https://localhost:3443/'
    }
    
session = requests.Session()
response = session.post(login, data=creds, headers=headerss_login,  verify=False)
print(response.status_code)
session_now = session.cookies.get_dict()
print(session_now)
'''