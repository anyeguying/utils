import base64
import datetime
import hashlib
import json
import os
import random
import sys
import threading
import time

import requests
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


def printf(text):
    ti = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    print(f'[{ti}]: {text}')
    sys.stdout.flush()

def desEn(content, key):
    key = key[:8].encode('utf-8')
    content = content.encode('utf-8')
    cipher = DES.new(key=key, mode=DES.MODE_ECB)
    content = pad(content, block_size=DES.block_size, style='pkcs7')
    res = cipher.encrypt(content)
    return base64.b64encode(res)

def desDe(content, key):
    key = key[:8].encode('utf-8')
    content = base64.b64decode(content)
    cipher = DES.new(key=key, mode=DES.MODE_ECB)
    res = cipher.decrypt(content)
    res = unpad(res, DES.block_size, style='pkcs7')
    return res.decode('utf-8')

def generate_random_str(randomlength=16):
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'
    length = len(base_str) - 1
    for i in range(randomlength):
        random_str += base_str[random.randint(0, length)]
    return random_str

def getTimestamp():
    return int(round(time.time() * 1000))

def rcape(v):
    if len(v) != 2:
        return '0'+v
    return v

def getJsonId():
    global start_time
    url = 'https://gz-cdn.xiaoyisz.com/mengniu_bainai/game_configs/prod_v1/game_configs.json?v=1670228082180'
     
    res = requests.get(url=url, headers=head).json()
    month = datetime.datetime.now().strftime('%m')
    day = datetime.datetime.now().strftime('%d')
    day = rcape(str(int(day) - 1))

    for item in res['activity_data']:
        result_id = item['result_id']
        result_id = result_id.replace('result_', '')
        json_id = item['json_id']
        if result_id == (month+day):
            reward_Num = item['reward_Num']
            start_time = item['start_time']
            printf(f'今日可抢牛奶数量：{reward_Num}')
            return json_id
    return ''

def getRKSign(timestamp, nonce):
    md5Str = f'clientKey={clientKey}&clientSecret={clientSecret}&nonce={nonce}&timestamp={timestamp}'
    return hashlib.md5(md5Str.encode('utf-8')).hexdigest().upper()

def getRk(token):
    timestamp = getTimestamp()
    nonce = generate_random_str(16)
    sign = getRKSign(timestamp, nonce)
    url = f'{domain}/mengniu-world-cup/mp/api/user/baseInfo?timestamp={timestamp}&nonce={nonce}&signature={sign}'
    head['Authorization'] = token
    res = requests.get(url=url, headers=head).json()
    printf(res)
    try:
        return res['data']['rk']
    except Exception:
        raise Exception('获取账号rk失败，该token已经触发风控机制，请重新抓包获取新token')

def getMilkSign(requestId, timestamp, rk):
    md5Str = f'requestId={requestId}&timestamp={timestamp}&key={rk}'
    return hashlib.md5(md5Str.encode('utf-8')).hexdigest()

def skillMilk(token,rk, jsonId):
    timestamp = getTimestamp()
    requestId = generate_random_str(32)
    nonce = generate_random_str(16)
    signature = getRKSign(timestamp, nonce)
    sign = getMilkSign(requestId, timestamp, rk)
    url = f'{domain}/mengniu-world-cup-1122{updateUrl}?timestamp={timestamp}&nonce={nonce}&signature={signature}&jsonId={jsonId}'
    head['sign'] = sign
    head['timestamp'] = str(timestamp)
    head['requestId'] = requestId
    head['Authorization'] = token
    res = requests.get(url=url, headers=head,timeout=5).text
    printf(res)

def isStart():
    timestamp = getTimestamp()
    current_time = getTimestamp()
    if current_time >= (start_time - preTime):
        return True
    else:
        return False

def qiangnai(token,rk, jsonId):
        while True:
            if isStart():
                for i in range(threadNumber):
                    try:
                        skillMilk(token,rk, jsonId)
                    except Exception as e:
                        printf(f'抢奶异常：{str(e)}')
                time.sleep(0.1)
                break
            else:
                printf("等待开始...")
                time.sleep(0.5)

if __name__ == '__main__':
    try:
        with open('./mn.json', 'r') as c:
            rdConfigStr = c.read()
        config = json.loads(rdConfigStr)
    except Exception as e:
        printf(f'加载配置文件异常：{str(e)}')
        os.system('pause')

    '''
    time无需管 服务器获取
    '''
    start_time = 0
    domain = config['domain']

    '''
    token是小程序包的请求头的Authorization: 
    '''
    token = config['token']
    desKey = config['desKey']
    clientKey = config['clientKey']
    clientSecret = config['clientSecret']
    updateUrl = config['updateUrl']
    '''
    请求头
    '''
    head = {
        'User-Agent': config['User-Agent'],
        'Referer': config['Referer'],
        'content-type': 'application/json',
    }

    global threadNumber 

    threadNumber = config['threadNumber']
    preTime = config['preTime']

    jsonId = getJsonId()
    time.sleep(1)
    tokensRk=[]
    f = open("./tk.txt","r")  
    lines = f.readlines()#读取全部内容  

    for line in lines:
        token=line.strip()
        rk=getRk(token)
        rk = desDe(rk, desKey)
        tkr={"token":token, "rk":rk}
        tokensRk.append(tkr)
    
    for tkr in tokensRk:
        t = threading.Thread(target=qiangnai, args=(tkr["token"], tkr["rk"],jsonId))
        t.start()
  
  
    os.system('pause')


