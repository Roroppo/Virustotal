import json as _json  
import urllib.request, urllib.parse, urllib.error  
import urllib.request, urllib.error, urllib.parse  
import sys  
import time   
import mysql.connector  
import datetime  
import pprint  

from urllib.request import Request, urlopen  

#Apikeyを設定  
class Apikey:  
def __init__(self):  
#database接続  
self.connect = mysql.connector.connect(user='root', password='', host='localhost', database='kaiseki_development', charset='utf8')  
self.connect.autocommit = True  
self.cursor = self.connect.cursor()  
self.cursor.execute('use kaiseki_development')  

#virustotal_api_keysの中身を空に  
self.cursor.execute('truncate table virustotal_api_keys')  
#apikey  
def set_apikeys(self):  
apikeys = [ apikeyが入ってます。]   

for n in range(len(apikeys)):  
#table virustotal_api_keysのapi_key,use_time,use_numbers,created_at,updated_atに追加      
self.cursor.execute('insert into virustotal_api_keys(api_key,use_time,use_numbers,created_at,updated_at) values(%s,now(),0,now(),now())' % (apikeys[n]))  



#Analysisを設定  
class Analysis:  
def __init__(self,analysis_id):  
#database接続  
self.connect = mysql.connector.connect(user='root', password='', host='localhost', database='kaiseki_development', charset='utf8')  
self.connect.autocommit = True  
self.cursor = self.connect.cursor(buffered=True)  
self.analysis_id = analysis_id  
self.cursor.execute('use kaiseki_development')  



self.analyse_url = "https://www.virustotal.com/vtapi/v2/url/scan"  

def virustotal(self):  

self.url = str(self.cursor.execute('select short_url from short_urls where id = + %d' % (self.analysis_id)))  
#現在の時間  
now = datetime.datetime.now()  

self.cursor.execute('select Max(id) from virustotal_api_keys')  

record = self.cursor.fetchone()  

mMax = record[0]  

#idの最大値をVirustotal_api_keysから取得  
for m in range(mMax):  

#now.minuteとuse_timeが一緒  
self.cursor.execute('select use_time from virustotal_api_keys where id = %d' % (m+1))  


if str(now.minute) == str(record[0]):  

#この分に使った回数が4回かrecord = self.cousor.fetchone()  
self.cursor.execute('select use_numbers from virustotal_api_keys where id = %d ' % (m+1))  
record = self.cursor.fetchone()  

if int(record[0]) == 4:  

#今見ているidが最大値を満たしているか  
if m + 1 == mMax:   
time.sleep(60)  
#sleepしたらidの探索を元に戻す  
m = -1  
continue  
else: break   
else:  
self.cursor.execute('update virustotal_api_keys set use_numbers = 0 where id = %d' % (m+1))          
break           

self.cursor.execute('select api_key from virustotal_api_keys where id = %d' % (m+1));  
record = self.cursor.fetchone()  
self.apikey = str(record[0])      
self.__calc()  
#table virustotal_api_keysのuse_time,use_numbersにnow,use_number+1をして格納  
self.cursor.execute('update virustotal_api_keys set use_time = now(),use_numbers = use_numbers + 1 where id = %d' % (m+1))  

def __calc(self):  

targeturl = self.url  
url = self.analyse_url  
apikey = self.apikey  


parameters = urllib.parse.urlencode({"apikey": apikey,"targeturl": self.url}).encode("utf-8")  

response = urllib.request.urlopen("https://www.virustotal.com/vtapi/v2/url/scan", data=parameters)  

json = _json.loads(response.read().decode('utf-8'))  

pprint.pprint(json)  
if not json:  
print("Error in calling /url/scan API")  
return 3  

scan_id = json["scan_id"]  

print("Wait 10 seconds...")  
time.sleep(10)  

print("Waiting response 'GET /url/report'")  

query = urllib.parse.urlencode({"apikey": self.apikey, "resource": scan_id})  

response = urllib.request.urlopen("https://www.virustotal.com/vtapi/v2/url/report?" + query)  

json = _json.loads(response.read().decode('utf-8'))  

pprint.pprint(json)  

#print (["positives"])  

if not json:  
print("Error in calling /url/report API")  
return 4  

return 0  

if __name__ == "__main__":  
sys.exit(main())          
#print (["positives"])  
#m2 = "url"      
#print(decjson["m2"])  

#self.cursor.execute('update analysis_results set search_time =now(), analysis_result = %s, updated_at =now()' % str(decjson ["positives"]))  
