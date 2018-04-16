import yaml
import requests
import datetime
import os
import json
import sys
from pprint import pprint

path = os.environ["WORKDIR"]
with open(path + "/lookup_plugins/virustotal/dnifconfig.yml", 'r') as ymlfile:
    cfg = yaml.load(ymlfile)


def execute():
    print "hello the world!"


def check_config():
    print cfg['lookup_plugin']['VT_API_KEY']


def get_url_report(inward_array,var_array):
    # https://www.virustotal.com/en/documentation/public-api/
    for i in inward_array:
        if var_array[0] in i:
            headers = {
              "Accept-Encoding": "gzip, deflate",
              "User-Agent": "gzip,  My Python requests library example client or username"
            }
            params = {'apikey': cfg['lookup_plugin']['VT_API_KEY'], 'resource':str(i[var_array[0]]),'scan':1,'allinfo':True}
            try:
                response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
                    params=params, headers=headers)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                if json_response['resource'] != '':
                    i['$VTURL'] = json_response['resource']
            except Exception:
                pass
            try:
                i['$VTPermalink'] = json_response['permalink']
            except Exception:
                pass
            try:
                i['$VTPositives'] = json_response['positives']
            except Exception:
                i['$VTPositives'] = 0
            try:
                i['$VTResponseCode'] = json_response['response_code']
            except Exception:
                i['$VTResponseCode'] = 0
            try:
                i['$VTTotal'] = json_response['total']
            except Exception:
                pass
            try:
                i['$VTSystemTstamp'] = datetime.datetime.strptime(json_response['scan_date'],
                                                               '%Y-%m-%d %H:%M:%S').isoformat()
            except Exception:
                pass
            try:
                arr_true = []
                arr_false = []
                c = {}
                c = json_response['scans']
                for key in c:
                    if (c[key]["detected"] == True):
                        arr_true.append(key)
                    else:
                        arr_false.append(key)
                if len(arr_true) > 0:
                    i['$VTPositive'] = arr_true
                if len(arr_false) >0:
                    i['$VTNegative'] = arr_false
            except Exception:
                pass
            try:
                i['$VTMessage'] = json_response['verbose_msg']
            except Exception:
                pass
            try:
                i['$VTScanID'] = json_response['scan_id']
            except Exception:
                pass
    return inward_array


def get_domain_report(inward_array,var_array):
    # https://www.virustotal.com/en/documentation/public-api/
    #need to configure whois data output
    for i in inward_array:
        if var_array[0] in i:
            headers = {
              "Accept-Encoding": "gzip, deflate",
              "User-Agent": "gzip,  My Python requests library example client or username"
            }
            params = {'apikey': cfg['lookup_plugin']['VT_API_KEY'], 'domain':str(i[var_array[0]])}
            try:
                response = requests.get('https://www.virustotal.com/vtapi/v2/domain/report',
                    params=params, headers=headers)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$VTResponseCode'] = json_response['response_code']
            except Exception:
                i['$VTResponseCode'] = 0
            try:
                i['$VTCategories'] = json_response['categories']
            except Exception:
                pass
            try:
                if json_response['Websense ThreatSeeker category'] !=[]:
                    i['$VTWebsenseThreatSeekercategory'] = json_response['Websense ThreatSeeker category']
            except Exception:
                pass
            try:
                if json_response['domain_siblings'] !=[]:
                    i['$VTDomainList'] = json_response['domain_siblings']
            except Exception:
                pass
            try:
                if json_response['subdomains'] !=[]:
                    i['$VTSubDomainList'] = json_response['subdomains']
            except Exception:
                pass
            try:
                url = []
                for b in json_response['detected_urls']:
                    url.append(b['url'])
                if url != []:
                    i['$VTURL'] = url
            except Exception:
                pass
            try:
                i['$VTSiteClass'] = json_response['categories']
            except Exception:
                pass
            try:
                i['$VTWebutationVerdict'] = json_response['Webutation domain info']['Verdict']
            except Exception:
                pass
            try:
                i['$VTWebutationSafetyScore'] = json_response['Webutation domain info']['Safety score']
            except Exception:
                pass
            try:
                i['$VTForcepointThreatSeekerCategory'] = json_response['Forcepoint ThreatSeeker category']
            except:
                pass
            try:
                res = []
                for a in json_response['resolutions']:
                    res.append(a['ip_address'])
                i['$VTPassiveDNSReplication'] = res
            except Exception:
                pass
            try:
                i['$VTWHOIS'] = json_response['whois']
            except Exception:
                pass
    return inward_array


def get_ip_report(inward_array,var_array):
    # https://www.virustotal.com/en/documentation/public-api/
    for i in inward_array:
        if var_array[0] in i:
            headers = {
              "Accept-Encoding": "gzip, deflate",
              "User-Agent": "gzip,  My Python requests library example client or username"
            }
            params = {'apikey': cfg['lookup_plugin']['VT_API_KEY'], 'ip':str(i[var_array[0]])}
            try:
                response = requests.get('https://www.virustotal.com/vtapi/v2/ip-address/report',
                                        params=params, headers=headers)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$VTResponseCode'] = json_response['response_code']
            except Exception:
                i['$VTResponseCode'] = 0
            try:
                i['$VTOwner'] = json_response['as_owner']
            except Exception:
                pass
            try:
                arr_url = []
                b = json_response['detected_urls']
                for j in range(len(b)):
                    arr_url.append(b[j]["url"])
                i['$VTURL'] = arr_url
            except Exception:
                pass
            try:
                arr_res = []
                c = json_response['resolutions']
                for k in range(len(c)):
                    arr_res.append(c[k]["hostname"])
                i['$VTPassiveDNSReplication'] = arr_res
            except Exception:
                pass
            try:
                com_samp= []
                cs = json_response['detected_communicating_samples']
                for csamp in range(len(cs)):
                    com_samp.append(cs[csamp]['sha256'])
                i['$VTCommunicatingSamples'] = com_samp
            except Exception:
                pass
            try:
                down_samp= []
                ds = json_response['detected_downloaded_samples']
                for dsamp in range(len(ds)):
                    down_samp.append(ds[dsamp]['sha256'])
                i['$VTDownloadedSamples'] = down_samp
            except Exception:
                pass
            try:
                i['$VTASN'] = json_response['asn']
            except Exception:
                pass
            try:
                i['$VTCN'] = json_response['country']
            except:
                pass

    return inward_array


def get_filehash_report(inward_array,var_array):
    # https://www.virustotal.com/en/documentation/public-api/
    for i in inward_array:
        if var_array[0] in i:
            headers = {
              "Accept-Encoding": "gzip, deflate",
              "User-Agent": "gzip,  My Python requests library example client or username"
            }
            params = {'apikey': cfg['lookup_plugin']['VT_API_KEY'], 'resource':str(i[var_array[0]]),'allinfo':True}
            try:
                response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                          params=params, headers=headers)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$VTmd5'] = json_response['md5']
            except Exception:
                pass
            try:
                i['$VTsha1'] = json_response['sha1']
            except Exception:
                pass
            try:
                i['$VTsha256'] = json_response['sha256']
            except Exception:
                pass
            try:
                i['$VTPermalink'] = json_response['permalink']
            except Exception:
                pass
            try:
                i['$VTPositives'] = json_response['positives']
            except Exception:
                i['$VTPositives']=0
            try:
                i['$VTResponseCode'] = json_response['response_code']
            except Exception:
                i['$VTResponseCode'] = 0
            try:
                i['$VTTotal'] = json_response['total']
            except Exception:
                pass
            try:
                i['$VTScanID'] = json_response['scan_id']
            except Exception:
                pass
            try:
                i['$VTSystemTstamp'] = datetime.datetime.strptime(json_response['scan_date'],
                                                               '%Y-%m-%d %H:%M:%S').isoformat()
            except Exception:
                pass
            try:
                arr_true = []
                arr_false = []
                c = {}
                c = json_response['scans']
                for key in c:
                    if (c[key]["detected"] == True):
                        arr_true.append(key)
                    else:
                        arr_false.append(key)
                if len(arr_true)>0:
                    i['$VTPositives'] = arr_true
                if len(arr_false)>0:
                    i['$VTNegative'] = arr_false
            except Exception, e:
                pass
    return inward_array


def post_scan_url(inward_array, var_array):
    for i in inward_array:
        if var_array[0] in i:
            headers = {
              "Accept-Encoding": "gzip, deflate",
              "User-Agent": "gzip,  My Python requests library example client or username"
            }
            params = {'apikey':cfg['lookup_plugin']['VT_API_KEY'], 'url': str(i[var_array[0]]) }
            try:
                response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan',
                                         data=params,headers=headers)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' %e
            try:
                i['$VTURL'] = json_response['url']
                i['$VTScanID'] = json_response['scan_id']
                i['$VTPermalink'] = json_response['permalink']
                i['$VTResponseCode'] = json_response['response_code']
                i['$VTSystemTstamp'] = datetime.datetime.strptime(json_response['scan_date'],
                                                               '%Y-%m-%d %H:%M:%S').isoformat()
                i['$VTMessage'] = json_response['verbose_msg']
            except Exception, e:
                i['$VTResponseCode'] = 0
    return inward_array

