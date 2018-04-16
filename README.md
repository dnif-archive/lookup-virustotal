## VirusTotal   
  https://www.virustotal.com/#/home/url

### Overview
VirusTotal inspects items with over 70 antivirus scanners and URL/domain blacklisting services, in addition to a myriad of tools to extract signals from the studied content
##### Real-time updates
Malware signatures are updated frequently by VirusTotal as they are distributed by antivirus companies, this ensures that our service uses the latest signature sets.
Website scanning is done in some cases by querying vendor databases that have been shared with VirusTotal and stored on our premises and
in other cases by API queries to an antivirus company's solution. As such, as soon as a given contributor blacklists a URL it is immediately reflected in user-facing verdicts.
##### Detailed results
VirusTotal not only tells you whether a given antivirus solution detected a submitted file as malicious, but also displays each engine's detection label (e.g., I-Worm.Allaple.gen).
The same is true for URL scanners, most of which will discriminate between malware sites, phishing sites, suspicious sites, etc. 
Some engines will provide additional information, stating explicitly whether a given URL belongs to a particular botnet, which brand is targeted by a given phishing site, and so on.
 
##### Lookups integrated with VirusTotal

##### Retrieve URL scan reports  
The URL for which you want to retrieve the most recent report
- input : A URL for which VirusTotal will retrieve the most recent report on the given URL.
          You may also specify a scan_id (sha256-timestamp as returned by the URL submission API) to access a specific                 report.
```
_fetch $Url from threatsample limit 1
>>_lookup virustotal get_url_report $Url
```
###### Sample Output 
![url_report](https://user-images.githubusercontent.com/37173181/38144498-8e1ade20-3462-11e8-8e80-a56457a149dc.jpg)


The Lookup call returns output in the following structure for available data

  | Fields        | Description  |
|:------------- |:-------------|
| $VTURL      | URL being queried |
| $VTPermalink      | Permalink of report stored in VirusTotal |
| $VTPositive | List of scans returning positive detection |
| $VTNegative | List of scans returning negative detection |
| $VTPositives | Count of positive detection |
| $VTResponseCode | If the queried url is present in VirusTotal database it returns 1 ,if absent returns 0 and if the requested item is still queued for analysis it will be -2 |
| $VTTotal | Count of positive and negative detections |
| $VTSystemTstamp | Scan Date |

 If the queried url is not present in VirusTotal Data base the lookup call returns the following

 | Fields        | Description  |
|:------------- |:-------------|
| $VTURL      | URL being queried |
| $VTPermalink      | Permalink of report stored in VirusTotal |
| $VTResponseCode | If the queried url is present in VirusTotal database it returns 1 ,if absent returns 0 and if the requested item is still queued for analysis it will be -2 |
| $VTTotal | Count of positive and negative detections |
| $VTSystemTstamp | Scan Date |
| $VTMessage | Verbose message of url being successfully queued up for scan |
| $VTScanID | Provides a scan id which can be later used for quering the report |


#####  Retrieve Domain reports
The domain for which you want to retrieve the report
- input : a domain name.

```
_fetch $Domain from threatsample limit 1
>>_lookup virustotal get_domain_report $Domain
```

##### Sample Output 
  ![domain_report](https://user-images.githubusercontent.com/37173181/38144398-2936c2ee-3462-11e8-922b-204e30abdbfd.jpg)


The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $VTURL      | List of URL processed by VirusTotal and hosted on the domain |
| $VTCategories | Domain category assigned by VirusTotal |
| $VTWebsenseThreatSeekercategory |Domain category assigned by Websense Threat Seeker |
| $VTDomainList | List of domains that lie on the same DNS hierarchical level |
| $VTSubDomainList | List of sub-domains |
| $VTSiteClass | Site-Classification assigned by VirusTotal |
| $VTWebutationVerdict  | Webutation Domain verdict |
| $VTWebutationSafetyScore | Webutationx Domain score  |
| $VTForcepointThreatSeekerCategory | Domain category assigned by Forcepoint Threat Seeker |
| $VTPassiveDNSReplication | The queried domain has been seen to resolve the list of ip address |
| $VTResponseCode | If the queried domain is present in VirusTotal database it returns 1 ,if absent returns 0 and if the requested item is still queued for analysis it will be -2 |
| $VTWHOIS | Registered domain owners and meta-data from WHOIS |   


##### Retrieve IP address reports

The IP address for which you want to retrieve the report
- input : a valid IPv4 address in dotted quad notation, for the time being only IPv4 addresses are supported.

```
_fetch $SrcIP from threatsample limit 1
>>_lookup virustotal get_ip_report $SrcIP
```
##### Sample Output 
![ip_report](https://user-images.githubusercontent.com/37173181/38144512-a3ed30c2-3462-11e8-9e00-cf11cfaddb34.jpg)

The Lookup call returns output in the following structure for available data  

 | Fields        | Description  |
|:------------- |:-------------|
| $VTOwner      | Autonomous system owner detail |
| $VTURL | List of latest url hosted on the queried ip address |
| $VTPassiveDNSReplication | Domain resolved to the queried ip address |
| $VTASN | Autonomous system number |
| $VTCN | Country |
| $VTCommunicatingSamples | SHA256 of files that communicate with the queried ip address  |
| $VTDownloadedSamples  | SHA256 of files that downloaded from the queried ip address |
| $VTResponseCode | If the queried domain is present in VirusTotal database it returns 1 ,if absent returns 0 and if the submitted IP address is invalid -1. |



#####  Retrieve file  scan  reports by MD5/SHA-1/SHA-256 hash
  
File report of MD5/SHA-1/SHA-256 hash for which you want to retrieve the most recent antivirus report
- input : a md5/sha1/sha256 hash will retrieve the most recent report on a given sample
```
_fetch $Filehash from threatsample limit 1
>>_lookup virustotal get_filehash_report $Filehash
```
##### Sample Output 
![filehash](https://user-images.githubusercontent.com/37173181/38144583-f6cb7dc6-3462-11e8-9706-ae4c3c5b063a.jpg)


The Lookup call returns output in the following structure for available data

 | Fields        | Description  |
|:------------- |:-------------|
| $VTmd5      | Corresponding MD5 hash of quried hash present in VirusTotal DB |
| $VTsha1 | Corresponding SHA-1 hash of quried hash present in VirusTotal DB |
| $VTsha256 | Corresponding SHA-256 hash of quried hash present in VirusTotal DB |
| $VTPermalink | Permalink of report stored in VirusTotal |
| $VTPositive | List of scans returning positive detection |
| $VTNegative | List of scans returning negative detection |
| $VTPositives | Count of positive detection |
| $VTResponseCode | If the queried url is present in VirusTotal database it returns 1 ,if absent returns 0 and if the requested item is still queued for analysis it will be -2 |
| $VTTotal | Count of positive and negative detections |
| $VTSystemTstamp | Scan Date |



### Using the VirusTotal API and DNIF  
The VirusTotal API is found on github at 

  https://github.com/dnif/lookup-virustotal

#### Getting started with VirusTotal API and DNIF

1. #####    Login to your Data Store, Correlator, and A10 containers.  
   [ACCESS DNIF CONTAINER VIA SSH](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)
2. #####    Move to the ‘/dnif/<Deployment-key/lookup_plugins’ folder path.
```
$cd /dnif/CnxxxxxxxxxxxxV8/lookup_plugins/
```
3. #####   Clone using the following command  
```  
git clone https://github.com/dnif/lookup-virustotal.git virustotal
```
4. #####   Move to the ‘/dnif/<Deployment-key/lookup_plugins/virustotal/’ folder path and open dnifconfig.yml configuration file     
    
   Replace the tag:<Add_your_apik_key_here> with your VirusTotal api key
```
lookup_plugin:
  VT_API_KEY: <Add_your_apik_key_here>

```
