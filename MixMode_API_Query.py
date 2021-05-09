# coding: utf-8

import sys
import io
import os
import json
import time
import datetime
  import mixmode_api
from mixmode_api.rest import ApiException
import urllib3
import requests
dictSample = {}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

mixmode_endpoint_host="" # the fully qualified domain name of the api server, e.g., api.mixmode.ai
mixmode_endpoint_user="" # the api/ui username
mixmode_endpoint_password="" # the api/ui user password
searchApi = None
authRes = None
strOutPath = "" #output file path
strContextPath = "" #secondary output file path
boolGetContext = False #context of notice and intel query results
strdateFormat = "%m/%d/%Y %I:%M:%S %p"; # 12/27/2018 2:47:52 PM
boolSampling = False # track IP port combo in a dict and only lookup x count every y entry
boolIncludeSensorName = True
boolTimeStamp = True #output timestamp
"""query to search logs"""
query = ''
#last 2 weeks tls log=notice #alerts on TLS
#last 2 weeks id_resp_p=22 log=intel #exposed SSH

def main(query):
    global searchApi
    global authRes
    config = mixmode_api.Configuration()
    config.verify_ssl = False
    config.host = "https://" + mixmode_endpoint_host + "/v1" # API URL
    api_client = mixmode_api.ApiClient(config)
    usersApi = mixmode_api.UsersApi(api_client)

    """Authenticate"""
    authRes = usersApi.authenticate_user({'username': mixmode_endpoint_user, 'password': mixmode_endpoint_password})

    # add the returned token as a header in all subsequent requests
    api_client.configuration.api_key['x-mixmode-api-token'] = authRes.token
    usersApi = mixmode_api.UsersApi(api_client)
    searchApi = mixmode_api.SearchApi(api_client)
    offsetCount = 0

    response = requests.get(config.host + "/search/stream", headers={'x-mixmode-api-token':authRes.token}, params={'query':query, 'timezone':'America/Los_Angeles', 'searchType': 'O_SENSOR'}, verify=False)
    textBody = response.content.decode("UTF-8")
    textBody = "[" + textBody.replace("\n", ",")[:-1] + "]"
    if "errorCode\":1," in textBody:
      print("error: " + textBody + "\n\n Please check your query and try again")
    else:
      JSONreturn = json.loads(textBody)
      processJSON(JSONreturn, strOutPath, config.host)


def contextSearch(APIurl, queryText):
    global authRes
    time.sleep(1)
    """should be able to search logs"""
    #JSONreturn = searchApi.query(queryText, 'UTC')
    response = requests.get(APIurl + "/search/stream", headers={'x-mixmode-api-token':authRes.token}, params={'query':queryText, 'timezone':'America/Los_Angeles', 'searchType': 'O_SENSOR'}, verify=False)
    textBody = response.content.decode("UTF-8")
    textBody = "[" + textBody.replace("\n", ",")[:-1] + "]"
    if "errorCode\":1," in textBody:
      print("error: " + textBody)
    else:
      JSONreturn = json.loads(textBody)
    processJSON(JSONreturn, strContextPath, APIurl)

def processJSON(res, strOutputPath, APIurl):
    with io.open(strOutputPath , "a", encoding="utf-8") as f:
        for connDetail in res:
            scrIP = ""
            destIP = ""
            scrPort = ""
            destPort = ""
            protocolOut = ""
            msg = ""
            timestamp = ""
            sensorName = connDetail["sensorName"]
            if boolTimeStamp == True and "ts" in connDetail:
              timestamp = datetime.datetime.utcfromtimestamp(connDetail["ts"]).strftime('%Y-%m-%d %H:%M:%S') + "|"
            if "src_ip_inet" in connDetail:
              scrIP = connDetail["src_ip_inet"]
            if "dst_ip_inet" in connDetail:
              destIP = connDetail["dst_ip_inet"]
            if "data" in connDetail:
              if "src" in connDetail["data"] and scrIP =="":
                scrIP = connDetail["data"]["src"]
              if "p" in connDetail["data"] and destIP == "":
                destPort = connDetail["data"]["p"]
              if "id_orig_p" in connDetail["data"]:
                scrPort = connDetail["data"]["id_orig_p"]
              if "id_resp_p" in connDetail["data"]:
                destPort = connDetail["data"]["id_resp_p"]
              if "seen_indicator" in connDetail["data"]:
                msg = connDetail["data"]["seen_indicator"]
                protocolOut =  "|" + msg
              if "desc" in connDetail["data"] and msg == "":
                msg = connDetail["data"]["desc"]
                protocolOut =  "|" + msg
            if connDetail['log'] == 'rfb':
              desktopName = ''
              if 'desktop_name' in connDetail['data']:
                desktopName = connDetail['data']['desktop_name']
              protocolOut =  "|" + desktopName
            if connDetail["log"] == "dns":
              dnsQuery = ''
              if  "query" in connDetail["data"]:
                dnsQuery = connDetail["data"]["query"]
              protocolOut =  "|" + dnsQuery
            if connDetail["log"] == "notice":
                msg = ""
                note = ""
                remote_location_country_code = ""
                remote_location_city = ""
                if "msg" in connDetail["data"]:
                    msg = connDetail["data"]["msg"]
                if "note" in connDetail["data"]:
                    note = connDetail["data"]["note"]
                if "remote_location_country_code" in connDetail["data"]:
                    remote_location_country_code = connDetail["data"]["remote_location_country_code"]
                if "remote_location_city" in connDetail["data"]:
                    remote_location_city = connDetail["data"]["remote_location_city"]
                protocolOut = "|" + msg + "|" + note + "|" + remote_location_country_code + "|" + remote_location_city 
            if connDetail["log"] == "socks":
              socksver = connDetail["data"]["version"]
              socksstatus = connDetail["data"]["status"]
              protocolOut =  str(socksver) + "|" + socksstatus
            if connDetail["log"] == "ntlm":
              if "username" in connDetail["data"]:
                username = connDetail["data"]['username']
              if "hostname" in connDetail["data"]:
                hostname = connDetail["data"]['hostname']
              if "domainname" in connDetail["data"]:
                domainname = connDetail["data"]['domainname']   
              if "server_dns_computer_name" in connDetail["data"]:
                server_dns_computer_name = connDetail["data"]['server_dns_computer_name']   
              protocolOut =  "|" + username + "|" + hostname + "|" + domainname + "|" + server_dns_computer_name
            if connDetail["log"] == "ssl":
                issuer = ""
                subject = ""
                server_name = ""
                version = ""
                cipher = ""
                SNI = ""
                last_alert = ""
                if "SNI" in connDetail["data"]:
                    SNI = connDetail["data"]["SNI"][0]
                if "cipher" in connDetail["data"]:
                    cipher = connDetail["data"]["cipher"]
                if "version" in connDetail["data"]:
                    version = connDetail["data"]["version"]
                if "server_name" in connDetail["data"]:
                    server_name = connDetail["data"]["server_name"]
                if "subject" in connDetail["data"]:
                    subject = connDetail["data"]["subject"]
                if "issuer" in connDetail["data"]:
                    issuer = connDetail["data"]["issuer"]
                if "last_alert" in connDetail["data"]:
                    last_alert = connDetail["data"]["last_alert"]
                    
                protocolOut = "|" + SNI + "|" + cipher + "|" + version + "|" + server_name + "|" + subject + "|" + issuer + "|" + last_alert 

            if connDetail["log"] == "http":
              strHost = ""
              strURI = ""
              strUserAgent = ""
              strOrigin = ""
              strReferrer = ""
              strOrigFileNames = ""
              orig_mime_type = ""
              resp_mime_type = ""
              strUserName = ""
              strPassword = ""
              if "host" in connDetail["data"]:
                strHost = connDetail["data"]["host"]
              if "uri" in connDetail["data"]:
                strURI = connDetail["data"]["uri"]
              if "user_agent" in connDetail["data"]:
                strUserAgent = connDetail["data"]["user_agent"]
              if "origin" in connDetail["data"]:
                strOrigin = connDetail["data"]["origin"]
              if "referrer" in connDetail["data"]:
                strReferrer = connDetail["data"]["referrer"]
              if "orig_filenames" in connDetail["data"]:
                strOrigFileNames = connDetail["data"]["orig_filenames"][0]
              if "orig_mime_types" in connDetail["data"]:
                orig_mime_type = connDetail["data"]["orig_mime_types"][0]
              if "resp_mime_types" in connDetail["data"]:
                resp_mime_type = connDetail["data"]["resp_mime_types"][0]
              if "username" in connDetail["data"]:
                strUserName = connDetail["data"]["username"]
              if "password" in connDetail["data"]:
                strPassword = connDetail["data"]["password"]
              protocolOut = "|" + strHost + "|" + strURI + "|" + strUserAgent + "|" + strOrigin + "|" + strReferrer + "|" + strOrigFileNames + "|" + orig_mime_type + "|" + resp_mime_type + "|" + strUserName
            if connDetail["log"] == "smb_files":
              strFolderPath = ""
              strFile = ""
              strAction = ""
              strModified = ""
              strCreated = ""
              strChanged = ""
              strPreviousName = ""
              if "path" in connDetail["data"]:
                strFolderPath = connDetail["data"]["path"]
              if "name" in connDetail["data"]:
                strFile = connDetail["data"]["name"]
              if "action" in connDetail["data"]:
                strAction = connDetail["data"]["action"]
              if "times_modified" in connDetail["data"]:
                strModified = connDetail['data']['times_modified']
              if "times_accessed" in connDetail["data"]:
                strAccessed = connDetail['data']['times_accessed']
              if "times_changed" in connDetail["data"]:
                strChanged = connDetail['data']['times_changed']
              if "times_created" in connDetail["data"]:
                strCreated = connDetail['data']['times_created']
              if "prev_name" in connDetail["data"]:
                strPreviousName = connDetail['data']['prev_name']
              protocolOut =  "|" + strFolderPath + "|" + strFile + "|" + strAction + "|" + strPreviousName + "|" + str(strModified) + "|" + str(strAccessed) + "|" + str(strChanged) + "|" + str(strCreated) 
            if connDetail["log"] == "smtp":
                user_agent = ""
                mailFrom = ""
                rcptTo = ""
                helo = ""
                subject = ""
                user_agent = ""
                if "mailfrom" in connDetail["data"]:
                    mailFrom = connDetail["data"]["mailfrom"]
                if "rcptTo" in connDetail["data"]:
                    rcptTo = connDetail["data"]["rcptTo"][0]
                elif "rcptto" in connDetail["data"]:
                    rcptTo = connDetail["data"]["rcptto"][0]
                else:
                    rcptTo = ""
                if "message_urls" in connDetail["data"]:
                    #need to add this as a variable. Commenting out for now
                    #fURL = open("D:\\exports\\smtp_URLs.txt", "a", encoding="utf-8")
                    #for outURL in connDetail["data"]["message_urls"]:
                    #    if outURL != "":
                    #        fURL.write(outURL + "\n")
                    #fURL.close()
                helo = connDetail["data"]["helo"]
                if "user_agent" in connDetail["data"]:
                    user_agent = connDetail["data"]["user_agent"]

                if "subject" in connDetail["data"]:
                    subject = connDetail["data"]["subject"]

                protocolOut = "|" + mailFrom + "|" + rcptTo + "|" + helo + "|" + subject + "|" + user_agent
            logSource = connDetail["log"]
            epochTime = connDetail["ts"]
            logDateTime = datetime.datetime.fromtimestamp(int(epochTime))
            logDateTime = logDateTime.timetuple();
            outDateTime = time.strftime(strdateFormat, logDateTime)
            strOut = timestamp + scrIP + "|" + str(scrPort) + "|" + destIP + "|" + str(destPort) + "|" + logSource 
            if boolIncludeSensorName == True:
              strOut = strOut + "|" + sensorName
            strOut = strOut + protocolOut
            strOut = "\"" + strOut.replace("|","\",\"") + "\""
            stDict = scrIP + "|" + destIP + "|" + str(destPort)  #don't track source port for sampling

            if boolGetContext == True and (connDetail["log"] == "notice" or connDetail["log"] == "intel"):
              if boolSampling == True and stDict not in dictSample or boolSampling == False:
                if str(scrPort)  != "" and scrIP != "" and destPort  != "" and str(destPort) != "": #best to only check if we have direct correlation with all matches
                  contextSearch(APIurl, "log!=notice log!=conn log!=notice log!=intel id_orig_p=" + str(scrPort) + " " + "src_ip_inet=" + scrIP + " " + "dst_ip_inet=" + destIP + " " + "id_resp_p=" + str(destPort)  )
                  #outDateTime + " " + "id_orig_p=" + str(scrPort) + " " + "src_ip_inet=" + scrIP + " " + "dst_ip_inet=" + destIP + " " + "id_resp_p=" + str(destPort)
                if boolSampling == True:
                  dictSample[stDict] = 1
            f.write(strOut + "\n")

    
if __name__ == '__main__':
    main(query)
