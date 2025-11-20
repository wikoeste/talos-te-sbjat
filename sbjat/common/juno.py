from sbjat.common import settings,logdata
settings.init()
import requests,json
requests.packages.urllib3.disable_warnings()

def getipv6(address):
    apiKey  = settings.junoKey
    headers = {'Content-type': 'application/json'}
    qry     = '{"_source":["_id","@timestamp","sbrs.ingest.score","sbrs.ingest.rules","ipas.original.result.ipv6","ipas.original.result.sbrs",' \
              '"ipas.ingest.verdict","ipas.original.result.ipas_score"],"query":{"term":{"sender_ip":{"value":"'+address+'"}}}}'
    total   = 0
    scores  = []
    rules   = []
    try:
        resp = requests.get(settings.juno+'juno_past_6_months/_search?', headers={'Content-type': 'application/json'}, data=qry, auth=(settings.uname, apiKey),verify=False)
        if resp.status_code == 200:
            json_result = resp.json()
            #print(json.dumps(json_result, indent=2))
            total = json_result['hits']['total']['value']
            if total > 0:
                for i in json_result['hits']['hits']:
                    scores.append(i['_source']['sbrs.ingest.score'])
                    for j in i['_source']['sbrs.ingest.rules']:
                        rules.append(j)
            tbldata = (
                    "\n====SBRS ipv6 Threat Intel====" \
                    "\nIP: {}".format(address) +
                    "\nScore: {}".format(scores) +
                    "\nRules: {}".format(rules)
            )
            return(tbldata,rules,scores)
        else:
            tbldata = (
                '\n===SBRS ipv6 Threat Intel===' \
                "\nIP: {}".format(address) +
                '\nResults: No data found for IP')
            return(tbldata,rules,scores)
    except:
        tbldata = ('\n===SBRS ipv6 Threat Intel===' \
                   '\nUnable to Reach Juno API Host!')
        print(tbldata)
        return (tbldata,rules,scores)
        logdata.logger.info(tbldata)