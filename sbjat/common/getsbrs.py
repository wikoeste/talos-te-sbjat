import json
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address

import requests
from netaddr import IPNetwork, valid_ipv4, valid_ipv6

from sbjat.common import juno, logdata, postjira, settings

requests.packages.urllib3.disable_warnings()

HTTP_TIMEOUT = (5, 30)
DNS_TIMEOUT = 10


def _listed_on(revip, blacklist):
    try:
        result = subprocess.run(
            ["dig", "+short", f"{revip}.{blacklist}"],
            capture_output=True,
            text=True,
            timeout=DNS_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        logdata.logger.exception("DNS blacklist lookup failed for %s", blacklist)
        return None
    return blacklist if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", result.stdout.strip()) else None

#entered from ticket data checks for ipv4
# in known spam block lists
def pbl(revip): # check the public blacklists and return the results
    blacklists = ("bl.spamcop.net", "cbl.abuseat.org", "pbl.spamhaus.org",
                  "sbl.spamhaus.org", "xbl.spamhaus.org","dnsbl.invaluement.com")
    # These independent DNS requests are the main per-IP latency cost.
    with ThreadPoolExecutor(max_workers=len(blacklists)) as executor:
        return [result for result in executor.map(lambda bl: _listed_on(revip, bl), blacklists) if result]

#entered from ticketdata
#get ip geo data
def getgeoip(ip):
    cont,cntry,subdnm,timzn = (None,None,None,None)
    metadata = []
    confid   = {'continent': 0, 'country': 0, 'locale': 0}
    endpoint = "https://api-private.thetap.cisco.com/geoip/v1/ip/"
    try:
        resp = requests.get(endpoint + str(ip), verify=False, timeout=HTTP_TIMEOUT)
    except requests.RequestException as exc:
        logdata.logger.warning("GeoIP request failed for %s: %s", ip, exc)
        return "==GeoDB API unavailable=="
    if resp.status_code == 200:
        try:
            rj = resp.json()
            cont   = rj['location']['continent']['name']
            cntry  = rj['location']['country']['name']
            subdnm = rj['location']['subdivision']['name']
            timezn = rj['location']['time_zone']
            confid.update({"continent":rj['confidence']['continent']})
            confid.update({"country":rj['confidence']['country']})
            confid.update({"locale":rj['confidence']['subdivision']})
            metadata.append("ASN: {}".format(rj['additional']['asn_name']))
            metadata.append("ISP: {}".format(rj['additional']['isp']))
            metadata.append("Type: {}".format(rj['additional']['user_type']))
        except (ValueError, KeyError, TypeError) as exc:
            logdata.logger.warning("Invalid GeoIP response for %s: %s", ip, exc)
            return "==GeoDB API returned invalid data=="
        data = (
        "==GEOIP Results==" \
		"\nContinent: {}".format(cont)+
        "\nCountry: {}".format(cntry)+
		"\nLocale: {}".format(subdnm)+
		"\nMisc: {}".format(metadata)+
		"\nConfidence: {}".format(confid)
        )
        return(data)
    else:
        return "==GeoDB API Error {}==".format(resp.status_code)

#entered from ticketdata to check if there is a cidr
#in the jira desc or summary
def cidrscore(ips, ticket, jira=None):
    flag = 0
    print("Only IP addresses with a Poor/malicious,"
          "SBRS score will print for any CIDR!\n")
    network = IPNetwork(ips)
    max_addresses = int(os.getenv("SBJAT_MAX_CIDR_ADDRESSES", "256"))
    if network.size > max_addresses:
        raise ValueError(
            f"CIDR {ips} contains {network.size} addresses; limit is {max_addresses}"
        )
    analysis = None
    for i in network:
        # get sbrs score and if -2.0 or more get sbrs data for that IP only
        scr,rules,pbl,ip,date = score(i)
        if float(scr) < -2.0:
            # get geoip data on that ip
            geoipdata = getgeoip(i)
            # Create SBRS table
            analysis = "\n===RealTimeThreat Analysis===\n \
                Date: {}".format(date)+"\n \
                Ticket: {}".format(ticket)+"\n \
                IP: {}".format(ip)+"\n \
                Score {}".format(scr)+"\n \
                Rule Hits: {}".format(rules)+"\n \
                Public Block List: {}".format(pbl) \
                +"\n"+str(geoipdata)
            #post comment to jira and update ticket fields
            flag = postjira.comment(ticket, analysis, rules, scr, str(i), jira=jira)
            logdata.logger.info("%s", analysis)
    # Resolve once after every address in the network has been analyzed.
    postjira.resolveclose(ticket, flag, jira=jira)

#Entered from ticketdata to get ipv4 socre
def score(ip):
    date = time.strftime("%Y-%m-%d %H:%M")
    try:
        revip = ip_address(ip).reverse_pointer
        revip = re.sub('.in-addr.arpa', '', revip)
        sbrsurl = revip + '.v1x2s.rf-adfe2ko9.senderbase.org'
        proc = subprocess.run(
            ["dig", "+noall", "+answer", "TXT", sbrsurl],
            capture_output=True,
            timeout=DNS_TIMEOUT,
            check=False,
        )
        out = proc.stdout
    except (ValueError, OSError, subprocess.TimeoutExpired):
        logdata.logger.exception("SBRS DNS lookup failed for %s", ip)
        out = b''
    score = 0.0
    rules, pblname = ("--", "--")
    # Parse the returned dig data to dispaly the rules, and scores.
    split = out.split()
    if len(split) < 5:
        # return empty results
        return score,rules,pblname,ip,date
    data = split[4]
    data = re.sub('b\'\"|\"\'', '', str(data))
    data = re.sub('.=', '', str(data))
    data = re.sub('\\|', ' ', str(data))
    res = data.split()
    if len(res) < 6:
        logdata.logger.warning("Malformed SBRS DNS response for %s", ip)
        return score, rules, pblname, ip, date
    # Check for the ip in dnsbl / pbl
    pblname = pbl(revip)
    score = res[1]
    rules = res[5]
    rules = ' '.join([rules[i:i + 3] for i in range(0, len(rules), 3)])
    return score,rules,pblname,ip,date

#Entered from main
def ticketdata(ticket, jira=None):
    extractedips    = []
    flag            = 0
    ticket_flags    = []
    ipvers          = None
    ticketurl       = "https://jira.talos.cisco.com/browse/{}".format(ticket)
    jiraAPI         = "https://jira.talos.cisco.com/rest/api/2/search?jql=key={}".format(ticket)
    fields          = "&fields=description,summary,labels,customfield_20042,customfield_20043,customfield_20380"
    headers         = {'Content-type': 'application/json'}
    try:
        response = requests.get(
            jiraAPI + fields,
            headers=headers,
            auth=(settings.uname, settings.jiraKey),
            verify=False,
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException:
        logdata.logger.exception("Jira API request failed for %s", ticket)
        return
    data,rules,scr,date,match = (None,None,None,None,None)
    if response.status_code == 200:
        try:
            jsondict = response.json()
        except ValueError:
            logdata.logger.exception("Jira returned invalid JSON for %s", ticket)
            return
        print('=jql search results=\n', json.dumps(jsondict, indent=2))
        if not jsondict.get('issues'):
            logdata.logger.error("Jira returned no issue for %s", ticket)
            return
        desc    = jsondict['issues'][0]['fields']['description'] or ""
        smry    = jsondict['issues'][0]['fields']['summary'] or ""
        cf20042 = jsondict['issues'][0]['fields']['customfield_20042']
        cf20043 = jsondict['issues'][0]['fields']['customfield_20043'] #ipfield
        cf20380 = jsondict['issues'][0]['fields']['customfield_20380'] #rule hits
        labels  = jsondict['issues'][0]['fields']['labels']
        # format desc and smry to not have line breaks tabs and spacing
        frmtdesc    = desc.translate(str.maketrans(' ', ' ', '\n\t\r'))
        frmtsmry    = smry.translate(str.maketrans(' ', ' ', '\n\t\r'))
        # regex to find ipv4 addresses
        ipPattern   = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        # regex for ipv6
        ipv6pattern = re.compile('(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})')
        # Check for any IPs in the custom fields
        if cf20042 is not None:
            for match in re.findall(ipPattern, cf20042):#ipv4
                extractedips.append(match)
            for match in re.findall(ipv6pattern, cf20042):#ipv6
                for m in match:
                    extractedips.append(m[0])
        if cf20043 is not None:
            for match in re.findall(ipPattern, cf20043):#ipv4
                extractedips.append(match)
            for match in re.findall(ipv6pattern, cf20043):#ipv6
                for m in match:
                    extractedips.append(match[0])
        # Check for any IPs in the desc
        for match in re.findall(ipPattern, desc):#ipv4
            extractedips.append(match)
        for match in re.findall(ipv6pattern, desc):#ipv6
            for m in match:
                if m[0] != 'd:':
                    extractedips.append(m[0])
        ips  = list(set(extractedips)) # remove duplicate ips
        if 'd' in ips:
            ips.remove(('d'))
        # Check the summary and description for CIDR entries
        cidrs = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}/(?:[0-9]|[12][0-9]|3[0-2])\b", smry + " " + desc))
        for network in cidrs:
            try:
                cidrscore(network, ticket, jira=jira)
            except (ValueError, TypeError):
                logdata.logger.warning("Ignoring invalid CIDR %s in %s", network, ticket)
        #log the ips
        logdata.logger.error(f"Ips from {ticket}, {ips}")
        #if there are ip address then get the sbrs data
        if len(ips) > 0:
            for i in ips:
                if valid_ipv6(i): # if the ip is v6 get v6 data
                    ipv6results,v6rules,scr = juno.getipv6(i)
                    geoipdata = getgeoip(i)
                    data = ipv6results+geoipdata
                    logdata.logger.error(f"{date}: {ipv6results} and, {geoipdata}.")
                    # post comment to jira and update ticket fields
                    flag = postjira.comment(ticket, data, str(v6rules), scr, i, jira=jira)
                    settings.results.extend([ticket, data, str(v6rules), scr, i])
                elif valid_ipv4(i): #ipv4 addres and get the ipv4 data
                    scr, rules, pbln, ip, date = score(i)  # send the ip list to get the SBRS score,rulehits, and possible pbl, of each ip from the ticket summary or description
                    geoipdata = getgeoip(i)
                    data = ("\n==SBRS Threat Intel==\n" \
                    "===RealTime Threat Analysis===\n \
                    IP Analyzed: {}".format(i) + "\n \
                    Date: {}".format(date)+"\n \
                    Score: {}".format(scr)+"\n \
                    Rule Hits: {}".format(rules)+"\n \
                    Public Block List: {}".format(pbln)+"\n \
                    "+str(geoipdata)+"")
                    logdata.logger.error(str(date)+":"+str(data))
                    # post comment to jira and update ticket fields
                    flag = postjira.comment(ticket, data, str(rules), scr, i, jira=jira)
                    logdata.logger.error("Flag for resolution, "+str(flag))
                    settings.results.append(ticket)
                    settings.results.extend([data,str(rules),scr,i])        # fixed extend error by adding []
                else:                                                       # NO valid IP address
                    print(str(i) +", is not a valid IPv4 or v6 address")
                    logdata.logger.error(str(ticket)+"; does not contain a valid IPv4 or v6 address: "+i)

                # if this is a geoip ticket then set to 3 and do not auto resolve.
                if flag == 0:
                    for m in settings.geolocation:
                        if str(m) in str(smry):
                            flag = 3
                        if str(m) in str(desc):
                            flag = 3
                ticket_flags.append(flag)
                # should think how to handle multiple ips storing all in a dictionary or list
                if settings.results is not None:
                    logdata.logger.error(f"{date}:{settings.results}")
            # Resolve the ticket is possible via automation
            # update resolution for the last analyzed IP
            postjira.resolveclose(ticket, max(ticket_flags, default=flag), jira=jira)
        else: # no IP addresses found in ticket
            err = "\nNo valid IPv4 or IPv6 Addresses found in IP fields of the ticket"
            logdata.logger.error(str(date)+":"+str(err))
    # HTTP ERR to jira api
    else:
        err = "\nHTTP ERROR: {}".format(response.status_code),ticket + " Jira API Search"
        logdata.logger.error(str(date)+":"+str(err))
