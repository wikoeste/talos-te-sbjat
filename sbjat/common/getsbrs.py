from common import settings
from common import postjira
from common import logdata
from netaddr import IPNetwork
import requests,subprocess,shlex,re,time,json
from ipaddress import ip_address
from jira import JIRA
from terminaltables import AsciiTable
requests.packages.urllib3.disable_warnings()

def ticketdata(ticket):
    ticketurl = "https://jira.sco.cisco.com/browse/{}".format(ticket)
    jiraAPI = "https://jira.sco.cisco.com/rest/api/2/search?jql=key={}".format(ticket)
    fields = "&fields=description,summary,created,assignee,reporter,resolutiondate,customfield_12385"
    headers = {'Content-type': 'application/json'}
    response = requests.get(jiraAPI+fields, headers=headers, auth=('wikoeste', 'S0urc3f1r3!10'), verify=False)
    tbl = AsciiTable([["NoData"], ["Jira API Search"]])
    data,rules,scr, = (None,None,None)
    if response.status_code == 200:
        jsondict = response.json()
        #print('jira lql search for cog ticket', json.dumps(jsondict, indent=2))
        extractedips = []
        desc = jsondict['issues'][0]['fields']['description']
        smry = jsondict['issues'][0]['fields']['summary']
        created = jsondict['issues'][0]['fields']['created']
        resolved = jsondict['issues'][0]['fields']['resolutiondate']
        rulehits = jsondict['issues'][0]['fields']['customfield_12385']
        #format desc and smry to not have line breaks tabs and spacing
        frmtdesc = desc.translate(str.maketrans(' ', ' ', '\n\t\r'))
        frmtsmry = smry.translate(str.maketrans(' ', ' ', '\n\t\r'))
        # regex to find ipv4 addresses
        ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        # Check for any IPs in the summary
        for match in re.findall(ipPattern, smry):
            extractedips.append(match)
        # Check for any IPs in the desc
        for match in re.findall(ipPattern, desc):
            extractedips.append(match)
        # Check for ip in comments
        ips = list(set(extractedips)) # remove duplicate ips
        #print(ips)
        flag = 0
        if len(ips) > 0:
            for i in ips:
                scr, rules, pbl, ip, date = score(i)  # send the ip list to get the SBRS score,rulehits, and possible pbl, of each ip from the ticket summary or description
                data = "==SBRS Jira Ticket Date at Creation==\n \
                    Ticket: "+str(ticket)+"\n \
                    Desc: "+ str(frmtdesc)+"\n \
                    Summary: "+str(frmtsmry)+"\n \
                    IP Addresses Submitted: {}".format(ips)+"\n \
                    Date Opened: {}".format(created)+"\n \
                    Date Closed: {}".format(resolved)+"\n \
                    \n===RealTime Threat Analysis===\n \
                    IP Analyzed: {}".format(i) + "\n \
                    Date: {}".format(date)+"\n \
                    Score: {}".format(scr)+"\n \
                    Rule Hits: {}".format(rules)+"\n \
                    Public Block List: {}".format(pbl)
                logdata.logger.info(str(date)+":"+str(data))
                # post comment to jira and update ticket fields
                flag = postjira.comment(ticket,data,rules,scr,ips[-1])
            postjira.resolveclose(ticket, flag)  # update resolution
        if re.search(r'\/.{2}',smry) is True: # this is a cidr entry in summary field
            cidrscore(match,ticket)
        elif re.search(r'\/.{2}',desc) is True: # this is a cidr entry in description
            cidrscore(match,ticket)
        else:
            err = "No valid IPv4 Addresses"
            logdata.logger.info(str(date)+":"+str(err))
    else:
        err = "HTTP ERROR: {}".format(response.status_code),ticket + " Jira API Search"
        logdata.logger.info(str(date)+":"+str(err))

def ipfromcomments(comment):
    cmtips = []
    # regex to find ipv4 addresses in the case comments
    ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    # Check for any IPs in the summary
    for match in re.findall(ipPattern, str(comment)):
        cmtips.append(match)
    return cmtips

def cidrscore(ips,ticket):
    print("Only SBRS scores with a Poor Reputation will print for any CIDR!")
    for i in IPNetwork(ips):
        # get sbrs score and if -2.0 or more get sbrs data for that IP only
        scr,rules,pbl,ip,date = score(i)
        if float(scr) < -2.0:
            # Create SBRS table
            analysis = "\n===RealTimeThreat Analysis===\n \
                Date: {}".format(date)+"\n \
                Ticket: {}".format(ticket)+"\n \
                IP: {}".format(ip)+"\n \
                Score {}".format(scr)+"\n \
                Rule Hits: {}".format(rules)+"\n \
                Public Block List: {}".format(pbl)
            #post comment to jira and update ticket fields, resolve
            postjira.comment(ticket,analysis,rules,scr,i)
            logdata.logger.info(str(analysis))
    #do not close case review the issue first
    jira.transition_issue(issue, '711', fields={'assignee': {'name': 'wikoeste'}})

def score(ip):
    date = time.strftime("%Y-%m-%d %H:%M")
    revip = ip_address(ip).reverse_pointer
    revip = re.sub('.in-addr.arpa', '', revip)
    sbrsurl = revip + '.v1x2s.rf-adfe2ko9.senderbase.org'
    digcmd = 'dig +noall +answer TXT ' + sbrsurl
    proc = subprocess.Popen(shlex.split(digcmd), stdout=subprocess.PIPE)
    out, err = proc.communicate()
    # Parse the returned dig data to dispaly the rules, and scores.
    split = out.split()
    if len(split) == 0:
        # return empty results
        score = "Unknown"
        rules,pblname = ("--","--")
        return score,rules,pbl,ip,date
    else:
        data = split[4]
        data = re.sub('b\'\"|\"\'', '', str(data))
        data = re.sub('.=', '', str(data))
        data = re.sub('\\|', ' ', str(data))
        res = data.split(' ')
        # Check for the ip in dnsbl / pbl
        pblname = pbl(revip)
        score = res[1]
        rules = res[5]
        rules = ' '.join([rules[i:i + 3] for i in range(0, len(rules), 3)])
        results = "None"
        ''''# Create SBRS table
        tbldata = [
            ["Date: {}".format(date)],
            ["IP: {}".format(ip)],
            ["Score {}".format(score)],
            ["Rules: {}".format(rules)],
            ["Block List: {}".format(pblname)],
            ["Results: {}".format(results)],
        ]
        sbrsTable = AsciiTable(tbldata, 'SBRS Data')
        print(sbrsTable.table)
        print()
        '''
        return score,rules,pblname,ip,date
# check the public blacklists and return the results
def pbl(revip):
    blacklists = ("bl.spamcop.net", "cbl.abuseat.org", "pbl.spamhaus.org", "sbl.spamhaus.org", "xbl.spamhaus.org",
                      "dnsbl.invaluement.com");
    # Nslookup to check the Black Lists
    res = ''
    for bl in blacklists:
        digcmd = 'dig +short ' + str(revip) + '.' + str(bl)
        proc = subprocess.Popen(shlex.split(digcmd), stdout=subprocess.PIPE)
        out, err = proc.communicate()
        decode = out.decode('utf-8')
        # test if an ip is returned from block list lookups
        if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', decode):
            res = bl
        if res is None:
            res = "Not Found"
        return res