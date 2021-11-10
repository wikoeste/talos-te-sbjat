from sbjat.common import settings
from sbjat.common import getsbrs
from jira import JIRA
import re,requests

def assign(ticket):
    options = {"server": "https://jira.sco.cisco.com"}
    jira = JIRA(basic_auth=('wikoeste', 'S0urc3f1r3!10'), options=options)
    issue = jira.issue(ticket)
    jira.assign_issue(ticket, 'wikoeste')
    issue.update(priority={'name': 'P4'}) # set to a p4

def comment(ticket,data,rules,scr,ip):
    #ticket = 'COG-53664'
    options = {"server": "https://jira.sco.cisco.com"}
    jira = JIRA(basic_auth=('wikoeste', 'S0urc3f1r3!10'), options=options)
    comment = jira.add_comment(ticket, str(data), visibility={'type': 'role', 'value': 'Project Developer'})  # private comment
    # comment.delete()
    issue = jira.issue(ticket)
    issue.update(fields={'customfield_12385':rules})  # write the rule hits in COG-Hits in jira
    #return boiler plate based on score
    # public comments
    if float(scr) >= -1.9:
        jira.add_comment(ticket, ip +": " + settings.boilerplates["recovered"])
        return 1
    elif "IaM" and "DhM" in rules:
        jira.add_comment(ticket,ip +": " + settings.boilerplates["iadh"])
        return 1
    elif "Gry" in rules:
        jira.add_comment(ticket,ip +": " +  settings.boilerplates["grey"])
        return 2
    elif float(scr) <= -2.0:
        jira.add_comment(ticket,"Your IP, {}".format(ip)+ "has a malicious score {}".format(scr)+" due to the following known rules: {}".format(rules))
        return 2
    elif "sbl" or "pbl" in rules:
        jira.add_comment(ticket,ip +": " + settings.boilerplates["spamhaus"])
        return 1
    else:
        jira.add_comment(ticket, scr +","+rules, visibility={'type': 'role', 'value': 'Project Developer'}) # private comment
        return 2

def resolveclose(ticket,flag):
    options = {"server": "https://jira.sco.cisco.com"}
    jira = JIRA(basic_auth=('wikoeste', 'S0urc3f1r3!10'), options=options)
    issue = jira.issue(ticket)
    transitions = jira.transitions(issue)
    #print([(t['id'], t['name']) for t in transitions])
    status = issue.fields.status
    #print(status)
    # Resolve the issue and set resolution to close is status is not cog investigating
    if flag == 1 and 'COG' in str(status):
        jira.transition_issue(issue, '741', resolution={'id': '1'})
    elif flag == 1 and 'Pending' in str(status):
            jira.transition_issue(issue, '741', resolution={'id': '1'})
    elif flag == 1:
        #jira.transition_issue(issue, '5', resolution={'id': '1'})
        jira.transition_issue(issue, '721')
    else:
        jira.transition_issue(issue, '721')
'''
resolutions ids40335
# 1 = Fixed
# 2 = wont fix
# 3 = duplicate
# 4 = incomplete
#
jira issue Status options
[('5', 'Resolve Issue'), ('2', 'Close Issue'), ('721', 'COG Investigating')]

721 -> [('731', 'Stop Progress'), ('741', 'Resolve Issue'), ('751', 'Close Issue'), ('761', 'Pending Reporter'), ('791', 'Pending Other')]
'''
