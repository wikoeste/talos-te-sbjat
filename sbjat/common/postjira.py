from common import settings
from common import getsbrs
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
        #resolveclose(ticket)
    elif "sbl" or "pbl" in rules:
        jira.add_comment(ticket,ip +": " + settings.boilerplates["spamhaus"])
        #resolveclose(ticket)
    elif "Ia" and "Dh" in rules:
        jira.add_comment(ticket,ip +": " + settings.boilerplates["iadh"])
        #resolveclose(ticket)
    elif "Gry" in rules:
        jira.add_comment(ticket,ip +": " +  settings.boilerplates["grey"])
    elif float(scr) <= -2.0:
        jira.add_comment(ticket,"Your IP, {}".format(ip)+ "has a malicious score {}".format(scr)+" due to the following known rules: {}".format(rules))
        #resolveclose(ticket)
    else:
        jira.add_comment(ticket, scr +","+rules, visibility={'type': 'role', 'value': 'Project Developer'}) # private comment
        jira.transition_issue(issue, '711', fields={'assignee': {'name': 'wikoeste'}})


def resolveclose(ticket):
    options = {"server": "https://jira.sco.cisco.com"}
    jira = JIRA(basic_auth=('wikoeste', 'S0urc3f1r3!10'), options=options)
    # available transitions
    issue = jira.issue(ticket)
    #print(issue.fields)
    # print(issue.fields.resolution)
    transitions = jira.transitions(issue)
    #print([(t['id'], t['name']) for t in transitions])
    # Resolve the issue and set resolution to close
    jira.transition_issue(issue, '5', fields={'assignee': {'name': 'wikoeste'}, 'resolution': {'id': '1'}})
    #resolutions ids
    # 1 = Fixed
    # 2 = wont fix
    # 3 =
    # 4 =