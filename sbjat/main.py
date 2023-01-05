# Senderbase Jira Automation Tool
# Tool to read, analyze, respond, and resolve jira sbrs case types
# Author: wikoeste
from sbjat.common import settings
settings.init()
from sbjat.common import getsbrs
from sbjat.common import postjira
from sbjat.common import logdata
from jira import JIRA
import re

def main():
    print("\n===Senderbase Jira Automation Tool (sbjat)==="+settings.version)
    #Collect all SBRS tickets in the last 4 weeks
    options = {"server": "https://jira.talos.cisco.com"}
    jira    = JIRA(basic_auth=('wikoeste', settings.cecpw), options=options)
    #qry    = 'project = COG AND cf[12380] in cascadeOption(14037) AND created >= -24d AND assignee in (EMPTY) ORDER BY key ASC'
    qry    = 'project = COG AND issuetype = SBRS AND created >= -24d AND assignee in (EMPTY) ORDER BY key ASC'
    sbrs    = jira.search_issues(qry, maxResults=100) # get max 100 results
    logdata.logger.info("Tool run by {}".format(settings.uname))
    clist,cmtips   = ([],[])
    cases   = str(sbrs)
    cog     = re.compile("COG-.{5}")
    for match in re.findall(cog, cases): # extract the cog ticket id cog-12345
        clist.append(match)
    totalsbrstickets = len(clist)
    print('Total sbrs cases in last 24 days is {}'.format(totalsbrstickets))
    print(clist)
    print("=====\n\n")
    for i in clist:
        # take ownership, parse for data, analyze data,
        # return and post analysis results in private comment,
        # post public boiler plate
        postjira.assign(i)
        issue = jira.issue(i)
        # get the ticket data for each cog case located
        getsbrs.ticketdata(i)
    if len(clist) == 0:
        print("No valid Tickets")
if __name__ == '__main__':
    main()