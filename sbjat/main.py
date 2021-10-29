# Senderbase Jira Automation Tool
# Tool to read, analyze, respnde, and resolve jira sbrs case types
# Author: wikoeste
from common import settings
settings.init()
from common import getsbrs
from common import postjira
from common import logdata
from jira import JIRA
import re

def main():
    print("\n===Senderbase Jira Automation Tool (sbjat)===")
    #Collect all SBRS tickets in the last 4 weeks
    options = {"server": "https://jira.sco.cisco.com"}
    jira    = JIRA(basic_auth=('wikoeste', 'S0urc3f1r3!10'), options=options)
    qry    = 'project = COG AND cf[12380] in cascadeOption(14037) AND created >= -24d AND assignee in (EMPTY) ORDER BY key ASC'
    #qry     = 'project = COG AND resolution is Empty and cf[12380] in cascadeOption(14037) AND created >= -24d AND assignee in (EMPTY) ORDER BY key ASC'
    sbrs    = jira.search_issues(qry, maxResults=100) # get max 100 results
    logdata.logger.info("Tool run by {}".format(settings.uname))
    # print(sbrs)
    clist,cmtips   = ([],[])
    cases   = str(sbrs)
    cog     = re.compile("COG-.{5}")
    for match in re.findall(cog, cases): # extract the cog ticket id cog-12345
        # print(match)
        clist.append(match)
    totalsbrstickets = len(clist)
    print('Total sbrs cases in last 24 days is {}'.format(totalsbrstickets))
    print(clist)
    print("=====\n\n")
    for i in clist:
        # take ownership, parse for data, analyze data, return and post analysis results in private comment, post public boiler plate
        postjira.assign(i)
        issue = jira.issue(i)
        cmts = issue.fields.comment.comments # get comments id at case creatuion
        for c in cmts:
            cmtips.append(getsbrs.ipfromcomments(c.body)) # search for ips and cidrs in the comment messages bodies and store in a list for each ticket
        getsbrs.ticketdata(i) # get the ticket data for each cog case located
    if len(clist) == 0:
        logdata.logger.warning("No valid Tickets")
if __name__ == '__main__':
    main()


