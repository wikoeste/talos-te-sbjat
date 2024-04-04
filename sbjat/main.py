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
    clist,cmtips   = ([],[])
    # log data
    logdata.logger.info("Tool run by {}".format(settings.uname))
    print("\n===Senderbase Jira Automation Tool (sbjat)==="+settings.version)
    #Collect all SBRS tickets in the last day
    options = {"server": "https://jira.talos.cisco.com"}
    jira    = JIRA(basic_auth=(settings.uname, settings.jiraKey), options=options)
    qry    = 'project = COG AND issuetype = SBRS AND created >= -1d AND assignee in (EMPTY) ORDER BY key ASC'
    # get max 10 results
    sbrs    = jira.search_issues(qry, maxResults=10)
    cases   = str(sbrs)
    cog     = re.compile("COG-.{5}")
    # extract the cog ticket id cog-12345
    for match in re.findall(cog, cases): #
        clist.append(match)
    totalsbrstickets = len(clist)
    print('Total sbrs cases in last day (24 hours) is {}'.format(totalsbrstickets))
    print(clist)
    #log the tickets located
    logdata.logger.info(clist)
    print("=====")
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
        logdata.logger.info("No valid Tickets")
    ##testing/debuging
    #getsbrs.ticketdata('COG-69847')
    #getsbrs.ticketdata('COG-69870')
    #getsbrs.ticketdata('COG-69929')

if __name__ == '__main__':
    main()