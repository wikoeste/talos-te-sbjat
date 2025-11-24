# Senderbase Jira Automation Tool
# Tool to read, analyze, respond, and resolve jira sbrs case types
# Author: wikoeste
from sbjat.common import settings
settings.init()
from sbjat.common import getsbrs,postjira,logdata
from jira import JIRA
import re,requests
requests.packages.urllib3.disable_warnings()

def main():
    jira           = None
    clist,cmtips   = ([],[])
    # log data
    logdata.logger.info("Tool run by {}".format(settings.uname))
    print("\n===Senderbase Jira Automation Tool (sbjat)==="+settings.version)
    #Collect all SBRS tickets in the last day
    options = {"server": "https://jira.talos.cisco.com"}
    try:
        jira    = JIRA(basic_auth=(settings.uname, settings.jiraKey), options=options)
    except:
            print(f"Jira API auth ERROR; {settings.uname}, API Key {settings.jiraKey}.")
    finally:
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
        print("\n\n")
        if len(clist) == 0:
            print("No valid SBRS Tickets")
            logdata.logger.info("No valid Tickets")
        else:
            for i in clist:
                # take ownership, parse for data, analyze data,
                # return and post analysis results in private comment,
                # post public boiler plate
                postjira.assign(i)
                issue = jira.issue(i)
                # get the ticket data for each cog case located
                getsbrs.ticketdata(i)
        ##testing/debuging
        #getsbrs.ticketdata('COG-74286')
        #getsbrs.ticketdata('COG-80149')

########################
if __name__ == '__main__':
    main()
