from sbjat.common import settings
from sbjat.common import logdata
from jira import JIRA

def assign(ticket):
    options     = {"server": "https://jira.talos.cisco.com"}
    jira        = JIRA(basic_auth=(settings.uname, settings.jiraKey), options=options)
    issue 	    = jira.issue(ticket)
    jira.assign_issue(ticket, 'wikoeste')   # assign the ticket to me


def comment(ticket,data,rules,scr,ip):
    score   = None
    options = {"server": "https://jira.talos.cisco.com"}
    jira    = JIRA(basic_auth=(settings.uname, settings.jiraKey), options=options)

    # private comment of sbrs data
    jira.add_comment(ticket, str(data), visibility={'type': 'role', 'value': 'Project Developer'})
    issue   = jira.issue(ticket)

    # write the rule hits in COG-Hits in jira
    issue.update(fields={'customfield_20380':rules})

    # if we have a list of scores get avg if scr is none
    if scr is None:
        score = 0.0
    elif type(scr) == list:
        if len(scr) > 0:
            avg   = sum(scr)/len(scr)
            score = avg
    else:
        score = scr
    # return boiler plate based on score these are public jira comments
    if ("RsH" or "RhM") in rules:
        if float(score) <= -2.0:
            jira.add_comment(ticket,ip +": " + settings.boilerplates["iadh"])
        return 1
    elif "Gry" in rules and float(score) <= -7.0:
        jira.add_comment(ticket,ip +": " +  settings.boilerplates["grey"])
        return 2
    elif ("Cbl" or "Pbl" or "Sbl" or "Css") in rules:
        jira.add_comment(ticket,ip +": " + settings.boilerplates["spamhaus"])
        return 1
    elif ("psb" or "PSB") in rules: # private comment
        if float(score) == -2.0 or float(score <= -2.0):
            jira.add_comment(ticket, ip + ": " + "IP listed in http://psbl.org",
                visibility={'type': 'role', 'value': 'Project Developer'})
            return 2
    elif "Ce" or "Ve" in rules: # private comment
        if float(score) <=-2.0:
            jira.add_comment(ticket, ip + ": " + "IP listed in http://enemieslist.com/classifications/",
                visibility={'type': 'role', 'value': 'Project Developer'})
        return 2
    elif ("Cp1" or "Cp2" or "Vp1" or "Vp2") in rules:
        if float(score) <= -2.0:
            jira.add_comment(ticket, ip + ": " + settings.boilerplates["cp1"])
            return 1
    elif ("Ivn" or "Ivm") in rules:
        if float(score) <= -2.0: # private comment
            jira.add_comment(ticket, ip + ": " + "listed on Invalument: https://www.invaluement.com/",
                visibility={'type': 'role', 'value': 'Project Developer'})
            return 2
    elif ("Vu" or "Cu") in rules:
        if float(score) <= -2.0: # private comment
            jira.add_comment(ticket, ip + ": " + "a domain associated with this IP are listed in the URIDB feed.",
                visibility={'type': 'role', 'value': 'Project Developer'})
            return 2
    elif "Rtm" in rules: # private comment
        if float(score) <= -2.0:
            jira.add_comment(ticket, ip + ": " + "is blocked by a Reptool entry",
                visibility = {'type': 'role', 'value': 'Project Developer'})
            logdata.logger.info(ticket, ip + ": " + "is blocked by a Reptool entry")
            return 2
    elif float(score) <= -2.0: # private comment
        jira.add_comment(ticket,"Your IP, {}".format(ip)+ " has a malicious score {}".format(scr)+" due to the following known rules: {}".format(rules),
        visibility = {'type': 'role', 'value': 'Project Developer'})
        return 2
    elif float(score) > -1.9:
        logdata.logger.info(ticket, ip + ": " + settings.boilerplates["recovered"])
        jira.add_comment(ticket, ip + ": " + settings.boilerplates["recovered"])
        return 1
    else: # private comment
        jira.add_comment(ticket, scr +","+rules, visibility={'type': 'role', 'value': 'Project Developer'})
        return 2

def resolveclose(ticket,flag):
    logdata.logger.info(ticket +","+str(flag))
    options     = {"server": "https://jira.talos.cisco.com"}
    jira        = JIRA(basic_auth=(settings.uname, settings.jiraKey), options=options)
    issue       = jira.issue(ticket)
    transitions = jira.transitions(issue)
    resol       = jira.resolutions()
    status      = issue.fields.status
    ###DEBUG PRINTS###
    #print(resol)
    #print(transitions)
    #print([(t['id'], t['name']) for t in transitions])
    #print("case status is", str(status))
    #################
    #Append the te labels for metrics
    issue.fields.labels.append(u'te-sbjat')
    issue.fields.labels.append(u'te-automation')
    issue.update(fields={"labels":issue.fields.labels})
    #print(issue.fields.labels)
    ###############
    #Setting the ticket to resolved or not
    #If the ticket is geoip do not close
    # else if score is -1.9 or better close
    # else if -2 or worse send reply and close
    # else if Rtm and -2 do not close comment wbrs score
    # else do not close
    ##################
    print('the flag is ', str(flag))
    #transitions = jira.transitions(issue, expand="transitions.fields")
    #for t in transitions:
    #    print(t)
    # Resolve the issue and set resolution to close is status is not cog investigating
    if flag == 3:  # geolocation ticket
        jira.add_comment(ticket, "Investigating the reported Geolocation issue. Update to follow")
        logdata.logger.info(str(ticket) + ";"+settings.uname+"; Investigating the reported Geolocation issue.")
    #Below are not geolocation and will be auto resolved if possible
    elif flag == 1:
        if 'Pending' in str(status) or 'Open' in str(status):
            jira.transition_issue(issue,'5',resolution={'id': '1'})
            logdata.logger.info(str(ticket) + "; Resolved Fixed")
        elif 'Investigating' in str(status):
            jira.transition_issue(issue,'741',resolution={'id':'1'})
            logdata.logger.info(settings.uname +"; "+str(ticket)+'; Resolved Fixed')
        elif 'Reopened' in str(status):
            jira.transition_issue(issue,'5',resolution={'id':'1'})
            logdata.logger.info(settings.uname +"; "+str(ticket)+'; Resolved Fixed')
        else:
            jira.add_comment(ticket, "Investigating the issue. Update to follow")
            logdata.logger.info(settings.uname + "; Investigating")
    # if the flag is 2 or not set, we will keep the ticket open for analysis
    elif flag == 2:
        jira.add_comment(ticket, "Investigating the issue. Update to follow")
        logdata.logger.info(settings.uname +"; Investigating")
    else:
        jira.add_comment(ticket, "Investigating the issue. Update to follow")
        logdata.logger.info(settings.uname +"; Investigating")