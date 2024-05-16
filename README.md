# Senderbase Jira Automation Tool
# Tool to read, analyze, respnde, and resolve jira sbrs case types
# Author: wikoeste

# Release Notes
1.6.1
fixed post jira issue with transition and resolving tickets
added additional logging for troubleshooting

1.6
fixed error if there is a non ip formatted entry 
fixed auto resolve err
fixed comment error for enimeieslist.com and not the correct boilerplate
added option to ignore lines starting with # in profiles

1.5
added geoip data
added auto resolution to the tickets
added ipv6 lookup support
added geolocation check to not auto resolve ticket
added auto label for te-sbjat to be added in the jira lable field for tracking/metrics

1.4
jira comments need fixed to post the correct response
removed erroneous code and old comments

1.3
fixed the jira comment for rule hits added the -2 score as well to post the correct template
1.2
added api key for jira 
changed to use api over cec / removed cec from settings
fixed error with multiple ips not printing/writing results
disabled #postjira.resolveclose()

1.1
updated api key error found on test and prod tepot hosts
changed from jira.sco to jira.talos for 01/03/2023 queue change
updated the boiler plates for ipedia changes
removed the writing of rule hits since that field is not present in jira.talos
removed qry error for sbrs in main.py
added timestamp to logging file for tracking

1.0
fixed ip data in jira comment to be the correct ip if there are multiple ips

Not Released
0.8/0.9
updated postjira to new password 
0.7
fixed private comment error
added cp1 boilerplate
removed errors with jira transition of the case status
removed any auto resoltuion of the ticket
0.6
Bug fixes
fixed error with Unknown score postjira.py", line 25, in comment ValueError: could not convert string to float: 'Unknown'
0.5
'''
Bug Fixes:
fixed issue where we print the incorrect ip due to the post jira call being outside the loop
fixed message view from public to private for comments where human interaction is needed
fixed log file creation to be in the user home dir
'''
