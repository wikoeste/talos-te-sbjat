# Senderbase Jira Automation Tool
# Tool to read, analyze, respnde, and resolve jira sbrs case types
# Author: wikoeste

# Release Notes
1.1
updated api key error found on test and prod tepot hosts
changed from jira.sco to jira.talos for 01/03/2023 queue change
updated the boiler plates for ipedia changes

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
