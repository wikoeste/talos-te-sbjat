import getpass,re,os.path,queue
def init():                                 # Global List of variables
    global uname,cecpw,sherlock,sherlockKey,boilerplates,version,jiraKey
    global juno,junoKey,geolocation

def getKey(keyname):                        # take the search keyname and return the appropriate api key
    match     = ''
    freebsd   = "/home/{}".format(uname)+"/.profile"
    osx       = "/Users/{}".format(uname)+"/.profile"
    if os.path.exists(freebsd):
        fname = freebsd
    else:
        fname = osx
    with open(fname, 'r') as fp:
        lines = fp.read().splitlines()
        if not lines.startswith('#'):
            for l in lines:
                if keyname.upper() in l:
                    match = l
    key = re.sub(r'.*=','',match)
    key = re.sub(r'"', '', key)
    return key
#Get user creds and API Keys at start
uname        = getpass.getuser()
cecpw        = "the$AM@dm1n^"
sherlockKey  = getKey("sherlock")
sherlock     = 'https://sherlock.ironport.com/webapi/'
juno         = 'https://prod-juno-search-api.sv4.ironport.com/'
junoKey      = getKey("jupiter")
jiraKey	     = "FlcPslVXxwFQ0QMYGF3chpi0fftY8SxRw56sFW"
version      = '1.6'
geolocation  = ['geo','GEO','geolocation','geo-location','GEOLOCATION','GEO-LOCATION','country','Country','None','none','Unknown','unknown']
# SBRS Boilerplates
boilerplates = {"general":"If the spam problem is fixed as you believe it to be, then there should be no further complaints received. \
                In general, once all issues have been addressed (fixed), reputation recovery can take anywhere from a few hours to just over one week \
                to improve, depending on the specifics of the situation, and how much email volume the IP sends. Complaint ratios determine the amount \
                of risk for receiving mail from an IP, so logically, reputation improves as the ratio of legitimate mails increases with respect to the number of complaints.",

                "grey":"The discrepancy with the IP has been addressed and the reputation of the IP will improve within 24 hours.",

                "spamhaus":"Your IP has a poor Talos Intelligence Reputation due to currently being listed on Spamhaus (http://www.spamhaus.org/lookup). \
                Please contact Spamhaus directly to resolve this listing issue. Once delisted, the Talos Intelligence Reputation for the IP should improve within 24 hours.",

                "recovered":"Your IP currently has a Neutral Talos Intelligence Email Reputation (within acceptable parameters). The reputation should continue to \
                improve as we receive additional good mail volume reports for the IP from our sensor network.",

                "heloptr":" Your IP or IPs has a poor Talos Intelligence email reputation because the IP is helo-ing with a generic host name string. \
                This is a known behavior pattern with BOT infected systems. The IP should be HELO-ing as the sending domain and the PTR should also point \
                to the hosted domain for proper SMTP authentication; HELO should match PTR and sender domain should match Helo string. \
                Once this discrepancy is addressed, the reputation of the IP should improve over the course of a few days as our \
                system receives sensor data indicating a fix in helo/ptr match for the IP and to the sender domain.",

                "noscore":"Your IP or IPs has a neutral  Talos Intelligence reputation due to very low levels of mailflow traffic reported for the IP by the Talos Intelligence Network. \
                As such, without sufficient email reports, Talos Intelligence cannot accurately generate a reputation for the IP and therefore grants the IP a Neutral reputation. \
                Generally this is a very good thing as Talos Intelligence does not see the IP as a potential spam risk, and the IP is considered within acceptable Talos Intelligence parameters.  \
                Sometimes however, our customers will throttle or reject mail if there is no reported evidence of sufficient traffic. \
                We have no control over how passive or aggressive our customers choose to be when implementing our reputation information.In some cases, \
                Cisco customers who use Talos Intelligence reputation as part of their filtering infrastructure may forget to add this explanation to the report they \
                generate when rejecting the message. This may be the case here. I recommend contacting the recipient via other means and having them request to their sys-admin or \
                ISP provider to whitelist mail from your IP so that it makes it into their network. You may try to generate a reputation based on sufficient mail \
                traffic by gradually ramping up on good outbound mail. This may generate some increase in Talos Intelligence Network reports for your IP \
                and thus produce enough data for Talos Intelligence to generate an actual score.",

                "iadh":"Our worldwide sensor network indicates that spam originated from your IP. We suggest checking these possibilities to help isolate the \
                root cause of the spam and mail server access attempts originating from your IP. Audit your mailing list(s) to ensure you are NOT sending \
                to invalid email addresses; A server, user computer, router or switch on your network may be compromised by a trojan spam virus;\
                There is an open port 25 through which a spammer may be gaining access and sending out spam; One of your users is sending spam \
                through the IP. Compromised hosting or mail accounts, which are then used to authenticate and send through other ports.\
                In general, once all issues have been addressed (fixed), reputation recovery can take anywhere from a few hours to just over one week to improve.",
                
                "cp1":"The IP address or addresses have a poor Talos Intelligence email reputation because the IP is helo-ing with a generic host name string. \
                This is a known behavior pattern with BOT infected systems. The IP should be HELO-ing as the sending domain and the PTR should also point to \
                the hosted domain for proper SMTP authentication; HELO should match PTR and sender domain should match Helo string."
                }

# access token git write: XsG1NRAmCzYxYcMWC73g
