import getpass,re,os.path,queue
def init():                                 # Global List of variables
    global uname,cecpw,sherlock,sherlockKey,boilerplates,version,jiraKey,jirapw
    global juno,junoKey,geolocation, results

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
        for l in lines:
            if '#' not in lines:
                if keyname.upper() in l:
                    match = l
    key = re.sub(r'.*=','',match)
    key = re.sub(r'"', '', key)
    return key

#Get user creds and API Keys at start
uname        = getpass.getuser()
cecpw        = ""
sherlockKey  = getKey("sherlock")
sherlock     = 'https://sherlock.ironport.com/webapi/'
juno         = 'https://prod-juno-search-api.sv4.ironport.com/'
junoKey      = getKey("jupiter")
#results of all ips scores
results = []

#hard coded NOT GOOD IDEA
jiraKey	     = "FlcPslVXxwFQ0QMYGF3chpi0fftY8SxRw56sFW"
jirapw       = "the$AM@dm1n^"

# Version
version      = '1.6.5'

# GEO Location string check
geolocation  = ['geo','GEO','geolocation','geo-location','GEOLOCATION','GEO-LOCATION','country','Country','None','none','Unknown','unknown','GeoBlock','GeoIP']

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

                "none":"Your IP or IPs has a neutral  Talos Intelligence reputation due to very low levels of mailflow traffic reported for the IP by the Talos Intelligence Network. \
                A score of none does not equate to a score of 0. A score of 0.0 means that SenderBase has collected equal amounts of positive and negative information about this sender, \
                and has assigned it a neutral reputation (TODO: double check with the Denali team if this information still applies in Ipedia which is currently used in 13.5 and later) \
                https://techzone.cisco.com/t5/Content-Security-General/ESA-FAQ-What-does-the-SBRS-value-of-quot-none-quot-mean-and-how/ta-p/276472",

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
