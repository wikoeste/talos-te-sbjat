# records a transaction log regarding for the tickets found and automated action logged
from sbjat.common import settings
import logging,os    # first of all import the module

#logging.basicConfig(filename='sbjat_sbrs_audit.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
#logging.warning('This message will get logged on to a file')
#Crate logger
# write to users home directory
homedir = os.path.expanduser("~")
print(homedir)
fname   = 'sbjat_sbrs_audit.log'
fmt     = '%(asctime)s:%(name)s:%(levelname)s - %(message)s'
logging.basicConfig(filename=homedir+"/"+fname, format= fmt)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


