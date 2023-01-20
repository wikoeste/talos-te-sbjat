# records a transaction log regarding for the tickets found
# and automated action logged
from sbjat.common import settings
import logging,os   # first of all import the module
#Crate logger
# write to users home directory
homedir = os.path.expanduser("~")
fname   = 'sbjat_sbrs_audit.log'
logging.basicConfig(
    format='%(asctime)s:%(name)s:%(levelname)s - %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S',
    filename=homedir+"/"+fname)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)