# create a log of the tools actions for review
# due to the cron tab automation

from sbjat.common import settings
import logging,os

# write to users home directory
homedir = os.path.expanduser("~")
fname   = 'sbjat_sbrs_audit.log'
logging.basicConfig(
    format='%(asctime)s:%(name)s:%(levelname)s - %(message)s',
    level=logging.ERROR,
    datefmt='%Y-%m-%d %H:%M:%S',
    filename=homedir+"/"+fname)
logger = logging.getLogger()
logger.setLevel(logging.INFO)