# create a log of the tools actions for review
# due to the cron tab automation
from sbjat.common import settings
settings.init()
import logging,os

# write to users home directory
homedir = os.path.expanduser("~")
fname   = 'talos-te-sbjat-err.log'
logging.basicConfig(
    format='%(asctime)s:%(name)s:%(levelname)s - %(message)s',
    level=logging.ERROR,
    datefmt='%Y-%m-%d %H:%M:%S',
    filename=homedir+"/"+fname)
logger = logging.getLogger()