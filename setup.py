from setuptools import setup

setup(
    name='te-sbjat',
    version='1.6.2',
    packages=["sbjat", "sbjat.common"],
    description='Senderbase Jira Automation Tool',
    author='Will Koester',
    author_email='wikoeste@cisco.com',
    url='https://gitlab.vrt.sourcefire.com/wikoeste/sbjat.git',
    entry_points={
        'console_scripts':[ 'te-sbjat=sbjat.main:main'],
        },
)