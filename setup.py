from setuptools import setup

setup(
    name='te-sbjat',
    version='1.1',
    packages=["sbjat", "sbjat.common"],
    description='Senderbase Jira Automation Tool',
    author='Will Koester',
    author_email='wikoeste@cisco.com',
    url='',
    entry_points={
        'console_scripts':[ 'te-sbjat=sbjat.main:main'],
        },
)