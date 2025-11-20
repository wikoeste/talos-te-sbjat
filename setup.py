from setuptools import setup

setup(
    name='talos-te-sbjat',
    version='1.6.6',
    packages=["sbjat", "sbjat.common"],
    description='Te - Senderbase Jira Automation Tool',
    author='Will Koester',
    author_email='wikoeste@cisco.com',
    url='https://github.com/wikoeste/talos-te-sbjat',
    entry_points={
        'console_scripts':[ 'talos-te-sbjat=sbjat.main:main'],
        },
)