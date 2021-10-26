from setuptools import setup

setup(
    name='sbjat',
    version='0.1',
    packages=["sbjat", "sbjat.common"],
    description='TE - Senderbase Jira Automation Tool',
    author='Will Koester',
    author_email='wikoeste@cisco.com',
    url='',
    entry_points={
        'console_scripts':[
            'sbjat=sbjat.main:main',
            ],
        },
)