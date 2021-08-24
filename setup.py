from setuptools import setup

setup(
        name = 'gcutils',
        version = '0.0.55',
        author = 'gcd0318',
        author_email = 'gcd0318@hotmail.com',
        url = 'https://github.com/gcd0318/gcutils',
        description = 'gcutils',
        packages = ['gcutils'],
        install_requires = [],
        entry_points = {
            'console_scripts': [
                'scan=gcutils:scan',
                'timestamp=gcutils:timestamp'
                ]
            }
        )

