try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
import setuptools

setup(
        name = 'gcutils',
        version = '0.0.61',
        author = 'gcd0318',
        author_email = 'gcd0318@hotmail.com',
        url = 'https://github.com/gcd0318/gcutils',
        description = 'gcutils',
        packages = ['gcutils'],
#        install_requires = ['paramiko'],
        entry_points = {
            'console_scripts': [
                'scan=gcutils:scan',
                'timestamp=gcutils:timestamp'
                ]
            }
        )

