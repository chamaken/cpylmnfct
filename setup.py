#!/usr/bin/env python

# http://stackoverflow.com/questions/6344076/differences-between-distribute-distutils-setuptools-and-distutils2

import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name='cpylmnfct',
      version='0.1',
      description='libnetfilter_conntrack Python wrapper',
      author='Ken-ichirou MATSUZAWA',
      author_email='chamas@h4.dion.ne.jp',
      url='https://github.com/chamaken/cpylmnfct',
      license='LGPLv2+',
      packages=['cpylmnfct',],
      classifiers=['License :: OSI Approved :: GNU Lesser General ' +
                   'Public License v2 or later (LGPLv2+)',
                   'Programming Language :: Python',
                   'Topic :: Software Development :: Libraries :: ' +
                   'Python Modules',
                   'Operating System :: Linux',
                   'Intended Audience :: Developers',
                   'Development Status :: 3 - Alpha Development Status'],
      long_description=read('README.md'),
      test_suite = 'nose.collector',
      install_requires = ['cpylmnl'],
      dependency_links=['https://github.com/chamaken/cpylmnl/zipball/master#egg=cpylmnl'],
)
