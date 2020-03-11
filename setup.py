import os
import sys

try:
    from setuptools import setup
except ImportError:
    sys.exit('ERROR: setuptools is required.\n')

try: # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError: # for pip <= 9.0.3
    from pip.req import parse_requirements


if os.environ.get('READTHEDOCS', None):
    # Set empty install_requires to get install to work on readthedocs
    install_requires = []
else:
    if sys.version_info[0] > 2:
        req_file = 'requirements.txt'
    else:
        req_file = 'requirements2.txt'
    try:
        reqs = parse_requirements(req_file, session=False)
    except TypeError:
        reqs = parse_requirements(req_file)
    install_requires = [str(r.req) for r in reqs]

# read version
exec(open('abcloud/version.py').read())

# # read long description
# with open("README.md", "r") as fh:
#     long_description = fh.read()

config = {
    'description': 'abcloud',
    'author': 'Bryan Briney',
    'url': 'https://www.github.com/briney/abcloud',
    'download_url': 'https://www.github.com/briney/abcloud',
    'author_email': 'briney@scripps.edu',
    'version': __version__,
    'install_requires': install_requires,
    'packages': ['abcloud'],
    'scripts': ['bin/abcloud'],
    'name': 'abcloud',
    'include_package_data': True,
    'classifiers': ['License :: OSI Approved :: MIT License',
                    'Programming Language :: Python :: 3.5',
                    'Programming Language :: Python :: 3.6',
                    'Programming Language :: Python :: 3.7',
                    'Programming Language :: Python :: 3.8',
                    'Topic :: Scientific/Engineering :: Bio-Informatics']
}

setup(**config)
