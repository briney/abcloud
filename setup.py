from setuptools import setup

config = {
	'description': 'AbCloud',
	'author': 'Bryan Briney',
	'url': 'www.github.com/briney/abcloud/',
	'download_url': 'www.github.com/briney/abcloud/',
	'author_email': 'briney@scripps.edu',
	'version': '0.1.0',
	'install_requires': ['nose',
						 'boto3',
						 # 'abtools',
						 ],
	'packages': ['abcloud'],
	'scripts': ['bin/abcloud'],
	'name': 'abcloud',
	'include_package_data': True
}

setup(**config)
