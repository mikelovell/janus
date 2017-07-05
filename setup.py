from setuptools import setup

requires = ['paramiko >= 1.13.0', 'ecdsa', 'cryptography', 'falcon',
            'passlib']

entry_points = {'console_scripts': ['janus-cli=janus.shell:main']}

setup(name='janus',
      version=0.1,
      description='Janus SSH Certificate Management',
      author='Mike Lovell',
      author_email='mike@dev-zero.net',
      license='GPLv3',
      packages=['janus'],
      install_requires=requires,
      entry_points=entry_points)
