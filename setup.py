from setuptools import setup

version = "0.1.5"

setup(
    name='bitgo',
    packages=['bitgo'],
    version=version,
    description='alpha version of a bitgo python library',
    author='Sebastian Serrano',
    author_email='sebastian@bitpagos.com',
    entry_points={
        'console_scripts':
            [
                'bitgo = bitgo.cmd:main',
            ]
    },
    url='https://github.com/sserrano44/pybitgo',
    download_url='https://github.com/sserrano44/pybitgo/tarball/%s' % version,
    keywords=['bitcoin', 'bitgo'],
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    install_requires=[
        "requests==2.13.0",
        "pycryptodome==3.4.3",
        "pycoin==0.70",
        "six==1.10.0",
    ]
)
