from distutils.core import setup

setup(
    name='pypki',
    version='',
    packages=['core'],
    url='',
    license='',
    author='Dennis Verslegers',
    author_email='dennis.verslegers@sd-consult.be',
    description='',
    install_requires=[
        "web.py>=0.37",
        "configobj",
        "pyyaml",
        "pexpect",
    ],
)
