from setuptools import setup

with open("README.ms", 'r') as f:
    long_description = f.read()

setup(
   name='foo',
   version='2.0.1',
   description='A useful module',
   license="MIT",
   long_description=long_description,
   author='Man Foo',
   author_email='foomail@foo.example',
   url="http://www.foopackage.example/",
   packages=['Karloss'],  #same as name
   install_requires=['pyshark', 'asn1tools', 'pandas'], #external packages as dependencies
)