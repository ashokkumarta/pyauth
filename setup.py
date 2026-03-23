from setuptools import setup

setup(
   name='pyauth',
   version='1.2.8',
   description='Enfore simple access control policy for REST API',
   author='Ashokkumar T.A',
   author_email='ashokkumar.ta@gmail.com',
   packages=['pyauth'],  
   install_requires=["requests==2.32.5"],
   keywords = ['Auth', 'Python library', 'Python tool', 'Access', 'Authorization', 'Policy'], 
)