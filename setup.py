from setuptools import setup

setup(
   name='pyauth',
   version='1.3.1-rl',
   description='Enfore simple access control policy for REST API, and also support rate limit',
   author='Ashokkumar T.A',
   author_email='ashokkumar.ta@gmail.com',
   packages=['pyauth'],  
   install_requires=["requests==2.32.5", "pyrate_limiter==4.1.0"],
   keywords = ['Auth', 'Python library', 'Python tool', 'Access', 'Authorization', 'Policy', 'rate limit'], 
)