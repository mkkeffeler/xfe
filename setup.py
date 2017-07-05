from setuptools import setup

setup(
    name='pyxforce',
    version='0.0.1',
    author='mkkeffeler',
    author_email='mkkeffeler@crimson.ua.edu',
    url='https://github.com/mkkeffeler/xfe',
    packages=[
        'xfe',
    ],
    license='Apache 2.0',
    description='A Python interface for the X-Force Exchange API',
    install_requires=[
        'requests>=2.18.1',
        'python-dateutil>=2.6.0',
        'sqlalchemy>=1.1.11',
        'configparser>=3.5.0'
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Programming Language :: Python :: 2.7',
        'Intended Audience :: Developers',
        'Natural Language :: English',
    ],

)
