import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()
#Table to hold most up to date score and Category on a given IP Address 
class IP_Current(Base):
    __tablename__ = 'current'
    # Here we define columns for the table person
    # Notice that each column is also a normal Python instance attribute.
    IP = Column(String(250), primary_key=True)
    Current_Score = Column(String(250), nullable=False)
#Table to hold historic scores, categories, and dates of an IP
class IP_History(Base):
    __tablename__ = 'address'
    # Here we define columns for the table address.
    # Notice that each column is also a normal Python instance attribute.
    IP = Column(String(250),primary_key=True)
    Date = Column(String(250))
    Score = Column(String(250))
    Category = Column(String(250), nullable=False)


# Create an engine that stores data in the local directory's
# sqlalchemy_example.db file.
engine = create_engine('sqlite:///IP_Report.db')
 
# Create all tables in the engine. This is equivalent to "Create Table"
# statements in raw SQL.
Base.metadata.create_all(engine)
