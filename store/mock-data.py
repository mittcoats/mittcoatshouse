from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Category, Product, Base

engine = create_engine('sqlite:///mittcoatshouse.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Menu for UrbanBurger
category1 = Category(name="skiing")

session.add(category1)
session.commit()

product1 = Product(name="gs-skis", description="The ultimate race ripper",
                     price="$1750", category=category1)

session.add(product1)
session.commit()

print "added menu items!"
