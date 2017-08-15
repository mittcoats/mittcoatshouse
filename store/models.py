from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
import random
import string
from itsdangerous import (TimedJSONWebSignatureSerializer as
                          Serializer, BadSignature, SignatureExpired)

Base = declarative_base()
secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits)
                     for x in xrange(32))


# User Model
class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    picture = Column(String)
    email = Column(String)
    password_hash = Column(String(64))

    # def hash_password(self, password):
    #     self.password_hash = pwd_context.encrypt(password)
    #
    # def verify_password(self, password):
    #     return pwd_context.verify(password, self.password_hash)
    #
    # def generate_auth_token(self, expiration=600):
    # 	s = Serializer(secret_key, expires_in=expiration)
    # 	return s.dumps({'id': self.id })
    #
    # @staticmethod
    # def verify_auth_token(token):
    # 	s = Serializer(secret_key)
    # 	try:
    # 		data = s.loads(token)
    # 	except SignatureExpired:
    # 		#Valid Token, but expired
    # 		return None
    # 	except BadSignature:
    # 		#Invalid Token
    # 		return None
    # 	user_id = data['id']
    # 	return user_id

    @property
    def serialize(self):
        """Return object data in serializeable format"""
        return {
            'username': self.username,
            'id': self.id,
            'email': self.email,
            'password': self.password_hash
        }


# Category Model
class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    products = relationship("Product", lazy='joined')

    @property
    def serialize(self):
        """Return object data in serializeable format"""
        return {
            'name': self.name,
            'id': self.id,
            'user': self.user,
            # 'products': self.serialize_products
        }

    # TODO add products to category serialization
    # @property
    # def serialize_products(self):
    #     """Return products data in serializeable format"""
    #     return [ p.serialize for p in self.products ]


# Product Model
class Product(Base):
    __tablename__ = 'product'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(250))
    price = Column(String(8))
    category_id = Column(Integer, ForeignKey('category.id'), nullable=False)
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            # 'category': self.category,
            'price': self.price,
            'user_id': self.user_id
        }


engine = create_engine('sqlite:///mittcoatshouse.db')

Base.metadata.create_all(engine)
