#!/usr/bin/env python2.7
import random
import string

from itsdangerous import BadSignature, Serializer, SignatureExpired
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy import Column, ForeignKey, Integer, \
    Text, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()
secret_key = ''.join(random.choice(
        string.ascii_uppercase +
        string.digits)
                     for x in range(32))


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(Text, index=True)
    email = Column(Text, index=True)
    picture = Column(Text)
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # Valid Token, but expired
            return None
        except BadSignature:
            # Invalid Token
            return None
        user_id = data['id']
        return user_id

    @property
    def serialize(self):
        return {
            'name':        self.name,
            'picture':     self.picture,
            'description': self.description
        }


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    up_file = Column(Text)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object in easily serializable format"""
        return {
            'name':           self.name,
            'description':    self.description,
            'image filename': self.up_file,
            'unique id':      self.id
        }


class Manufacturer(Base):
    __tablename__ = 'manufacturer'
    name = Column(Text, primary_key=True, index=True)
    description = Column(Text, nullable=False)
    up_file = Column(Text)
    id = Column(Integer, index=True, unique=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object in easily serializable format"""
        return {
            'name and unique id': self.name,
            'description':        self.description,
            'image filename':     self.up_file,
        }


class Shop(Base):
    __tablename__ = 'shop'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(Text, nullable=False, index=True)
    description = Column(Text, nullable=False)
    up_file = Column(Text)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """Return object in easily serializable format"""
        return {
            'unique id':      self.id,
            'name':           self.name,
            'description':    self.description,
            'image filename': self.up_file,
        }


class Item(Base):
    __tablename__ = 'items'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(Text, nullable=False, index=True)
    description = Column(Text, nullable=False)
    category = Column(Integer, ForeignKey('category.id'), nullable=False)
    ingredients = Column(Text)
    up_file = Column(Text)
    m_id = Column(Text, ForeignKey('manufacturer.name'), nullable=False)
    s_id = Column(Integer, ForeignKey('shop.id'), nullable=False)
    # Make relationships so SQLAlchemy knows them.
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship(User)
    Category_id = relationship(Category)
    Manufacturer_id = relationship(Manufacturer)
    Shop_id = relationship(Shop)

    @property
    def serialize(self):
        """Return object in easily serializable format"""
        return {
            'name':            self.name,
            'category':        self.category,
            'description':     self.description,
            'image filename':  self.up_file,
            'shop id':         self.s_id,
            'manufacturer id': self.manufacturer_id,
            'unique id':       self.id,
        }


# Make the database and call it something
engine = create_engine('postgresql://catalog:catalog@localhost/catalog')

Base.metadata.create_all(engine)
