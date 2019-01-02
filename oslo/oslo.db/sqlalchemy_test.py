#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = "Wilson Lan"

import sys
from contextlib import contextmanager

from sqlalchemy import Column, String, Integer, create_engine
from sqlalchemy import orm
from sqlalchemy.ext.declarative import as_declarative, declared_attr

engine = create_engine("mysql+pymysql://neutron:nsfocus@controller/neutron")


@as_declarative()
class Base(object):
    @declared_attr
    def __tablename__(cls):
        return cls.__name__.lower() + 's'

    id = Column(String(30), primary_key=True)

class User(Base):
    name     = Column(String(30))
    fullname = Column(String(30))
    password = Column(String(30))

    def __repr__(self):
        return ("<User(name = {name}, "
                      "fullname = {fullname}, "
                      "password = {password})>"
               ).format(name=self.name, 
                        fullname=self.fullname,
                        password=self.password)

    __str__ = __repr__


@contextmanager
def get_session(engine):
    session = orm.Session(bind=engine)
    try:
        yield session
        session.commit()
    except:
        session.rollback()
        raise
    finally:
        session.close()

def test_db_create_api(session, item):
    session.add(item)

def test_db_read_api(session, model, filter_args):
    return session.query(model).filter(model.name == filter_args).all()

def test_db_update_api(session, model, filter_args, val):
    session.query(model).filter(model.name == filter_args).update({"password": val})

def test_db_delete_api(session, model, filter_args):
    session.query(model).filter(model.name == filter_args).delete()


if __name__ == "__main__":
    Base.metadata.create_all(engine)

    with get_session(engine) as session:
        peter = User(id="1", name="Peter", fullname="Peter Alex", password="123")
        john  = User(id="2", name="John", fullname="John Alen", password="234")

        test_db_create_api(session, peter)
        test_db_create_api(session, john)
        print "Create User 'Peter' and 'John'"

        res = test_db_read_api(session, User, peter.name)
        print "Read User 'Peter':", res

        test_db_update_api(session, User, peter.name, "###")
        print "Update the password of User 'Peter'"

        res = test_db_read_api(session, User, peter.name)
        print "Read User 'Peter':", res

        test_db_delete_api(session, User, peter.name)
        test_db_delete_api(session, User, john.name)
        print "Delete User 'Peter' and 'John'"

    Base.metadata.drop_all(engine)
