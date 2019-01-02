#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = "Wilson Lan"

import oslo_context

from oslo_log import log as logging
from oslo_config import cfg
from sqlalchemy import Column, String
from sqlalchemy.ext.declarative import as_declarative, declared_attr
from oslo_db.sqlalchemy import models
from oslo_db.sqlalchemy import enginefacade


LOG = logging.getLogger(__name__)
logging.register_options(cfg.CONF)
logging.setup(cfg.CONF, __name__)

enginefacade.configure(connection="mysql+pymysql://neutron:nsfocus@controller/neutron")


@as_declarative()
class Base(object):
    @declared_attr
    def __tablename__(cls):
        return cls.__name__.lower() + 's'

    id = Column(String(30), primary_key=True)

class User(Base, models.ModelBase):
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

@enginefacade.transaction_context_provider
class Context(oslo_context.context.RequestContext):
    pass


@enginefacade.writer
def test_db_create_api(context, item):
    context.session.add(item)

@enginefacade.reader
def test_db_read_api(context, model, filter_args):
    return context.session.query(model).filter(model.name == filter_args).all()

@enginefacade.writer
def test_db_update_api(session, model, filter_args, val):
    context.session.query(model).filter(model.name == filter_args).update({"password": val})

@enginefacade.writer
def test_db_delete_api(context, model, filter_args):
    context.session.query(model).filter(model.name == filter_args).delete()


if __name__ == "__main__":
    Base.metadata.create_all(enginefacade.get_legacy_facade().get_engine())
    context = Context()

    peter = User(id="1", name="Peter", fullname="Peter Alex", password="123")
    john  = User(id="2", name="John", fullname="John Alen", password="234")

    test_db_create_api(context, peter)
    test_db_create_api(context, john)
    print "Create User 'Peter' and 'John'"

    res = test_db_read_api(context, User, peter.name)
    print "Read User 'Peter':", res

    test_db_update_api(context, User, peter.name, "###")
    print "Update the password of User 'Peter'"

    res = test_db_read_api(context, User, peter.name)
    print "Read User 'Peter':", res

    test_db_delete_api(context, User, peter.name)
    test_db_delete_api(context, User, john.name)
    print "Delete User 'Peter' and 'John'"

    Base.metadata.drop_all(enginefacade.get_legacy_facade().get_engine())
