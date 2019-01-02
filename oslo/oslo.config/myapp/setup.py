#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = "Wilson Lan"

from setuptools import setup, find_packages

setup(
    name = "myapp",
    version = "1.0",
    packages = ["myapp"],
    entry_points = {
        "oslo.config.opts" : [
            "myapp = myapp.opts:list_opts",
        ]
    }
)
