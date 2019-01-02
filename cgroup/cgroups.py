#!/usr/bin/env python
# -*- coding: utf-8 -*-
# __author__ = "Wilson Lan"

import os


#####################
# utility functions #
#####################
def must_make_cgroup(hierarchy, cgroup_name):
    # create cgroup under specific hierarchy
    root_cgroup = "/sys/fs/cgroup/{hierarchy}/{cgroup_name}"
    cgroup = root_cgroup.format(hierarchy=hierarchy,
                                cgroup_name=cgroup_name)
    if not os.path.exists(cgroup):
        os.mkdir(cgroup, 0755)
    return cgroup

def set_cgroup_task(task, *cgroups):
    # add task to specific cgroup
    for cg in cgroups:
        tasks = "{cgroup}/tasks".format(cgroup=cg)
        with open(tasks, "a") as fp:
            fp.write("{task}\n".format(task=task))

def set_cgroup_cfs_attr(*cgroups):
    # attributes' values
    cpu_usage_percent = 0.5
    period_us = 100000
    quota_us  = int(period_us * cpu_usage_percent)

    for cg in cgroups:
        hierarchy = os.path.basename(cg[:cg.rfind("/")])
        subsystem = hierarchy
        if subsystem == "cpu":
            cfs_quota_us  = "{cgroup}/cpu.cfs_quota_us".format(cgroup=cg)
            cfs_period_us = "{cgroup}/cpu.cfs_period_us".format(cgroup=cg)
            with open(cfs_quota_us, "w") as fp:
                fp.write("{quota_us}\n".format(quota_us=quota_us))
            with open(cfs_period_us, "w") as fp:
                fp.write("{period_us}\n".format(period_us=period_us))

def set_cgroup_cpuset_attr(*cgroups):
    # attributes' values
    core_id = "8"

    for cg in cgroups:
        hierarchy = os.path.basename(cg[:cg.rfind("/")])
        subsystem = hierarchy
        if subsystem == "cpuset":
            cpus = "{cgroup}/cpuset.cpus".format(cgroup=cg)
            with open(cpus, "w") as fp:
                fp.write("{cpus}\n".format(cpus=core_id))


if __name__ == "__main__":
    pid = os.getpid()
    print "Task {pid}".format(pid=pid)

    # init related cgroup
    cgroups = []
    cgroups.append(must_make_cgroup("cpuset", "cgrouptest"))
    cgroups.append(must_make_cgroup("cpu", "cgrouptest"))

    # set cgroup
    set_cgroup_task(pid, *cgroups)

    # set cpu cfs attributes
    set_cgroup_cfs_attr(*cgroups)
    
    # set cpuset cpus attributes
    set_cgroup_cpuset_attr(*cgroups)

    # user code
    while True:
        pass

