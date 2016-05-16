What is SDoN PoC
================
This repository contains a Proof of Concept (PoC) for our novel method of managing Overlay Networks by leveraging the SDN paradigm. As the architecture is explained in the accompanying research paper, the following steps are here to re-create our testbed.
This repository should be cloned in the host machine. 

Machines
========
We recommend using Linux virtual machines for this purpose. We used XEN as hypervisor and for convenience we have placed our XEN config file in sdon-poc/ryu/app/sdonManager/sdon1.cfg. This config file should be cloned for each of the other SDoN nodes, i.e. sdon node 2 to 6.

Installing and configuring XEN is not the scope of this README, however we have used the information from the following link to configure our XEN VMs: https://help.ubuntu.com/community/Xen , especially focusing on the section about "Manually Create a PV Guest VM".

As IP subnet, we chose 10.0.0.0/24, where 10.0.0.1 is the XEN bridge for the VMs, and the SDON nodes are at 10.0.0.101 to 10.0.0.106.

After each VM is up and running, one has to install Open vSwitch (ovs) and scapy in each VM. Then copy the python script at sdon-poc/app/sdonManager/sdonManager.py from this repository in the VM's home directory. Note this script is the Signaling Module in our paper.


Running the Ryu SDoN app
========================
The SDoN Controller application is at sdon-poc/app/sdon.py and should be run with:
	% ryu-manager ryu/app/sdon.py
from the folder where this code repository is cloned.

After running this command, the SDoN Controller waits for the SDoN nodes (i.e. your VMs) to connect and start their overlay application.

Go now to the console of the VMs and run on each VM the following command to start the signaling module:
	% sudo python sdonManager.py
and follow the on screen menu that will deliver a our PoC demo.



The remainder is from the original ryu controller README file.

What's Ryu
==========
Ryu is a component-based software defined networking framework.

Ryu provides software components with well defined API that make it
easy for developers to create new network management and control
applications. Ryu supports various protocols for managing network
devices, such as OpenFlow, Netconf, OF-config, etc. About OpenFlow,
Ryu supports fully 1.0, 1.2, 1.3, 1.4, 1.5 and Nicira Extensions.

All of the code is freely available under the Apache 2.0 license. Ryu
is fully written in Python.


Quick Start
===========
Installing Ryu is quite easy::

   % pip install ryu

If you prefer to install Ryu from the source code::

   % git clone git://github.com/osrg/ryu.git
   % cd ryu; python ./setup.py install

If you want to write your Ryu application, have a look at
`Writing ryu application <http://ryu.readthedocs.org/en/latest/writing_ryu_app.html>`_ document.
After writing your application, just type::

   % ryu-manager yourapp.py


Optional Requirements
=====================

Some functionalities of ryu requires extra packages:

- OF-Config requires lxml
- NETCONF requires paramiko
- BGP speaker (ssh console) requires paramiko

If you want to use the functionalities, please install requirements::

    % pip install lxml
    % pip install paramiko


Support
=======
Ryu Official site is `<http://osrg.github.io/ryu/>`_.

If you have any
questions, suggestions, and patches, the mailing list is available at
`ryu-devel ML
<https://lists.sourceforge.net/lists/listinfo/ryu-devel>`_.
`The ML archive at Gmane <http://dir.gmane.org/gmane.network.ryu.devel>`_
is also available.
