BIRD-LG
=======

This is a looking glass for the Internet Routing Daemon "Bird".


Software is split in two parts:

 - lgproxy.py:

   It must be installed and started on all bird nodes. It act as a proxy to make traceroute and bird query on the node.
   Access restriction to this web service can be done in file "lgproxy.cfg" (only IP address based restriction for now).

 - lg.py:

   This is the frontend, a web based UI that request informations to all lgproxy.py nodes.
   The domain and the list of all bird nodes can be done.


```


                                         ***************
                                    +--> * lgproxy.py *
                                    |    ***************
                                    |  
********       *******************  |    ***************
* USER * ----> * webserver/lg.py *--+--> * lgproxy.py *
********       *******************  |    ***************
                                    |  
                                    |    ***************
                                    +--> * lgproxy.py *
                                         ***************
```

Installation
------------

```
apt-get install python-memcache python-flask python-pydot python-dnspython libapache2-mod-wsgi
```

bird-lg depends on :

 - python-flask  >= 0.8
 - python-dnspython
 - python-pydot

Each services can be embedded in any webserver by following regular python-flask configuration.

You should copy the configuration files (`lgproxy.cfg.example` to `lgproxy.cfg`
and `lg.cfg.example` to `lg.cfg`) and edit them.

Should work with most Bird versions (from 1.2.x, tested up to 1.4.5).

Source code is under GPL 3.0, powered by Flask, jQuery and Bootstrap.

Copyright © 2012 Mehdi Abaakouk <sileht@sileht.net>
