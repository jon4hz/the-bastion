# The good, the bad and a list of things that aren't done yet

# The good
- we have controlled port forwarding that integrates seemlessly with the existing access control
- port forwarding rule = host + ssh_port + forward_port +
- port forwarding feature must be enabled in the config
- port forwarding rule can be owned by groups and accounts
- accounts get access to port forwardings the same way they get access to servers
- aclkeepers have permission to manages port forwards of groups
- every forwarding rule gets a random local port assigned, an sshd config is generated for every user, 
  so that they can only access

# the bad
- only local forwarding is possible (is that really bad?)
- honestly no idea if it works with realms. The feature isn't well documented and my French isn't good enough to understand that one video on youtube.
- no unit tests yet
- tested only on debian 13
- if server gets removed, associated portforwards still persist. Should they get removed automatically?
- when allocating a local port, we check only on the master if that port is free. We also have no guarantee that this 
  port doesn't get allocated by another process. However, I have no idea how to avoid this and I think this is an
  acceptable risk.
- I'm not sure how to log connections if the client uses the `-N` option from ssh
- the portforward parameters are logged in the comment field for now
- this is currently only supported on servers using systemd

# the list of things that arent done yet
- ttl not tested yet
- sync sshd forwarding configs and reload remote sshd server
- close connections if rule gets deleted or user gets removed from group
- remote-user param could probably be removed, since we should use the existing allowdeny functions to check access for port forwardings
- Guest access not tested yet
- allow deletion by id to make commands simpler
- not tested --force-key and --force-password options
- not tested grant role thingy yet


# The uncertain
- should we automatically add the `-N` parameter when starting a port forwarding session?
- the remote host from the `-L` flag is currently always the ip of the remote host. Should we allow 127.0.0.1 as well? 
  Or even enforce it?
- do we have to make changes to the auditor function?
- require mfa to connect?
  
How does it work with session locking?


# Fully tested commands:

- [x] accountAddPortForward
- [x] accountDelPortForward
- [x] accountListPortForward
- [x] selfAddPortForward
- [x] selfDelPortForward
- [x] selfListPortForward
- [x] groupAddPortForward
- [x] groupDelPortForward
- [x] groupListPortForward
- [ ] groupAddGuestPortForward
- [ ] groupDelGuestPortForward
