# The good, the bad and a list of things that aren't done yet

# The good
- port forwarding rule = host + ssh_port + forward_port +
- port forwarding feature must be enabled in the config
- port forwarding rule can be owned by groups and accounts
- accounts get access to port forwardings the same way they get access to servers
- aclkeepers have permission to manages port forwards of groups
- every forwarding rule gets a random local port assigned, an sshd config is generated for every user, 
  so that they can only access
- 

# the bad
- only local forwarding is possible
- honestly no idea if it works with realms. The feature isn't well documented and my French isn't good enough to understand that one video on youtube.
- no unit tests yet
- tested only on debian 13
- if server gets removed, associated portforwards still persist. Should they get removed automatically?

# the list of things that arent done yet
- ttl not tested yet
- sync sshd forwarding configs and reload remote sshd server
- close connections if rule gets deleted or user gets removed from group
- remote-user param could probably be removed, since we should use the existing allowdeny functions to check access for port forwardings
- Guest access not tested yet
- allow deletion by id to make commands simpler
- not tested --force-key and --force-password options
- not tested grant role thingy yet



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
