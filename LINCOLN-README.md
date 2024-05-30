# Using gnbsim

1.  The first step should be to modify the `default.config`.  We need to update the `defaultAmf.ipAddr` value, to be updated with the ip address used by sdcore on the raven mgmt interface.
2. In `default.config` we also need to modify the `httpServer.ipAddr` and `gnbs.gnb1.n3IpAddr` with the ip address that the container gets on the docker network.  This should be a `172.26` ip address based on the aether-onramp values set for the this network.
3.  When making changes, the main file to modify is `realue/worker/pdusessworker/handler.go`.  The two main functions are `handlePacket` which takes packets from gnb and sends over gtp tunnel to the end point.  The other function is `HandleIpv4Packet` which takes the packet from the gtp tunnel and sends it back to gnb.



For both UDP and TCP, We open up a port in gnbsim.  This allows local applications to send traffic to this port.  We then for UDP send it out.  For TCP, we create two connections, one for local and one for remote.  The goal (not yet achieved) is then to bridge traffic between the two tcp sockets.

The issue at this point is I believe the UPF is buffering packets, and we recieve packets out of order, which means that we actually need to manage the TCP connection ourself.  This implementation is currently not working.  We need to properly implement the AckMap, to track/manage the tcp connection and only send data when its been acked correctly.


## How to run

`./bin/gnbsim --cfg default.config` to start.  This will run a 200ish icmp packets, during that time you have a valid pdusession and can send packets over the gtp tunnel.

For the specific commands to run, review the demo on which ffmpeg, ffplay settings were used.


## Notes

`gnodeb/transport/uptransport.go` can be reverted.  The changes to the code here were to make sure that the go channels and threads were not causing the packet re-ordering, that it comes from upstream (UPF).  So going back to using golang channels is fine.
