# tupperwarewithspears

Based off the awesome project
[beeswithmachineguns](https://github.com/newsapps/beeswithmachineguns),
but this uses containers.

Each container is run from a `jess/ab` image, which is just the apache
benchmark utility.

If you pass in a cidr with `-cidr` and gateway with `-gateway`,
containers will be given ips and have outbound traffic routed
via that IP. This uses openvswitch and a super gross
implementation of shelling out to `ovs-vsctl` & `ip netns exec`.

**NOTE:** Do not use this for evil. Consider yourself warned.

```console
$ tws
 _
| |___      _____
| __\ \ /\ / / __|
| |_ \ V  V /\__ \
 \__| \_/\_/ |___/
 Tupperware with Spears (A DDoS Production)
 Author:    Jess Frazelle
 Email:     no-reply@butts.com
 Version:   v0.1.0

 tws [options] [http[s]://]hostname[:port]/path

 Usage of tws:
  -A="": auth-username:password
  -C="": cookie-name=value;cookie-name=value
  -H="": custom-header;custom-header
  -P="": proxy-auth-username:password
  -T="": content type
  -bridge="tws0": bridge name
  -c=100: number of multiple requests to perform at a time. Default is one request at a time
  -cidr="": ip cidr to use for interface from containers
  -d=false: run in debug mode
  -dockerHost="unix://var/run/docker.sock": docker daemon socket to connect to
  -f="ALL": specify SSL/TLS protocol (SSL2, SSL3, TLS1, or ALL)
  -gateway="": set gateway for outbound traffic
  -m="GET": method
  -n=10000: number of requests to perform for the benchmarking session
  -nc=16: number of containers (tupperware) to attack with
  -s=30: timeout, seconds to max. wait for each respone
  -t=0: timelimit, implies a -n 50000 internally
  -tlscert="": path to TLS certificate file
  -tlskey="": path to TLS key file
  -v=3: verbosity, 4 -> headers, 3 -> response codes, 2 -> warnings/info
  -version=false: print version and exit
```

Installing:
```
$ go get github.com/jessfraz/tupperwarewithspears/cmd/tws
```

Example:

```console
$ tws -nc 21 -n 10000 -c 250 https://google.com
```
