# About #

The node configurator server is used in combination with the [node configurator server](https://github.com/sudomesh/node-configurator) to auto-configure newly flashed routers for peoplesopen.net

The server runs on e.g. a normal Debian machine and the client runs on the the newly flashed router. When the router boots up, the client is started. The client attempts to find node configurator servers on the network using DNS Service Discovery (DNS-SD), resolves the hostname using multicast DNS (mDNS) and then connects to the first found server to which it can establish a secure SSL connection. The configuration server interfaces to a peoplesopen.net admin via a web app and sends configuration information to the client. The client configures itself using the received information (usually by installing an ipk) and runs a post-configuration command (usually reboot).

# Requirements #

## Lua libraries ##

* string
* socket
* luasec

On Debian-based systems, lua and the required lua libraries can be installed using:

```
aptitude install lua5.1 lua-socket lua-sec
```

## Other requirements ##

* [mdnssd-min](https://github.com/sudomesh/mdnssd-min) is required if you want to use DNS service discovery (the alternative is specifying hostname and port manually).

* A copy of the root certificate you plan to trust. The node configurator server must be using a certificate that can trace its chain of trust back to this root certificate.

# Configuration #

Copy config.json.example to config.json and edit to suit your needs.

# Usage #

If run with no arguments, nodeconfclient will use mdnssd-min to search for and resolve node configurator services on the LAN and attempt to connect to each found service until success.

```
Arguments: 

         --host: Specify server hostname manually.
                 (must be used with --port)
         --port: Specify server port manually.
    -h / --help: Print version and usage info.
 -v / --version: Print version info.

```

# License #

nodeconfclient.lua and config.json.example are licensed under GPLv3. 

getopt_alt.lua and dkjson-min.lua include their own license information.