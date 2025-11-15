# ft_traceroute

My **ft_traceroute** project for the 42 school cursus.

## Getting Started

You need to compile the project with `make`.

### Usage

```
Usage: traceroute [-dIrSv] [-f first_ttl] [-m max_ttl]
        [-p port] [-q nqueries] [-w waittime] host [packetlen]
```

## Overview

The ft_traceroute program is a network diagnostic tool used to trace the path that packets take from the source to a specified destination host. It works by sending packets with gradually increasing Time-To-Live (TTL) values and recording the responses from each hop along the route.

It is based on the BSD traceroute implementation which uses a different approach compared to GNU/Linux traceroute. This implementation uses two sockets; one to send UDP packets with varying TTL values, and another to listen for ICMP "Time Exceeded" messages from intermediate routers. This method is more flexible but requires elevated privileges to create raw sockets, typically having a setuid bit enabled to be run by non-root users.