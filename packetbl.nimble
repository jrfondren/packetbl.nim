# Package

version       = "0.1.0"
author        = "Julian Fondren"
description   = "User space daemon that filters packets against realtime blacklists"
license       = "MIT"
srcDir        = "src"
bin           = @["packetbl"]


# Dependencies

requires "nim >= 1.4.0"
requires "libnetfilter_queue >= 0.1.0"
requires "lrucache >= 1.1.3"
requires "cligen >= 1.2.2"
