import std/[strformat, strutils, sequtils, tables, sets]
import std/posix
import libnetfilter_queue, lrucache, regex

proc c_signal(sig: cint, handler: proc (a: cint) {.noconv.}) {.importc: "signal", header: "<signal.h>".}

type
  IPv4 = (uint8, uint8, uint8, uint8)
  PacketInfo = object
    ip: IPv4
    sport, dport: uint16
    flags: uint8

var
  rbls: seq[string]
  wlconfig, blconfig: HashSet[IPv4]
  cache = newLRUCache[IPv4, bool](10000)
  nfq: NetfilterQueue
  queueNo = -1

proc onStop(sig: cint) {.noconv.} =
  nfq.close
  quit(QuitSuccess)

proc `$`(ip: IPv4): string = &"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}"

proc canResolve(host: string): bool =
  var hints: AddrInfo
  var res: ptr AddrInfo
  hints.ai_family = AF_INET
  hints.ai_socktype = SOCK_STREAM
  hints.ai_protocol = IPPROTO_TCP
  if 0 == getaddrinfo(host, "80", hints.addr, res):
    freeAddrInfo(res)
    return true
  return false

proc blacklisted(ip: PacketInfo): bool =
  if ip.ip in wlconfig: return true
  if ip.ip in blconfig: return false
  if ip.ip in cache: return cache[ip.ip]
  for rbl in rbls:
    let host = &"{ip.ip[3]}.{ip.ip[2]}.{ip.ip[1]}.{ip.ip[0]}.{rbl}"
    if canResolve(host):
      cache[ip.ip] = true
      return true
  cache[ip.ip] = false
  return false

# https://github.com/zevenet/packetbl/blob/master/src/packetbl.c#L929
proc get_packet_info(payload: openArray[uint8]): PacketInfo =
  let
    version = (payload[0] and 0xF0) shr 4
    iplen = (payload[0] and 0x0F) shl 2
  if version != 4: return
  result.ip = (payload[12], payload[13], payload[14], payload[15])
  result.s_port = (payload[iplen].uint16 shl 8) or payload[iplen+1].uint16
  result.d_port = (payload[iplen + 2].uint16 shl 8) or payload[iplen+3].uint16
  result.flags = payload[iplen + 13].uint8 and 0x3F

proc cb(id: uint32, buffer: pointer, bufLen: int32, res: var Result) =
  res.verdict = NF_ACCEPT
  if buffer == nil: return
  let ip = get_packet_info(cast[ptr UncheckedArray[uint8]](buffer).toOpenArray(0, bufLen-1))
  if blacklisted(ip):
    res.verdict = NF_DROP

func parseIPv4(ip: string): IPv4 =
  let parts = ip.split('.').mapIt(it.parseInt.uint8)
  result[0] = parts[0]
  result[1] = parts[1]
  result[2] = parts[2]
  result[3] = parts[3]

proc readConfig(path: string) =
  var lineNo = 1
  var m: RegexMatch
  for line in path.lines:
    if line.match(re"^rbl\s+([\w.-]+)\s*(?:#.*)?$", m):
      rbls.add m.group(0, line)[0]
    elif line.match(re"^queue\s+(\d+)\s*(?:#.*)?$", m):
      if queueNo >= 0:
        quit &"packetbl: {path}({lineNo}): duplicate `queue` config"
      queueNo = m.group(0, line)[0].parseInt
    elif line.match(re"^blacklist\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9])\s*(?:#.*)?$", m):
      blconfig.incl m.group(0, line)[0].parseIPv4
    elif line.match(re"^whitelist\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9])\s*(?:#.*)?$", m):
      wlconfig.incl m.group(0, line)[0].parseIPv4
    elif line.match(re"^\s*(?:#.*)?$"):
      discard
    else:
      quit &"packetbl: {path}({lineNo}): didn't understand config line: {line}"
    lineNo.inc
  if rbls.len == 0:
    quit "packetbl config failed to define any RBLs"
  if queueNo < 0:
    quit "packetbl config failed to set the queue"

proc dumpConfig(path: string) =
  echo "# packetbl config file: ", path
  echo "queue ", queueNo
  for rbl in rbls:
    echo "rbl ", rbl
  for bl in blconfig:
    echo "blacklist ", $bl
  for wl in wlconfig:
    echo "whitelist ", $wl

proc main(config_file = "/etc/packetbl.conf", dump_config = false, foreground = false) =
  readConfig(config_file)
  if dump_config:
    dumpConfig(config_file)
    quit()
  if foreground:
    setControlCHook(proc() {.noconv.} =
      echo "Ctrl+C pressed, exiting.."
      nfq.close
    )
  else:
    if fork() > 0: quit(QuitSuccess)
    discard chdir("/var/run")
    discard setsid()
    discard umask(0)
    if fork() > 0: quit(QuitSuccess)
    flushFile(stdout)
    flushFile(stderr)
    c_signal(SIGINT, onStop)
    c_signal(SIGTERM, onStop)
    c_signal(SIGHUP, onStop)
    c_signal(SIGQUIT, onStop)
  nfq = initNetfilterQueue(queueNo.uint16, cb)
  nfq.run

when isMainModule:
  import cligen
  clCfg.version = "0.1.0"
  dispatch(main, help = {
    "config-file": "Set config file",
    "dump-config": "Dump config and exit",
    "foreground": "Don't daemonize",
  })
