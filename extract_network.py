import re
import logging
import dns.resolver
import dns.inet
import ipaddress

logger = logging.getLogger("EXTRACT_NETWORK")
# create console handler
formatter = logging.Formatter('%(levelname)s: %(message)s')
consoleHandle = logging.StreamHandler()
consoleHandle.setLevel(logging.DEBUG)
consoleHandle.setFormatter(formatter)
logger.addHandler(consoleHandle)
logger.setLevel(logging.DEBUG)


class PAC_Network(object):
    def __init__(self, pac_filename="accelerated_pac_base.pac"):
        self.pac_filename = pac_filename
        self.proxy = []
        self.host_domain = []
        self.net = []
        self.unified_net = []
        self.logger = logging.getLogger("EXTRACT_NETWORK")

    def _extract_target_host_and_net(self, lineno, line):
        match = re.search(r'dnsDomainIs\(.+,\s+"([^"]+)"\)', line)
        if match:
            self.host_domain.append(match.group(1))
            return
        match = re.search(r'isInNet\(.+,\s+"([^"]+)",\s+"([^"]+)"\)', line)
        if match:
            self.net.append([match.group(1), match.group(2)])
            return
        raise Exception("line {} unknow format which return DIRECT: '{}'".format(lineno, line))

    def extract_all_host_and_network(self):
        with open(self.pac_filename) as f:
            lines = f.readlines()
        for index, line in enumerate(lines):
            if re.match(r"\s*//", line):
                # it's a comment
                continue
            match = re.search(r"return\s+(.+)$", line)
            if match:
                return_stuff = match.group(1).strip()
                if not return_stuff.endswith(";"):
                    raise Exception("line {} not end with ';' : '{}'".format(index+1, line))
                match = re.search(r'"DIRECT"\s*;', return_stuff)
                if match:
                    # the target is not through proxy, so need add them in route
                    self._extract_target_host_and_net(index + 1, line)
                    continue
                match = re.search(r'"PROXY\s+(\S+):\d+"', return_stuff)
                if match:
                    proxy = match.group(1)
                    if proxy not in self.proxy:
                        self.proxy.append(proxy)
                else:
                    raise Exception("line {} unknow return statement: '{}'".format(index+1, line))
        self._convert_name_to_address()
        self.unify_net()

    def _resolve(self, resolver, name):
        try:
            answer = resolver.query(name, "A")
            self.logger.debug("{}: {}".format(name, " ".join([x.address for x in answer])))
            for a in answer:
                self.net.append([a.address, "255.255.255.255"])
        except Exception as e:
            self.logger.debug("Error for {}: {}".format(name, e))

    def _convert_name_to_address(self):
        myResolver = dns.resolver.Resolver()
        if "192.168.1.1" in myResolver.nameservers:
            myResolver.nameservers.remove("192.168.1.1")

        for h in self.proxy:
            try:
                af = dns.inet.af_for_address(h)
                if af == dns.inet.AF_INET:
                    self.net.append([h, "255.255.255.255"])
                else:
                    raise Exception("IPV6 is not supported: '{}'".format(h))
            except ValueError:
                self._resolve(myResolver, h)

        for h in self.host_domain:
            self._resolve(myResolver, h)

        for net in self.net:
            self.logger.info("{} {}".format(net[0], net[1]))

    @staticmethod
    def is_subnet_of(a, b):
        try:
            # Always false if one is v4 and the other is v6.
            if a._version != b._version:
                raise TypeError(f"{a} and {b} are not of the same version")
            return (b.network_address <= a.network_address and
                    b.broadcast_address >= a.broadcast_address)
        except AttributeError:
            raise TypeError(f"Unable to test subnet containment "
                            f"between {a} and {b}")

    def unify_net(self):
        for net in self.net:
            if net[0].startswith("127.") or net[0] == "0.0.0.0":
                self.logger.debug("ignore address {} {}".format(net[0], net[1]))
                continue
            netaddr = ipaddress.IPv4Network("{}/{}".format(net[0], net[1]), strict=False)
            contained = False
            for index, n in enumerate(self.unified_net):
                if n.overlaps(netaddr):
                    if self.is_subnet_of(netaddr, n):
                        self.logger.warning("{} is subnet of {}, skipped".format(netaddr, n))
                        contained = True
                        break
                    elif self.is_subnet_of(n, netaddr):
                        self.logger.warning("{} is supernet of {}, replace it".format(netaddr, n))
                        self.unified_net[index] = netaddr
                        contained = True
                        break
                    else:
                        self.logger.warning("{} is overlap of {}, will add it".format(netaddr, n))
            if not contained:
                self.unified_net.append(netaddr)
        self.unified_net.sort()
        for n in self.unified_net:
            self.logger.debug("{} {}".format(n.network_address, n.netmask))


if __name__ == "__main__":
    logger.setLevel(logging.WARNING)
    pac_net = PAC_Network()
    pac_net.extract_all_host_and_network()
    with open("pacnet.txt", "w", encoding="ascii") as f:
        for n in pac_net.unified_net:
            f.write("{}, {}\n".format(n.network_address, n.netmask))