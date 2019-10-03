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


class Combine_Net(object):
    def __init__(self):
        self.network = []
        self.unified_network = []
        self.logger = logging.getLogger("EXTRACT_NETWORK")

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

    def add_net_from_file(self, filename):
        with open(filename) as f:
            lines = f.readlines()
        for index, line in enumerate(lines):
            line = line.strip("\r\n")
            match = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+),\s*(\d+\.\d+\.\d+\.\d+)", line)
            if match:
                network_address = match.group(1)
                netmask = match.group(2)
                if network_address.startswith("127.") or network_address == "0.0.0.0":
                    self.logger.debug("ignore address {} line {}: {}".format(filename, index+1, line))
                    continue
                self.network.append(ipaddress.IPv4Network("{}/{}".format(network_address, netmask), strict=False))
            else:
                self.logger.debug("ignore text {} line {}: {}".format(filename, index + 1, line))

    def unify_net(self):
        for net in self.network:
            contained = False
            for uni_net in self.unified_network:
                if self.is_subnet_of(net, uni_net):
                    self.logger.warning("{} is subnet of {}, skipped".format(net, uni_net))
                    contained = True
                    break
            if contained:
                continue

            new_unified_network = []
            for uni_net in self.unified_network:
                if self.is_subnet_of(uni_net, net):
                    self.logger.warning("{} is supernet of {}, replace it".format(net, uni_net))
                else:
                    new_unified_network.append(uni_net)
            self.unified_network = new_unified_network

            for uni_net in self.unified_network:
                if uni_net.overlaps(net):
                    self.logger.warning("{} is overlap of {}, still will add it".format(net, uni_net))
            self.unified_network.append(net)
        self.unified_network.sort()
        for n in self.unified_network:
            self.logger.debug("{} {}".format(n.network_address, n.netmask))


if __name__ == "__main__":
    logger.setLevel(logging.DEBUG)
    comb_net = Combine_Net()
    comb_net.add_net_from_file("pacnet.txt")
    comb_net.add_net_from_file("intranet.txt")
    comb_net.unify_net()
    logger.debug("process again")
    logger.setLevel(logging.INFO)
    comb_net.network = comb_net.unified_network[:]
    comb_net.unified_network = []
    comb_net.unify_net()
    with open("intranet.network", "w", encoding="ascii") as f:
        for n in comb_net.unified_network:
            f.write("{}, {}\n".format(n.network_address, n.netmask))