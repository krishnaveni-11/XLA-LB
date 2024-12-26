import time
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.topo import Topo

class SimpleTopo(Topo):
    def build(self):
        # Add hosts and assign IPs using format method
        for i in range(1, 26):  # Creating hosts h1 to h10
            self.addHost('h{}'.format(i), ip='172.17.0.{}/24'.format(9 + i))
        
        # Add a switch
        s1 = self.addSwitch('s1')

        # Create links between the switch and the hosts
        for i in range(1, 26):
            self.addLink('h{}'.format(i), s1)

def run():
    # Set Mininet logging level
    setLogLevel('info')
    
    # Create the network from the SimpleTopo
    topo = SimpleTopo()
    net = Mininet(topo=topo, switch=OVSSwitch)
    
    # Start the network
    net.start()
    
    # Configure hosts
    for i in range(1, 26):
        host = net.get('h{}'.format(i))
        # Adjust MAC address based on host index
        mac_address = '02:42:ac:11:00:{:02d}'.format(9 + i)  # Zero-padded to two digits, add 9
        
        # Set MAC address
        print("Configuring host h{} with MAC {}".format(i, mac_address))
        mac_result = host.cmd('ifconfig h{}-eth0 hw ether {}'.format(i, mac_address))
        print("MAC address configuration result: {}".format(mac_result))
        
        # Add default route
        print("Adding default route for h{}".format(i))
        default_route_output = host.cmd('/sbin/ip route add default via 172.17.0.3')
        print("Default route output for h{}: {}".format(i, default_route_output))
        
        # Add specific routes
        for route in ['172.17.0.7/32', '172.17.0.1/32', '172.17.0.6/32','172.17.0.2/32','172.17.0.4/32','172.17.0.5/32']:
            print("Adding route {} for h{}".format(route, i))
            route_output = host.cmd('/sbin/ip route add {} via 172.17.0.3'.format(route))
            print("Route addition output for {}: {}".format(route, route_output))
        
        # Check the routing table after adding routes
        print("Routing table for h{}".format(i))
        print(host.cmd('route -n'))

        # Sleep to allow configurations to take effect
        time.sleep(2)  # Increase sleep to ensure network initialization

   

    # Start CLI for interactive testing
    CLI(net)
    
    # Wait for user input before stopping the network
    input("Press Enter to stop the network...")

    # Stop the network when done
    net.stop()

if __name__ == '__main__':
    run()
