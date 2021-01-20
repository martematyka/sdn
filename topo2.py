# sudo mn --custom example-topo.py --topo mytopo --mac --controller remote --switch ovsk

from mininet.topo import Topo

"""
Topologia
h1-s1-             s11                -s4-h3
h2-              s12- s22                -h4
               s13- s23- s33
             s14- s24- s34- s44
"""
class MyTopo( Topo):
    
    def __init__(self):
        Topo.__init__(self)
        
        #deklaracja 4 hostÃ³w
        host1 = self.addHost('h1') #source of traffic 1
        host2 = self.addHost('h2') #source of traffic 2

        host3 = self.addHost('h3') #DHCP Server
        host4 = self.addHost('h4') #DHCP Client
        host5 = self.addHost('h5') #attacker

        
        #pierwszy switch
        switch1 = self.addSwitch('s1')
        self.addLink(switch1, host1, 1)
        self.addLink(switch1, host2, 2)

        switch4 = self.addSwitch('s4')

        #pierwsza warstwa switchy
        switch11 = self.addSwitch('s11')
        switch12 = self.addSwitch('s12')
        switch13 = self.addSwitch('s13')
        switch14 = self.addSwitch('s14')

        #polaczenie pierwszej warstwy ze switchem1
        self.addLink(switch1, switch11, 3, 1, delay = '5ms')
        self.addLink(switch1, switch12, 4, 1, delay = '20ms')
        self.addLink(switch1, switch13, 5, 1, delay = '35ms')
        self.addLink(switch1, switch14, 6, 1, delay = '50ms')
        
        #druga warstwa switch
	switch21 = self.addSwitch('s21')
        switch22 = self.addSwitch('s22')
        switch23 = self.addSwitch('s23')
        switch24 = self.addSwitch('s24')

        #trzecia warstwa switchy
	switch31 = self.addSwitch ('s31')
	switch32 = self.addSwitch ('s32')
        switch33 = self.addSwitch('s33')
        switch34 = self.addSwitch('s34')

        #czwarta warstwa switchy
        #switch44 = self.addSwitch('s44')
       
        #laczenie warst
	self.addLink(switch11, switch21, 2, 1, delay = '5ms')
        self.addLink(switch12, switch22, 2, 1, delay = '20ms')
        self.addLink(switch13, switch23, 2, 1, delay = '35ms')
        self.addLink(switch14, switch24, 2, 1, delay = '50ms')
        
	self.addLink(switch21, switch31, 2, 1, delay = '5ms')
	self.addLink(switch22, switch32, 2, 1, delay = '20ms')
        self.addLink(switch23, switch33, 2, 1, delay = '35ms')
        self.addLink(switch24, switch34, 2, 1, delay = '50ms')

        #self.addLink(switch34, switch44, 2, 1)

        #podlaczenie switcha4 ze switchami
        self.addLink(switch4, switch31, 1, 2)
        self.addLink(switch4, switch32, 2, 2)
        self.addLink(switch4, switch33, 3, 2)
        self.addLink(switch4, switch34, 4, 2)
        
        #ostatni switch
        self.addLink(switch4, host3, 5)
        self.addLink(switch4, host4, 6)
        self.addLink(switch4, host5, 7)

           
topos = { 'mytopo': (   lambda: MyTopo()   ) }
