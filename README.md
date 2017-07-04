# Psniff - Network Analyser
psniff is designed and written with the goal of makeing packet sniffing more simple, it does this with simple to understand packet decodes, support for tcpdump and wireshark filters and simple color highlighting for the packets

## Installation

	$ git clone https://www.github.com/Dylan-Halls/Psniff.git
	$ cd Psniff
	$ ./configure

This will download psniff from github then install and configure it for your system. Now to check the installation type

	$ psniff -v

## Packet Sniffing

For a simple packet sniff just run <code>psniff</code> with no arguments

for a more complex sniff run

	$ psniff --filter

and then when prompted enter any tcpdump/wireshark compatible filter

and to sniff any udp packets pass the option <code>--udp</code>