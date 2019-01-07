import pyshark
import time
import threading

# Store how many times an ip is a packet's source or destination,
# as well as how many times a packet is sent from a specific source to a specific destination.

SRCs = {}
DSTs = {}
PATHs = {}

def print_callback(pkt):
	if 'ip' in pkt:
		SRCs[pkt.ip.src] = SRCs.get(pkt.ip.src, 0) + 1
		DSTs[pkt.ip.dst] = DSTs.get(pkt.ip.dst, 0) + 1
		PATHs[(pkt.ip.src, pkt.ip.dst)] = PATHs.get((pkt.ip.src, pkt.ip.dst), 0) + 1

def run():
	cap = pyshark.LiveCapture(interface='Wi-Fi 2')

	# Run this in a separate thread so we can see the data real-time.
	t = threading.Thread(None, cap.apply_on_packets, args=(print_callback,))
	t.start()

	while True:
		# Print all the paths in order of the source, as well as how many times we've seen that path.
		last_src = ""
		print("Current state: ")
		for path in sorted(PATHs):
			if last_src != path[0]:
				print("{:15} --> {:15} : {}".format(path[0], path[1], PATHs[path]))
				last_src = path[0]
			else:
				print("{:19} {:15} : {}".format("", path[1], PATHs[path]))
		print()

		time.sleep(1)

if __name__ == "__main__":
	run()