from pyfiglet import Figlet
from scapy.all import *
import signal
import socket

class CoreScanner:
	def __init__(self):
		self.mode = 0
		self.target = ""
		self.port = []

	def tcp_connect_scan(self):
		print("\n SCANNER RESULTS--------")
		print("\n PORT\tSTATUS")
		for x in self.port:
			if x.find("-") == -1:
				with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
					status = s.connect_ex((self.target, int(x)))
					if(status == 0):
						print("\n {}\topen\t".format(x))
			else:
				start = int(x.split("-")[0])
				stop = int(x.split("-")[1])

				for i in range(start,stop):
					with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
						status = s.connect_ex((self.target, i))
						if(status == 0):
							print("\n {}\topen\t".format(i))

	def tcp_syn_scan(self):
		print("\n SCANNER RESULTS--------")
		print("\n PORT\tSTATUS")			
		for x in self.port:
			if x.find("-") == -1:
				try:
					srcport = RandShort()
					conf.verb=0
					packet = sr1(IP(dst = self.target)/TCP(sport=srcport, dport=int(x), flags="S"))
					flags = packet.getlayer(TCP).flags
					if flags == "SA":
						print("\n {}\topen\t".format(x))
					reset_packet= IP(dst = self.target)/TCP(sport=srcport, dport=int(x), flags="R")
					send(reset_packet)
				except PermissionError:
					print("\n Root privileges required for this scan mode!")
					quit()

			else:
				start = int(x.split("-")[0])
				stop = int(x.split("-")[1])
				for i in range(start,stop):
					try:
						srcport = RandShort()
						conf.verb=0
						packet = sr1(IP(dst = self.target)/TCP(sport=srcport, dport=int(i), flags="S"))
						flags = packet.getlayer(TCP).flags
						if flags == "SA":
							print("\n {}\topen\t".format(i))
						reset_packet= IP(dst = self.target)/TCP(sport=srcport, dport=int(i), flags="R")
						send(reset_packet)
					except PermissionError:
						print("\n Root privileges required for this scan mode!")
						quit()

	def setter(self, mode, target, port):
		self.mode = mode
		self.target = target
		self.port = str.split(port)

	def banner(self):
		f = Figlet(font="slant")
		print(f.renderText("Baphomet"))
		print(" by s3pi0l\n")
		print("""
 Note : one or more ports can be specified, separated by a space
 You can also insert a port range by typing 'first_port-last_port' 
			""")

	def menu(self):
		print("""
 Select scanner mode:

  1) TCP Connect (non-root)

  2) TCP SYN (root)
  		""")

		while True:
			try:
				mode = int(input("\n > "))
				if(mode < 7):
					break
				else:
					print("\n Invalid option")
			except ValueError:
				print("\n Invalid option")
		
		print("\n Insert target: ", end='')
		target = input()

		print("\n Insert port: ", end='')
		port = input()

		self.setter(mode, target, port)

		if(self.mode == 1):
			self.tcp_connect_scan()
		elif(self.mode == 2):
			self.tcp_syn_scan()

def main():
	try:
		cs = CoreScanner()
		cs.banner()
		cs.menu()
	except KeyboardInterrupt:
		print("\n\n Program interrupted\n")
		quit()
	print()

if __name__=="__main__":
	main()

