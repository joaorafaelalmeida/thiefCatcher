import sys
import argparse
import pyshark
import datetime
import time
from netaddr import IPNetwork, IPAddress, IPSet

npkts=0

def pkt_callback(pkt):
	global scnets
	global ssnets
	global npkts
	global c
	global T0
	global lastks
	global sampDelta
	global obsDelta

	if (IPAddress(pkt.ip.src) in scnets and IPAddress(pkt.ip.dst) in ssnets) or (IPAddress(pkt.ip.src) in ssnets and IPAddress(pkt.ip.dst) in scnets):
		t=float(pkt.sniff_timestamp)
		if npkts==0:
			T0=t
			lastks=0
			c=[0,0,0,0]
		ks=int((t-T0)/sampDelta)
		ko=int((t-T0)/obsDelta)
		
		if ks!=lastks:
			koaux=int(lastks*sampDelta/obsDelta)
			print("Obs.Wnd., Sampling Wnd. -> {}, {}: [{},{},{},{}]".format(koaux,lastks,*c))
			for k in range(lastks+1,ks):
				koaux=int(k*sampDelta/obsDelta)
				print("Obs.Wnd., Sampling Wnd. -> {}, {}: [{},{},{},{}]".format(koaux,k,0,0,0,0))
			c=[0,0,0,0]
		
		if IPAddress(pkt.ip.src) in scnets: #Upload
			c[0]=c[0]+int(pkt.ip.len)
			c[1]=c[1]+1

		if IPAddress(pkt.ip.dst) in scnets: #Download
			c[2]=c[2]+int(pkt.ip.len)
			c[3]=c[3]+1

		npkts=npkts+1
		if pkt.ip.proto=='17':
			print('{}: IP packet from {} (UDP:{}) to {} (UDP:{}) {}'.format(pkt.sniff_timestamp,pkt.ip.src,pkt.udp.srcport,pkt.ip.dst,pkt.udp.dstport,pkt.ip.len))
		elif pkt.ip.proto=='6':
			print('{}: IP packet from {} (TCP:{}) to {} (TCP:{}) {}'.format(pkt.sniff_timestamp,pkt.ip.src,pkt.tcp.srcport,pkt.ip.dst,pkt.tcp.dstport,pkt.ip.len))
		else:
			print('{}: IP packet from {} to {} (other) {}'.format(pkt.sniff_timestamp, pkt.ip.src,pkt.ip.dst,pkt.ip.len))
		lastks=ks

def printAtEnd():
	global c
	global T0
	global lastks
	global 	sampDelta
	global obsDelta
	
	t=time.time()
	ks=int((t-T0)/sampDelta)

	koaux=int(lastks*sampDelta/obsDelta)
	print("Obs.Wnd., Sampling Wnd. -> {}, {}: [{},{},{},{}]".format(koaux,lastks,*c))
	for k in range(lastks+1,ks):
		koaux=int(k*sampDelta/obsDelta)
		print("Obs.Wnd., Sampling Wnd. -> {}, {}: [{},{},{},{}]".format(koaux,k,0,0,0,0))
	
	return

def main():
	parser=argparse.ArgumentParser()
	parser.add_argument('-i', '--interface', nargs='?',required=True, help='capture interface')
	parser.add_argument('-c', '--cnet', nargs='+',required=True, help='client network(s)')
	parser.add_argument('-s', '--snet', nargs='+',required=True, help='service network(s)')
	parser.add_argument('-t', '--tcpport', nargs='?',help='service TCP port (or range)')
	parser.add_argument('-u', '--udpport', nargs='?',help='service UDP port (or range)')
	args=parser.parse_args()
	
	cnets=[]
	for n in args.cnet:
		try:
			nn=IPNetwork(n)
			cnets.append(nn)
		except:
			print('{} is not a network prefix'.format(n))
	print(cnets)
	if len(cnets)==0:
		print("No valid client network prefixes.")
		sys.exit()
	global scnets
	scnets=IPSet(cnets)

	snets=[]
	for n in args.snet:
		try:
			nn=IPNetwork(n)
			snets.append(nn)
		except:
			print('{} is not a network prefix'.format(n))
	print(snets)
	if len(snets)==0:
		print("No valid service network prefixes.")
		sys.exit()
		
	global ssnets
	ssnets=IPSet(snets)
		
	if args.udpport is not None:
		cfilter='udp portrange '+args.udpport
	elif args.tcpport is not None:
		cfilter='tcp portrange '+args.tcpport
	else:
		cfilter='ip'

	global npkts
	global T0
	global sampDelta
	global obsDelta
	npkts=0
	T0={}
	sampDelta=1
	obsDelta=30

	cint=args.interface
	print('Filter: {} on {}'.format(cfilter,cint))
	try:
		capture = pyshark.LiveCapture(interface=cint,bpf_filter=cfilter)
		capture.apply_on_packets(pkt_callback)
	except KeyboardInterrupt:
		print('\n{} packets captured!'.format(npkts))
		printAtEnd()
		print("Done!\n")

if __name__ == '__main__':
    main()
