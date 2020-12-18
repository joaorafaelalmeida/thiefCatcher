import sys
import argparse
import pyshark
from datetime import datetime
from netaddr import IPNetwork, IPAddress, IPSet
from lxml import etree

now = datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
npkts=0
resultsDir="results/"
fileUDP=open('{}udp.txt'.format(resultsDir), 'a')
fileTCP=open('{}tcp{}.txt'.format(resultsDir, now), 'w')
fileTCPUp=open('{}tcpUpload{}.txt'.format(resultsDir, now), 'w')
fileTCPDown=open('{}tcpDownload{}.txt'.format(resultsDir, now), 'w')
fileWin=open('{}tcpWindows{}.txt'.format(resultsDir, now), 'w')
fileOther=open('{}other.txt'.format(resultsDir), 'a')

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

		#Captured packages slit by TCP, UDP and others
		if pkt.ip.proto=='6':
			fileTCP.write('{}:{}\n'.format(lastks,pkt.ip.len))

			#New observation window
			if ks!=lastks: #Nova janela de amostragrem
				koaux=int(lastks*sampDelta/obsDelta)
				fileWin.write("{} {} {} {} {}\n".format(lastks,*c))
				for k in range(lastks+1,ks):
					koaux=int(k*sampDelta/obsDelta)
					fileWin.write("{} {} {} {} {}\n".format(k,0,0,0,0))
				c=[0,0,0,0]

				print(lastks)
				if lastks >= 286:
					raise Exception('I know Python!')
			
			#Upload packages
			if IPAddress(pkt.ip.src) in scnets:
				c[0]=c[0]+int(pkt.ip.len)
				c[1]=c[1]+1
				fileTCPUp.write('{}:{}\n'.format(lastks,pkt.ip.len))

			#Download packages
			if IPAddress(pkt.ip.dst) in scnets:
				c[2]=c[2]+int(pkt.ip.len)
				c[3]=c[3]+1
				fileTCPDown.write('{}:{}\n'.format(lastks,pkt.ip.len))
		
		elif pkt.ip.proto=='17':
			fileUDP.write('{}:{}\n'.format(lastks,pkt.ip.len))
		else:
			fileOther.write('{}:{}\n'.format(lastks,pkt.ip.len))
		
		lastks=ks
		npkts=npkts+1

def main():#python thiefCatcher.py -i Wi-Fi -c 192.168.1.109 -s 192.168.1.253  
	parser=argparse.ArgumentParser()
	parser.add_argument('-i', '--interface', nargs='?',required=True, help='capture interface')
	parser.add_argument('-c', '--cnet', nargs='+',required=True, help='client network(s)')#redes de clientes com base nos endereços dos clientes
	parser.add_argument('-s', '--snet', nargs='+',required=True, help='service network(s)')#redes de clientes com base nos endereços dos serviços
	parser.add_argument('-t', '--tcpport', nargs='?',help='service TCP port (or range)')
	parser.add_argument('-u', '--udpport', nargs='?',help='service UDP port (or range)')
	args=parser.parse_args()
	'''
	destino ip serviços-> upload
	destino ip serviços-> download
	
	Separar download de upload
	'''

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
	except etree.XMLSyntaxError as e:
		print(e)
	except KeyboardInterrupt:
		print('\n{} packets captured!'.format(npkts))
		print("Done!\n")
		fileUDP.close()
		fileTCP.close()
		fileTCPUp.close()
		fileTCPDown.close()
		fileOther.close()
		fileWin.close()

if __name__ == '__main__':
	main()


'''
Usar tamanho dos pacotes
usar numero de pacotes por janela temporal
sampDelta = intervalo de amostragem

Perguntas:
Qual das janelas observacionais devo usar?
Para extrair features, que janela usar?
Acho que preciso da periocidade, nao?

Deteçao de anomalias nao serve como classificaçao???? sou de anomalias
cntar o numero de tempo seguido de silencio e de atividade

grava as aulas? eu vi um processo do obs na barra
coisas que posso fazer diferente
-> tratamentos dos dados iniciais, como crio as features
-> fazer um algoritmo novo, estudo dos melhores parametros
-> usar multiplos, paralelo ou serie, detetar anomalias e depois classificar, decisao a varios passos
	-> attention networks
	
-> tentar is bucar info que nao é geralmente passada para o ML e DL
	-> definir parametro mastigados
'''