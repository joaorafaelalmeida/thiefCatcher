import argparse
import scipy.stats as stats
import scipy.signal as signal
import numpy as np
import matplotlib.pyplot as plt
import scalogram

def plotPeriodogram(data):
    # fft=np.fft.fft(data)
    # psd=abs(fft)**2
    # plt.plot(psd[:50])
    
    f,psd=signal.periodogram(data)
    plt.plot(1/f[:50],psd[:50])
    plt.show()
    
def plotScalogram(data):
    scales=np.arange(1,50)
    S,scales=scalogram.scalogramCWT(data,scales)
    plt.plot(scales,S)
    plt.show()

def slidingMultObsWindow(data,lengthObsWindow,slidingValue):
    nSamples,nMetrics=data.shape
    for s in np.arange(max(lengthObsWindow),nSamples,slidingValue):
        for oW in lengthObsWindow:
            subdata=data[s-oW:s,1]
            #plotPeriodogram(subdata)
            plotScalogram(subdata)

    
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('-i', '--input', nargs='?',required=True, help='input file')
    args=parser.parse_args()
    
    fileInput=args.input
        
    data=np.loadtxt(fileInput,dtype=int)
    
    # plt.subplot(2,1,1)
    # plt.plot(data[:,0],data[:,1],data[:,0],data[:,3])
    # plt.subplot(2,1,2)
    # plt.plot(data[:,0],data[:,2],data[:,0],data[:,4])
    # plt.show()
            
    obsWindows=[285]
    slidingValue=285
    slidingMultObsWindow(data[:,:2],obsWindows,slidingValue)
            
        

if __name__ == '__main__':
    main()
