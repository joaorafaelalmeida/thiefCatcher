import argparse
import numpy as np
import matplotlib.pyplot as plt

'''
Junta varias janelas de amostragem
tem sequenciais, sidling e multisliding
'''
def seqObsWindow(data,lengthObsWindow):
    nSamples,nMetrics=data.shape
    print("Observation window size: {}".format(lengthObsWindow))
    for s in np.arange(lengthObsWindow,nSamples,lengthObsWindow):
        print("\nAt sample: {}\n".format(s-1))
        subdata=data[s-lengthObsWindow:s,:]
        print(subdata)
        
def slidingObsWindow(data,lengthObsWindow,slidingValue):
    nSamples,nMetrics=data.shape
    print("Observation window size: {}\nSliding value: {}".format(lengthObsWindow,slidingValue))
    for s in np.arange(lengthObsWindow,nSamples,slidingValue):
        print("\nAt sample: {}\n".format(s-1))
        subdata=data[s-lengthObsWindow:s,:]
        print(subdata)
        
def slidingMultObsWindow(data,lengthObsWindow,slidingValue):
    nSamples,nMetrics=data.shape
    for s in np.arange(max(lengthObsWindow),nSamples,slidingValue):
        for oW in lengthObsWindow:
            print("\nAt sample: {}\nObservation window size: {}\nSliding value: {}".format(s-1,oW,slidingValue))
            subdata=data[s-oW:s,:]
            print(subdata)


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
    
    obsWindows=[5,10]
    for oW in obsWindows:
        seqObsWindow(data,oW)
        
    obsWindows=[5,10]
    slidingValue=3
    for oW in obsWindows:
        slidingObsWindow(data,oW,slidingValue)
        
    obsWindows=[5,10]
    slidingValue=3
    slidingMultObsWindow(data,obsWindows,slidingValue)
            
        

if __name__ == '__main__':
    main()
