
<h1 align="center">
  <br>
  <a href="https://github.com/joaorafaelalmeida/thiefCatcher"><img src="https://github.com/joaorafaelalmeida/thiefCatcher/blob/master/figs/thiefCatcherLogo.PNG" alt="ThiefCatcher" width="200"></a>
  <br>
</h1>

<h4 align="center">A proof-of-concept system designed for detecting intrusions in the network using machine learning algorithms.</h4>

![screenshot](https://github.com/joaorafaelalmeida/thiefCatcher/blob/master/figs/thiefCatcher.PNG)



## How To Use

To clone and run this application, you'll need Git and Anaconda. From your command line:

```bash
# Clone this repository
$ git clone https://github.com/joaorafaelalmeida/thiefCatcher

# Go into the repository
$ cd thiefCatcher

# Starting capture packages 
$ python capture.py -i <interface> -c <Source IP> -s <Destination IP> 

# Run the malware
# Brute mode
$ python thief -b

# Smooth mode
$ python thief -s

# Intelligent mode
$ python thief -i

# For the detection system, please use Jupyter Notebook
```



## Download

You can [download](https://github.com/joaorafaelalmeida/thiefCatcher/releases/tag/v1.0.0) the latest installable version of ThiefCatcher source code.

