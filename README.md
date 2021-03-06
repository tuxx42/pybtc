# pybtc

## installation

The requirements are listed in requirements.txt and can be installed using

```python
pip3 install -r requirements.txt
```

The code has only been tested to work on python3


## starting the client

When starting the main.py, you will drop into a shell with a object client, which is instance of BitcoinClient.

BitcoinClient is essentially merely a threaded event loop which polls streaming events from a connection socket to which event handlers are hooked. Currently the ip address of a full node has been hardcoded in main.py, which is probably not the best idea :D

To start the client thread, run client.start()


```python
python3 main.py
Welcome to Scapy (3.0.0)
Type "client.start()" to start the client
>>> 
>>> client.start() 
###[ Bitcoin Header ]###
  magic= main
  cmd= 'version\x00\x00\x00\x00\x00'
  len= 102
  checksum= None
###[ BitcoinVersion ]###
     version= 70015
     services= 0
     timestamp= '2017-12-27 18:02:10'
     \addr_recv\
      |###[ AddrWithoutTimePktField ]###
      |  services= 0
      |  addr= ::ffff:217.248.23.25
      |  port= 8333
     \addr_from\
      |###[ AddrWithoutTimePktField ]###
      |  services= 0
      |  addr= ::
      |  port= 0
     nonce= 17183200291397913359
     \user_agent\
      |###[ VarStrPktField ]###
      |  len= None
      |  data= '/Satoshi:0.14.2/'
     start_height= 0
     relay= 1
```


#### protocol specification

The protocol https://en.bitcoin.it/wiki/Protocol_documentation


#### tributes

The binary protocol is implemented in bitcoin.py and was borrowed from https://github.com/jbcayrou/scapy-bitcoin. A special shoutout to jbcayrou for that! 
