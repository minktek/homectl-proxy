Intro
-----
Home control proxy to simplify client development

This is for personal use and also to show the kids how coding works.

Basic idea is that a pretty simple Android (Java) app will be able to access a proxy within the house
that does all the heavy lifting for accessing networked devices that initially can do 3 things:
- provide information for a device
- turn on a device
- turn off a device

The kids screen time (game consoles, tv, tablets) is tied to a combination of exercise and reading,
so eventually we are going to be adding time keeping to this so that people who don't do their
homework won't be able to (at least) turn on the TV and or the PS3.


Credits
-------
Giving credit where credit is due, some of this came from here:
- https://github.com/softScheck/tplink-smartplug


Usage
-----
Assuming that you have a shell variable setup with the host and port information (e.g. 127.0.0.1:1234),
these commands should do useful things:

1. Get a list of devices
$ curl -ks http://$MYHOST/iot && echo ' '

2. Add a device
$ curl --data "name=test&ipaddr=192.168.1.1&macaddr=aa:bb:cc:dd:ee:ff" http://$MYHOST/iot && echo ' '

3. Remove a device
$ curl -X DELETE --data "name=test" http://$MYHOST/iot && echo ' '

4. Run a command on a device (GET for all)
-> turn on 
$ curl -X GET --data "cmd=on" http://$MYHOST/iot/tv-lr && echo ' '
-> turn off 
$ curl -X GET --data "cmd=off" http://$MYHOST/iot/tv-lr && echo ' '
-> get info 
$ curl -X GET --data "cmd=info" http://$MYHOST/iot/tv-lr && echo ' '


Initial conditions
------------------
I am assuming that you are running on some Linux variation and that you have install version 3.x of 
python along with flask. We have no Windows computers or Macs at home, so this will be Linux-specific.
Most of the documentation I am including here will use curl for requests and responses. Additionally, 
when something goes wrong, having wireshark and tcpdump will be useful.

