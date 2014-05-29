# Testing Servers

Testing whether servers are vulnerable is done using wpa_supplicant. Once connect to the AP it will listen on **localhost:45678**. You can now connect to this socket as if it were the actual RADIUS server. This allows you to **use existing heartbleed tools to test** the RADIUS server.

## Installation

The default .config in this repository is sufficient for normal heartbleed testing. Hence simply execute the following to compile a working version:

	git clone https://github.com/vanhoefm/apbleed.git
	cd apbleed/wpa_supplicant
	make

## Usage

You being the same way as any wpa_supplicant session. That means:

	sudo ./wpa_supplicant -Dnl80211 -iwlan0 -cexample.conf

Modify `example.conf` to specify the AP you want to test. The example config file will attempt to connect to [eduroam](https://www.eduroam.org/) and test the radius server of `example.com` (which does not exist):

	network={
	    # 1. Filters to specify which network to test
	    ssid="eduroam"
	    key_mgmt=WPA-EAP
	
	    # 2. Configure which RADIUS server (realm) to connect to.
	    anonymous_identity="anonymous@example.com"
	
	    # 3. Tell wpa_supp to listen at 127.0.0.1:56789 once connected
	    eap=SOCKET
	}

In general take the configuration file of a network and change the line `eap=XXXX` to `eap=SOCKET` and you are good to go. Once connected it will open a socket to which you must connect.

	wlan2: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25
	>> eap_socket_init
	
			==== ApBleed: connect to localhost:45678 ====
	
		Be fast enough, otherwise the connection will time out...

You can now use **any heartbleed tool** to test the server. For example with [heartleech](https://github.com/robertdavidgraham/heartleech):

	mathy@kali:~/heartleech$ ./heartleech 127.0.0.1 -p 45678
	
	--- heartleech/1.0.0i ---
	https://github.com/robertdavidgraham/heartleech
	[-] PATCHED: heartBEAT received, but not BLEED

## Remarks

The code has not been tested for reliability. Patches are welcome. Possible improvements:

1. Detect the inner EAP method the server is expecting, and use that.
2. Improved error handling.
3. Improved packet forwarding.
4. ...

# Testing Clients

Testing clients has not yet been implemented. Look at the commits to see how to do this, it will be similar to testing servers. Patches are welcome.
