# CodeAlpha_Network_Sniffer
* sniff_arp.py
  
# #!/usr/bin/env python
* The shebang line at the top of the script tells the operating system to use the Python interpreter to execute the script. env is used to locate the Python interpreter in the user's environment.
# import scapy.all as scapy
# from scapy.layers import http
* This part imports necessary modules from scapy, a powerful Python library used for network packet manipulation and analysis. It also imports the http module * from scapy.layers to handle HTTP-specific packet layers.

# def sniff(interface):
#    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
* iface=interface: Specifies the network interface to sniff on (e.g., wlan0 for a wireless interface).
store=False: Tells scapy not to store the packets in memory.
prn=process_sniffed_packet: Specifies the callback function process_sniffed_packet to be called for each captured packet.

# def get_url(packet):
#    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
* This function extracts the URL from an HTTP request packet.
* packet[http.HTTPRequest].Host: Extracts the Host header (e.g., example.com).
* packet[http.HTTPRequest].Path: Extracts the Path of the URL (e.g., /index.html).

# def get_login_info(packet):
#    if packet.haslayer(scapy.Raw):
#        load = str(packet[scapy.Raw].load)
#        keywords = ["username", "user", "password", "pass"]
#        for keyword in keywords:
#           if keyword in load:
#                return load

* This function attempts to find potential login information in the packet.
* packet.haslayer(scapy.Raw): Checks if the packet has a Raw data layer.
* load = str(packet[scapy.Raw].load): Converts the Raw data to a string.
* keywords = ["username", "user", "password", "pass"]: List of keywords to search for in the packet data.
The loop checks if any of the keywords are present in the load and returns the data if found.

# def process_sniffed_packet(packet):
#    if packet.haslayer(http.HTTPRequest):
#        url = get_url(packet)
#        print("[+] HTTP Request >> " + url.decode())
#        login_info = get_login_info(packet)
#        if login_info:
#            print("\n\n[+] Possible username/password > " + login_info + "\n\n")

* This function processes each packet captured by the sniffer.
* if packet.haslayer(http.HTTPRequest): Checks if the packet is an HTTP request.
* url = get_url(packet): Extracts the URL from the HTTP request.
* print("[+] HTTP Request >> " + url.decode()): Prints the URL of the HTTP request.
* login_info = get_login_info(packet): Tries to extract potential login information.
* If login_info is found, it prints the possible username/password.
# sniff("wlan0")
* Calls the sniff function, specifying the network interface (wlan0 in this case) to start sniffing on.
# Summary
This script captures HTTP packets on the specified network interface and analyzes them to extract URLs and potential login information. It provides a basic demonstration of how to use scapy for network traffic analysis. Here are some key points:

Importing Scapy and HTTP layers: scapy provides tools to capture and manipulate packets, and http is specifically for handling HTTP layers.
Sniffing Function: Captures packets on a specified network interface and processes them using a callback function.
URL Extraction: Extracts and prints the URL from HTTP request packets.
Login Information Extraction: Searches for keywords related to login credentials in the packet data.
Processing Packets: Checks if packets are HTTP requests, extracts relevant information, and prints it.
#### To run this script, you would typically need root privileges because capturing packets directly from a network interface usually requires elevated permissions.

* sniff_extracting.py

### Shebang Line

```python
#!/usr/bin/env python
```

The shebang line tells the operating system to use the Python interpreter specified by the user's environment to execute this script.

### Imports

```python
import scapy.all as scapy
from scapy.layers import http
```

- `scapy.all`: Imports all functionalities of the `scapy` library, which is used for network packet manipulation and analysis.
- `from scapy.layers import http`: Specifically imports HTTP-related functionalities from `scapy`.

### Sniff Function

```python
def sniff(interface):
	scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
```

- `sniff(interface)`: A function to start sniffing on a specified network interface.
  - `iface=interface`: Specifies the network interface to sniff on (e.g., `wlan0` for a wireless interface).
  - `store=False`: Instructs `scapy` not to store packets in memory, which saves resources.
  - `prn=process_sniffed_packet`: Specifies the callback function to be called for each captured packet.

### Process Sniffed Packet Function

```python
def process_sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
		print(url)
		if packet.haslayer(scapy.Raw):
			load = packet[scapy.Raw].load
			keywords = ["username", "user", "password", "pass"]
			for keyword in keywords:
				print(load)
				break
```

- `process_sniffed_packet(packet)`: This function is called for each packet captured by the sniffer.
  - `if packet.haslayer(http.HTTPRequest)`: Checks if the packet contains an HTTP request layer.
    - `url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path`: Extracts the Host and Path from the HTTP request to form the URL.
    - `print(url)`: Prints the extracted URL.
  - `if packet.haslayer(scapy.Raw)`: Checks if the packet contains a Raw data layer (usually holds the payload of the packet).
    - `load = packet[scapy.Raw].load`: Extracts the payload from the Raw data layer.
    - `keywords = ["username", "user", "password", "pass"]`: List of keywords to search for in the packet payload.
    - `for keyword in keywords`: Iterates over the keywords.
      - `print(load)`: Prints the payload of the packet.
      - `break`: Breaks the loop after the first payload print. This will print the payload only once for each packet that contains any of the keywords.

### Start Sniffing

```python
sniff("wlan0")
```

- Calls the `sniff` function, specifying the network interface (`wlan0` in this case) to start sniffing on.

### Summary

1. **Shebang Line**: Ensures the script uses the correct Python interpreter.
2. **Imports**: Imports necessary modules from `scapy` for network sniffing and HTTP packet processing.
3. **Sniff Function**:
   - Defines which network interface to sniff on.
   - Specifies that packets should not be stored in memory.
   - Sets the function to process each packet captured.
4. **Process Sniffed Packet Function**:
   - Checks if the packet is an HTTP request.
   - Extracts and prints the URL from the HTTP request.
   - Checks for Raw data in the packet.
   - Searches for specific keywords in the payload.
   - Prints the payload if it contains any of the keywords (prints the payload once per packet).
5. **Start Sniffing**: Initiates sniffing on the specified network interface.

This script captures HTTP traffic, prints URLs, and searches for specific keywords in the packet payloads, helping to understand and analyze network traffic and potentially sensitive data being transmitted over the network.
