# Public

## Pcap Parser

### description
This tool was designed to ease the burden of network analysis whilst conducting security audits of networks.

It will output a spreadsheet and a diagram that can be viewed/edited on draw.io to provide a high-level overview of the network architecture associated with a project.

### usage
```python
    python3 pcap_to_drawio.py capture.pcap
    python3 pcap_to_drawio.py capture.pcap -o out.drawio --xlsx out.xlsx
    python3 pcap_to_drawio.py capture.pcap --min-packets 3 --collapse-external
    python3 pcap_to_drawio.py capture.pcap --hostname-file hosts.txt
```


