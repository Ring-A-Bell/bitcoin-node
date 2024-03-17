# Python Node in Bitcoin Blockchain
This lab exercise demonstrates interacting with the BitCoin network to retrieve and manipulate blocks from the block chain. The main objectives include connecting to a peer in the P2P BitCoin network, retrieving a specific block based on a given criterion, displaying the transactions in the block, and optionally manipulating a transaction and observing the effects on block integrity.

## Requirements
Connect to a peer in the P2P BitCoin network and retrieve the block number corresponding to your SU ID number (your number modulo 10,000).
Display the transactions in the retrieved block.
Optionally manipulate one of the transactions in the block to change its output account and observe the effects on the block's integrity.
Program should be written in Python 3 without the use of publicly available BitCoin libraries, except for provided helper functions.
Utilize *TCP/IP* to communicate with a full node in the BitCoin network.

## Getting Started
To begin, ensure you have Python 3 installed on your system. Follow the instructions below to set up your environment and run the program.

## Obtaining Bitcoin Nodes:

Retrieve a list of Bitcoin nodes using the provided script *makeseeds.py*.

Install *dnspython* if not already installed: `pip3 install dnspython` or `pip install dnspython`

Download the list of Bitcoin nodes:

`curl https://bitcoin.sipa.be/seeds.txt.gz | gzip -dc > seeds_main.txt`

`curl https://bitcoin.sipa.be/asmap-filled.dat > asmap-filled.dat`

`python3 makeseeds.py -a asmap-filled.dat -s seeds_main.txt > nodes_main.txt`

## Connecting to a Node:

Choose a node from `nodes_main.txt` and hard-code its host in your program.
Running the Program:

Execute the provided Python script `lab5.py` to interact with the BitCoin network.

## Guidance
Refer to the provided code snippets and guidance for interacting with Bitcoin peers and messages. Follow the steps outlined in the lab exercise to achieve the specified objectives.

For additional resources and documentation on Bitcoin and its protocol, visit the following links:

* [Bitcoin Developer Documentation](https://developer.bitcoin.org/devguide/p2p_network.html)

* [Bitcoin Wiki](https://en.bitcoin.it/wiki/Main_Page)

* [Bitcoin Improvement Proposals (BIPs)](https://github.com/bitcoin/bips)

## Disclaimer
> Ensure that you comply with the guidelines and regulations while interacting with the BitCoin network. Manipulating transactions for experimental purposes should be done responsibly and within legal boundaries.

