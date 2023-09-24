#!/usr/bin/env python3

import scapy.all as scapy
import argparse



def getArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Single Target IP (e.g.: 10.0.2.1) or Target IP range (e.g.: 10.0.2.1/24).")
    option = parser.parse_args()
    return option


def scan(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arpRequestBroadcast = broadcast/arpRequest
    answeredList= scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]

    clientList = []
    for element in answeredList:
        clientDict = {"ip":element[1].psrc, "mac":element[1].hwsrc}
        clientList.append(clientDict)
    return clientList

def printResult(resultList):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for client in resultList:
        print(client["ip"]+"\t\t"+client["mac"])

option = getArguments()
if(option.target_ip == None):
    print("[-] Enter a target IP (e.g.: 10.0.2.1) or target IP range (e.g.: 10.0.2.1/24).")
else:
    scanResult = scan(option.target_ip)

printResult(scanResult)