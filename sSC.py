#Problem Statement : IPv6 echo client/server and IPv4 address conversion project
#Detail Problem statement : Implement an IPv6 echo client/server using Python. Implement a program to convert an IPv4 address to different
#formats and finding a service name, given the port and protocol using Python.

#!usr/bin/python

__author__="Naina Chaturvedi"

import socket
from binascii import hexlify
import time
import threading

def check_ipv6_support(port=8800):
    # to check if IPv6 is supported or not
    #socket.has_ipv6 :constant contains a boolean value which indicates if IPv6 is supported on this platform.
    if not socket.has_ipv6:
        raise Exception("IPv6 not supported")
    else:
      print ("Machine supports IPv6")
    #getaddrinfo returns a list of 5 tuples 
    #(family, socktype, proto, canonname, sockaddr)
    address_info = socket.getaddrinfo("localhost", port, socket.AF_INET6, 0, socket.SOL_TCP)
    print("The address is : ",address_info)
    #To get fully qualified name for localhost
    fqdomain_name=socket.getfqdn("localhost")
    print("The Fully Qualified Domain Name",fqdomain_name)
    #To get hostname for the given IPv6 address(Google IPv6 address)
    host_address=socket.gethostbyaddr("2001:4860:4860::8888")
    print("The hostname for given IPv6 address 2001:4860:4860::8888 is : ",host_address)
    #To get hostname for the given IPv6 address(Naina Machine IPv6 address)
    host_address_naina=socket.gethostbyaddr("2601:2c6:4106:4860:f452:e541:fae6:4753")
    print("The hostname for given IPv6 address 2601:2c6:4106:4860:f452:e541:fae6:4753 is : ",host_address_naina)
    p = address_info[0]
    socket_address = p[-1]
    return socket_address
 
 
def ipv6_server(socket_address):
    #Create Socket
    #AF_INET6 for IPV6 family,STREAM for TCP connection
    server_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    #binds address (hostname, port number pair) to socket.
    server_sock.bind(socket_address)
    #sets up and start TCP listener
    server_sock.listen(5)
    print ("Server is listening for open connection", server_sock, ", address: '%s'" % socket_address[0])
    #accept TCP client connection
    connection, address = server_sock.accept()
    time.sleep(1)
    print ('Server is connected to : ', address)
    if True: 
        incoming_data = connection.recv(1024)
        connection.send(incoming_data)
    connection.close()
 
 
def ipv6_client(socket_address):
    # socket address = Hostname+port
    #Create Socket
    #AF_INET6 for IPV6 family,STREAM for TCP connection
    client_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    #actively initiates TCP server connection
    client_sock.connect(socket_address)
    print ("Socket connection from client", client_sock.getsockname())
    sending_data = 'Hey, I enjoy computer networking'
    #Repr : Return a string containing a printable representation of an object
    print ('Sending message', repr(sending_data))
    client_sock.send(sending_data.encode())
    #decode(): decodes the string using the codec registered for encoding. It defaults to the default string encoding.
    sending_data = client_sock.recv(1024).decode()
    client_sock.close()
    print ('Server responded to the client', repr(sending_data))

#Function to fetch my machine information using gethostbyname and gethostname   
def fetch_info_machine():
 hostname = socket.gethostname()
 ipaddress = socket.gethostbyname(hostname)
 print ("Host name: %s" % (hostname))
 print ("IP address: %s" %(ipaddress))
 
#Function to fetch remote machine information whose url is given
def fetch_info_remote_machine():
 remote_host_address = 'www.microsoft.com'
 print ("IP address of the remote machine: %s" %(socket.gethostbyname(remote_host_address)))
 
#Function to convert IPv4 address into different formats
def ipv4_conversion():
 #google and yahoo Ip address
 for ip_address in ['8.8.8.8', '64.4.52.30']:
  #inet_aton() function converts the specified string in the Internet standard dot notation to a network address.    
  ip_packed = socket.inet_aton(ip_address)
  #inet_ntoa() returns the dots-and-numbers string.
  ip_addr_u = socket.inet_ntoa(ip_packed)
  #binascii.hexlify() gives the hexadecimal representation of data
  print ("IP Address: %s --> Packed ip address: %s, Unpacked ip address: %s" %(ip_address, hexlify(ip_packed), ip_addr_u))
  
#Function to fetch service name by port and protcol using gerservbyport socket function
def fectch_service_byport_protocol():
 protocol = 'tcp'
 for ports_list in [110,11,179]:
  print ("Port: %s => service name: %s" %(ports_list, socket.getservbyport(ports_list, protocol)))
 print ("Port: %s => service name: %s" %(69, socket.getservbyport(69, 'udp')))

#main function
 
if __name__=='__main__':
    
    V6address = check_ipv6_support()
    threads = threading.Thread(target=ipv6_server, args=(V6address,))
    threads.start()
    time.sleep(5)
    ipv6_client(V6address)
    fectch_service_byport_protocol()
    fetch_info_remote_machine()
    fetch_info_machine()
    ipv4_conversion()
 
 

