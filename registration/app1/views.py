from django.shortcuts import render, HttpResponse,redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import mysql.connector
from scapy.layers.l2 import Ether
import pandas as pd
import time
from datetime import datetime
import pytz # pip install pytz
import matplotlib.pyplot as plt
import numpy as np




# Create your views here.

 

def homepage(request):
    test=""
    db = mysql.connector.connect(
        host="127.0.0.1", 
        port="3306", 
        user="root", 
        password="ishan1234", 
        auth_plugin="mysql_native_password"
        )
    cursor = db.cursor()
    cursor.execute("USE packetdata")
    
    create_table_query = """
    CREATE TABLE packets (
        id INT AUTO_INCREMENT PRIMARY KEY,
        source_ip VARCHAR(15),
        destination_ip VARCHAR(15),
        source_mac VARCHAR(25),
        destination_mac VARCHAR(25),
        time_stamp VARCHAR(25),
        port_length FLOAT(15),
        S_port VARCHAR(15),
        D_port VARCHAR(15),
        packet_data BLOB
    )
    """
    #cursor.execute("DROP TABLE PACKETS")
    #cursor.execute(create_table_query)
    global counter
    counter=0
      
    def process_packet(packet):
        global counter
        counter += 1 
        print(counter)  
        print(packet)  
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        source_mac = packet[Ether].src
        destination_mac = packet[Ether].dst
        tz = pytz.timezone('Asia/Calcutta')
        ts = time.time()    
        

        time_stamp=datetime.fromtimestamp(ts,tz).strftime('%d-%m-%Y %H:%M:%S')
      
        port_length=packet[IP].len
        S_port=packet[IP].sport 
        D_port=packet[IP].dport #http:data through encrypted network is 443 and #https: plain text is 80
        packet_data = bytes(packet)
        insert_query = "INSERT INTO packets (source_ip, destination_ip, time_stamp, source_mac, destination_mac, port_length, S_port, D_port,  packet_data) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
        cursor.execute(insert_query, (source_ip, destination_ip, time_stamp, source_mac, destination_mac, port_length, S_port, D_port,  packet_data))
        #cursor.execute()
        db.commit()
   

    sniff(filter="ip",prn=process_packet,count=10)
    
    global a
    
    cursor.execute("SELECT COUNT(id) FROM PACKETS")
    a=cursor.fetchone()
    
    cursor.execute("SELECT * FROM PACKETS")
    data=cursor.fetchall()
    test=data
    
    cursor.close()
    db.close()

    
    return render(request,'home.html',{'test':test,'a':a})

def signuppage(request):
    if request.method=='POST':
        print("user created")
        uname=request.POST.get('username')
        email=request.POST.get('email')
        password=request.POST.get('password')
        cpassword=request.POST.get('cpassword')
        if password!=cpassword:
         return  HttpResponse("password error!")
        else:
         my_user=User.objects.create_user(uname,email,password)
         my_user.save()
        return redirect('login')
       
       # return HttpResponse("user has been created sucessfully")        
      

    return render(request,'signup.html')

def loginpage(request):
    if request.method=='POST':
       username=request.POST.get('username')
       password=request.POST.get('password')
      # print(email,password)
       user=authenticate(request,username=username,password=password)
       if user is not None:
          login(request,user)
          return redirect('home')
       else:
          return HttpResponse("email and password are invalid")
    

    
    return render(request,'login.html')

def Logoutpage(request):
   logout(request)
   return  redirect('login')

def timestamp(request):
   time=""
   db = mysql.connector.connect(
        host="127.0.0.1", 
        port="3306", 
        user="root", 
        password="ishan1234", 
        auth_plugin="mysql_native_password"
        )
   cursor = db.cursor()
   cursor.execute("USE packetdata")
   cursor.execute("SELECT id,time_stamp FROM PACKETS")
   
   data=cursor.fetchall()
   time=data
   #print(f'time {data}')
   return render(request,'time.html',{'time':time,'a':a})

def timestamp(request):
   time=""
   db = mysql.connector.connect(
        host="127.0.0.1", 
        port="3306", 
        user="root", 
        password="ishan1234", 
        auth_plugin="mysql_native_password"
        )
   cursor = db.cursor()
   cursor.execute("USE packetdata")
   cursor.execute("SELECT id,time_stamp FROM PACKETS")
   
   data=cursor.fetchall()
   time=data
   #print(f'time {data}')
   return render(request,'time.html',{'time':time,'a':a})

def sourceip(request):
   sip=""
   db = mysql.connector.connect(
        host="127.0.0.1", 
        port="3306", 
        user="root", 
        password="ishan1234", 
        auth_plugin="mysql_native_password"
        )
   cursor = db.cursor()
   cursor.execute("USE packetdata")
   cursor.execute("SELECT id,source_ip FROM PACKETS")
   
   data=cursor.fetchall()
   sip=data
   #print(f'time {sip}')
   return render(request,'sip.html',{'sip':sip,'a':a})

def destinationip(request):
   dip=""
   db = mysql.connector.connect(
        host="127.0.0.1", 
        port="3306", 
        user="root", 
        password="ishan1234", 
        auth_plugin="mysql_native_password"
        )
   cursor = db.cursor()
   cursor.execute("USE packetdata")
   cursor.execute("SELECT id,destination_ip FROM PACKETS")
   
   data=cursor.fetchall()
   dip=data
   #print(f'time {dip}')
   return render(request,'dip.html',{'dip':dip,'a':a})

def sourcemac(request):
   smac=""
   db = mysql.connector.connect(
        host="127.0.0.1", 
        port="3306", 
        user="root", 
        password="ishan1234", 
        auth_plugin="mysql_native_password"
        )
   cursor = db.cursor()
   cursor.execute("USE packetdata")
   cursor.execute("SELECT id,source_mac FROM PACKETS")
   
   data=cursor.fetchall()
   smac=data
   #print(f'time {smac}')
   return render(request,'smac.html',{'smac':smac,'a':a})

def destinationmac(request):
   dmac=""
   db = mysql.connector.connect(
        host="127.0.0.1", 
        port="3306", 
        user="root", 
        password="ishan1234", 
        auth_plugin="mysql_native_password"
        )
   cursor = db.cursor()
   cursor.execute("USE packetdata")
   cursor.execute("SELECT id,destination_mac FROM PACKETS")
   
   data=cursor.fetchall()
   dmac=data
   #print(f'time {dmac}')
   return render(request,'dmac.html',{'dmac':dmac,'a':a})

def sourceport(request):
   sport=""
   db = mysql.connector.connect(
        host="127.0.0.1", 
        port="3306", 
        user="root", 
        password="ishan1234", 
        auth_plugin="mysql_native_password"
        )
   cursor = db.cursor()
   cursor.execute("USE packetdata")
   cursor.execute("SELECT id,S_port FROM PACKETS")
   
   data=cursor.fetchall()
   sport=data
   #print(f'time {sport}')
   return render(request,'sport.html',{'sport':sport,'a':a})
   
def destinationport(request):
   dport=""
   db = mysql.connector.connect(
        host="127.0.0.1", 
        port="3306", 
        user="root", 
        password="ishan1234", 
        auth_plugin="mysql_native_password"
        )
   cursor = db.cursor()
   cursor.execute("USE packetdata")
   cursor.execute("SELECT id,D_port FROM PACKETS")
   
   data=cursor.fetchall()
   dport=data
   #print(f'time {dport}')
   return render(request,'dport.html',{'dport':dport,'a':a})  

def packetlen(request):
   plen=""
   db = mysql.connector.connect(
        host="127.0.0.1", 
        port="3306", 
        user="root", 
        password="ishan1234", 
        auth_plugin="mysql_native_password"
        )
   cursor = db.cursor()
   cursor.execute("USE packetdata")
   cursor.execute("SELECT id,port_length FROM PACKETS")
   
   data=cursor.fetchall()
   plen=data
   #print(f'time {plen}')
   return render(request,'plen.html',{'plen':plen,'a':a})   

def summary(request):
  
   all=""
   db = mysql.connector.connect(
        host="127.0.0.1", 
        port="3306", 
        user="root", 
        password="ishan1234", 
        auth_plugin="mysql_native_password"
        )
   cursor = db.cursor()
   cursor.execute("USE packetdata")
   cursor.execute("SELECT source_ip, COUNT(10) AS NUMBER FROM packets GROUP BY source_ip LIMIT 10")
   summ=cursor.fetchall()

   ip_addresses = [row[0] for row in summ]
   packet_counts = [row[1] for row in summ]

   plt.bar(ip_addresses, packet_counts)
   plt.xlabel('IP Addresses')
   plt.ylabel('Number of Packets')
   plt.title('Packet Counts per IP Address')
   plt.show()
   cursor.execute("SELECT * FROM PACKETS")
   data=cursor.fetchall()
   all=data
   #print(f'time {all}')
   
   return render(request,'summary.html',{'all':all,'a':a})   


def summary2(request):
   db = mysql.connector.connect(
        host="127.0.0.1", 
        port="3306", 
        user="root", 
        password="ishan1234", 
        auth_plugin="mysql_native_password"
        )
   cursor = db.cursor()
   cursor.execute("USE packetdata")
   cursor.execute("SELECT * FROM PACKETS")
   data=cursor.fetchall()
   all=data
   return render(request,'summary.html',{'all':all,'a':a})   
   