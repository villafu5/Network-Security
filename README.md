# Network-Security

Part 1: Review Questions
Security Control Types
The concept of defense in depth can be broken down into three different security control types. Identify the security control type of each set of defense tactics.
Walls, bollards, fences, guard dogs, cameras, and lighting are what type of security control?

Answer: Physical


Security awareness programs, BYOD policies, and ethical hiring practices are what type of security control?

Answer: Administrative


Encryption, biometric fingerprint readers, firewalls, endpoint security, and intrusion detection systems are what type of security control?

Answer: Technical


Intrusion Detection and Attack indicators
What's the difference between an IDS and an IPS?

Answer: IDS is a passive defense mechanism in which it alerts the security team that an attack is taking place but does nothing to mitigate the attack. IPS on the other hand is an active defense mechanism that can block attacks that are taking place.


What's the difference between an Indicator of Attack and an Indicator of Compromise?

Answer: IoA indicates that an attack is currently taking place, while IoC indicates that an attack has occurred and that there is a breach into the network/system.


The Cyber Kill Chain
Name each of the seven stages for the Cyber Kill chain and provide a brief example of each.

Stage 1: Reconnaissance: the attacker gathers as much information on the target as possible. This type of Reconnaissance is passive as they are only gathering information that is readily made available to the public, it becomes active when they actively engage their target.


Stage 2: Weaponization: the attackers are able to create a malware or some sort of attack based off the information they gathered on their target through Reconnaissance.


Stage 3: Delivery: Delivering the weapon through the doors of the network/system through any means possible.


Stage 4: Exploitation: Getting the weapon to run on the system.


Stage 5: Installation: Getting the weapon to be installed on the system.


Stage 6: Command & Control: The attacker has command and control on the system remotely.


Stage 7: Actions on Objectives: The attacker is now able to perform any objectives that they desire as they now have access to the sytem network.


Snort Rule Analysis
Use the Snort rule to answer the following questions:

Snort Rule #1
alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"ET SCAN Potential VNC Scan 5800-5820"; flags:S,12; threshold: type both, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2002910; classtype:attempted-recon; sid:2002910; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)
Break down the Sort Rule header and explain what is happening.

Answer: creates an alert that applies to all tcp packets coming from any ip address on the external network across any port to ports 5800:5820 on the home network


What stage of the Cyber Kill Chain does this alert violate?

Answer: Reconnaissance


What kind of attack is indicated?

Answer: Potetial VNC Scan


Snort Rule #2
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"ET POLICY PE EXE or DLL Windows file download HTTP"; flow:established,to_client; flowbits:isnotset,ET.http.binary; flowbits:isnotset,ET.INFO.WindowsUpdate; file_data; content:"MZ"; within:2; byte_jump:4,58,relative,little; content:"PE|00 00|"; distance:-64; within:4; flowbits:set,ET.http.binary; metadata: former_category POLICY; reference:url,doc.emergingthreats.net/bin/view/Main/2018959; classtype:policy-violation; sid:2018959; rev:4; metadata:created_at 2014_08_19, updated_at 2017_02_01;)

Break down the Sort Rule header and explain what is happening.

Answer: creates an alert that applies to all tcp packets coming from any ip address from the external network through HTTP_PORT 80 to any ports on the home network


What layer of the Defense in Depth model does this alert violate?

Answer: Host


What kind of attack is indicated?

Answer: Ransomware


Snort Rule #3
Your turn! Write a Snort rule that alerts when traffic is detected inbound on port 4444 to the local network on any port. Be sure to include the msg in the Rule Option.

Answer: alert tcp $External_Network 4444 -> $Home_Network any {msg: "TCP packet Detected through port 4444";}


Part 2: "Drop Zone" Lab

Log into the Azure firewalld machine
Uninstall ufw
Before getting started, you should verify that you do not have any instances of ufw running. This will avoid conflicts with your firewalld service. This also ensures that firewalld will be your default firewall.

Run the command that removes any running instance of ufw.

sudo apt -y remove ufw


Enable and start firewalld
By default, these service should be running. If not, then run the following commands:
Run the commands that enable and start firewalld upon boots and reboots.

sudo systemctl enable firewalld
Sudo systemctl start firewalld


Confirm that the service is running.
Run the command that checks whether or not the firewalld service is up and running.

sudo /etc/init.d/firewalld status 


List all firewall rules currently configured.
Next, lists all currently configured firewall rules. This will give you a good idea of what's currently configured and save you time in the long run by not doing double work.
Run the command that lists all currently configured firewall rules:

firewall-cmd --direct --get-all-rule


Take note of what Zones and settings are configured. You may need to remove unneeded services and settings.


List all supported service types that can be enabled.
Run the command that lists all currently supported services to see if the service you need is available

sudo firewall-cmd --get-services


We can see that the Home and Drop Zones are created by default.


Zone Views
Run the command that lists all currently configured zones.

sudo firewall-cmd --list-all-zones


We can see that the Public and Drop Zones are created by default. Therefore, we will need to create Zones for Web, Sales, and Mail.


Create Zones for Web, Sales and Mail.
Run the commands that creates Web, Sales and Mail zones.

Sudo firewall-cmd --permanent --new-zone=Web
Sudo firewall-cmd --permanent --new-zone=Sales
Sudo firewall-cmd --permanent --new-zone=Mail


Set the zones to their designated interfaces:
Run the commands that sets your eth interfaces to your zones.

sudo firewall-cmd --zone=Web --add-interface=eth0
sudo firewall-cmd --zone=Sales --add-interface=eth0
sudo firewall-cmd --zone=Mail --add-interface=eth0



Add services to the active zones:
Run the commands that add services to the public zone, the web zone, the sales zone, and the mail zone.


Public:
sudo firewall-cmd --zone=public --add-service=http --permanent
sudo firewall-cmd --zone=public --add-service=https --permanent
sudo firewall-cmd --zone=public --add-service=smtp --permanent
sudo firewall-cmd --zone=public --add-service=pop3 --permanent


Web:
sudo firewall-cmd --zone=Web --add-service=http --permanent
sudo firewall-cmd --zone=Web --add-service=https --permanent
sudo firewall-cmd --zone=Web --add-service=smtp --permanent
sudo firewall-cmd --zone=Web --add-service=pop3 --permanent


Sales
sudo firewall-cmd --zone=Sales --add-service=http --permanent
sudo firewall-cmd --zone=Sales --add-service=https --permanent
sudo firewall-cmd --zone=Sales --add-service=smtp --permanent
sudo firewall-cmd --zone=Sales --add-service=pop3 --permanent


Mail
sudo firewall-cmd --zone=Mail --add-service=http --permanent
sudo firewall-cmd --zone=Mail --add-service=https --permanent
sudo firewall-cmd --zone=Mail --add-service=smtp --permanent
sudo firewall-cmd --zone=Mail --add-service=pop3 --permanent


What is the status of http, https, smtp and pop3?


Add your adversaries to the Drop Zone.
Run the command that will add all current and any future blacklisted IPs to the Drop Zone.

sudo firewall-cmd --zone=drop --add-rich-rule=”rule family=’ipv4’ source address=’10.10.10.10’ reject”

<ADDCOMMAND HERE>$ <ADD COMMAND HERE>
Make rules permanent then reload them:
It's good practice to ensure that your firewalld installation remains nailed up and retains its services across reboots. This ensure that the network remains secured after unplanned outages such as power failures.
Run the command that reloads the firewalld configurations and writes it to memory

sudo firewall-cmd --runtime-to-permanent


View active Zones
Now, we'll want to provide truncated listings of all currently active zones. This a good time to verify your zone settings.
Run the command that displays all zone services.

sudo firewall-cmd --list-services


Block an IP address
Use a rich-rule that blocks the IP address 138.138.0.3.

sudo firewall-cmd --zone=drop --add-rich-rule=”rule family=’ipv4’ source address=’138.138.0.3’ reject”


Block Ping/ICMP Requests
Harden your network against ping scans by blocking icmp ehco replies.
Run the command that blocks pings and icmp requests in your public zone.

sudo firewall-cmd --zone=public --add-icmp-block=echo-request
Rule Check
Now that you've set up your brand new firewalld installation, it's time to verify that all of the settings have taken effect.
Run the command that lists all of the rule settings. Do one command at a time for each zone.

Sudo firewall-cmd --zone=Web --list-all
Sudo firewall-cmd --zone=Mail --list-all
Sudo firewall-cmd --zone=Sales --list-all
Sudo firewall-cmd --zone=public --list-all
Sudo firewall-cmd --zone=drop --list-all


Are all of our rules in place? If not, then go back and make the necessary modifications before checking again.


Congratulations! You have successfully configured and deployed a fully comprehensive firewalld installation.

Part 3: IDS, IPS, DiD and Firewalls
Now, we will work on another lab. Before you start, complete the following review questions.
IDS vs. IPS Systems
Name and define two ways an IDS connects to a network.

Answer 1: Network TAP: connected east-west of a network and monitors all innound and outbound data.

Answer 2: SPAN: connected east-west of a network and copies all network data and sends them to another port where it can be analyzed by an administrator when something has been flagged.


Describe how an IPS connects to a network.

Answer: Inline with the flow of data, inbetween the firewall and the network switch


What type of IDS compares patterns of traffic to predefined signatures and is unable to detect Zero-Day attacks?

Answer: Signature based intrusion detection system


Which type of IDS is beneficial for detecting all suspicious traffic that deviates from the well-known baseline and is excellent at detecting when an attacker probes or sweeps a network?

Answer: Anomaly based intrusion detection system


Defense in Depth
For each of the following scenarios, provide the layer of Defense in Depth that applies:


A criminal hacker tailgates an employee through an exterior door into a secured facility, explaining that they forgot their badge at home.

Answer: Perimeter


A zero-day goes undetected by antivirus software.

Answer: Network


A criminal successfully gains access to HR’s database.

Answer: Data


A criminal hacker exploits a vulnerability within an operating system.

Answer: Application


A hacktivist organization successfully performs a DDoS attack, taking down a government website.

Answer: Network


Data is classified at the wrong classification level.

Answer: Host


A state sponsored hacker group successfully firewalked an organization to produce a list of active services on an email server.

Answer: Data


Name one method of protecting data-at-rest from being readable on hard drive.

Answer: Encryption


Name one method to protect data-in-transit.

Answer: Public Key Encryption/Cryptography


What technology could provide law enforcement with the ability to track and recover a stolen laptop.

Answer: GPS tracking


How could you prevent an attacker from booting a stolen laptop using an external hard drive?

Answer: 2-Factor Authentication


Firewall Architectures and Methodologies

Which type of firewall verifies the three-way TCP handshake? TCP handshake checks are designed to ensure that session packets are from legitimate sources.
Answer: Circuit-level gateways

Which type of firewall considers the connection as a whole? Meaning, instead of looking at only individual packets, these firewalls look at whole streams of packets at one time.
Answer: Stateful Firewalls

Which type of firewall intercepts all traffic prior to being forwarded to its final destination. In a sense, these firewalls act on behalf of the recipient by ensuring the traffic is safe prior to forwarding it?
Answer: Application gateways

Which type of firewall examines data within a packet as it progresses through a network interface by examining source and destination IP address, port number, and packet type- all without opening the packet to inspect its contents?
Answer: Stateless/Packet Filtering firewalls

Which type of firewall filters based solely on source and destination MAC address?
Answer: MAC firewalls

Bonus Lab: "Green Eggs & SPAM"
In this activity, you will target spam, uncover its whereabouts, and attempt to discover the intent of the attacker.
You will assume the role of a Jr. Security administrator working for the Department of Technology for the State of California.


As a junior administrator, your primary role is to perform the initial triage of alert data: the initial investigation and analysis followed by an escalation of high priority alerts to senior incident handlers for further review.


You will work as part of a Computer and Incident Response Team (CIRT), responsible for compiling Threat Intelligence as part of your incident report.


Threat Intelligence Card
Note: Log into the Security Onion VM and use the following Indicator of Attack to complete this portion of the homework.
Locate the following Indicator of Attack in Sguil based off of the following:
Source IP/Port: 188.124.9.56:80
Destination Address/Port: 192.168.3.35:1035
Event Message: ET TROJAN JS/Nemucod.M.gen downloading EXE payload
Answer the following:
What was the indicator of an attack?
Answer: It reveals that a trojan malware via an EXE file received through an email is being download on the home network 

What was the adversarial motivation (purpose of attack)?
Answer: Steal private information


Describe observations and indicators that may be related to the perpetrators of the intrusion. Categorize your insights according to the appropriate stage of the cyber kill chain, as structured in the following table.

Reconnaissance: How did they attacker locate the victim? Passive Reconnaissance 
Weaponization: What was it that was downloaded? Trojan Malware
Delivery: How was it downloaded? Email through EXE files
Exploitation: What does the exploit do? Steals private information
Installation: How is the exploit installed? The malware is installed in the background when the user opens the PDF file
Command & Control (C2): How does the attacker gain control of the remote machine? The installed malware communicates with the attackers network giving them access to the system
Actions on Objectives: What does the software that the attacker sent do to complete it's tasks? Compresses the files before sending it back to the attacker

Answer:
What are your recommended mitigation strategies?
Answer: Have an intrusion detection system to detect any anomalies coming into and out of the network. Additionally, have an intrusion prevention system set up to detect and mitigate any threats in real time.


List your third-party references.
Answer: www.certego.net/en/news/italian-spam-campaigns-using-js-nemucod-downloader/


