# AIsploit
USE ONLY IN YOUR LAB FOR TEST

Offensive Automation Tool (Beta)
Web-based automation tool for offensive security operations.
Runs Nmap scans against a target and maps detected vulnerabilities to suitable Metasploit exploits and payloads.

Prerequisites

Linux debian

nmap

metasploit

Install guides
sudo apt update && sudo apt install nmap metasploit-framework

nmap --version

msfconsole --version

python3 -m venv name

source name/bin/activate

pip install python-nmap

pip install streamlit

streamlit run aisploit.py --server.port 8888

