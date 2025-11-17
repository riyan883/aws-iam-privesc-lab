AWS IAM Privilege Escalation Lab

A complete hands-on project demonstrating misconfigurations in AWS IAM and how attackers exploit them to gain unauthorized access.

🚀 Project Overview

This project is a fully practical AWS IAM Privilege Escalation Lab built from scratch.
It simulates real-world IAM misconfigurations and shows how attackers can escalate privileges using:

IAM PassRole misuse

Misconfigured policies

Overly permissive roles

Access key exposure

Policy chaining

ngrok-based external access

Automated IAM graph generator

The project includes a live running demo, screenshots, and a step-by-step exploit scanner.

🎯 Key Features
🔐 1. 10 IAM Users with Custom Roles

Each user has carefully crafted permissions to simulate a realistic corporate environment.

📜 2. 18 IAM Policies

Policies include:

Privilege escalation paths

Misconfigured PassRole

Over-permissive “*” permissions

S3, Lambda, IAM, EC2 specific access

🛑 3. 4 Privilege Escalation Scenarios

Including:

iam:PassRole

sts:AssumeRole

iam:PutUserPolicy

Role chaining escalation

🤖 4. Python IAM Scanner

A fully custom script that:

Reads IAM users

Detects dangerous permissions

Identifies possible escalation paths

Generates a graph output (static/iam-graph.png)

🌐 5. Live Demo with ngrok

Frontend hosted through a secure ngrok tunnel.

🎥 6. Live Video Walkthrough

Google Drive video showing full exploitation steps.

🔗 Demo Links
🌍 Live Project (ngrok)
https://89c4f0148a1f.ngrok-free.app

🎥 Video Walkthrough

Google Drive link:
https://drive.google.com/file/d/1j7SfRcZRDM4ymMXLB8yoLedkBpkORyfb/view
