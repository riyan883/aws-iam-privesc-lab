#!/usr/bin/env python3
import boto3
from graphviz import Digraph
from flask import Flask, render_template_string
import os

app = Flask(__name__)

def scan_iam():
    client = boto3.client('iam')
    dot = Digraph(comment='10-User IAM Privesc Lab')
    escalations = 0
    total_users = 0
    total_policies = 0

    users = client.list_users()['Users']
    
    for user in users:
        username = user['UserName']
        total_users += 1
        dot.node(username, username, shape='ellipse', style='filled', color='lightyellow')
        
        try:
            attached = client.list_attached_user_policies(UserName=username)['AttachedPolicies']
            total_policies += len(attached)
            
            for pol in attached:
                pol_name = pol['PolicyName']
                node_id = f"{username}-{pol_name}"
                dot.node(node_id, pol_name, shape='box', style='filled', color='lightcoral')
                dot.edge(username, node_id, label='has')
                
                try:
                    policy = client.get_policy(PolicyArn=pol['PolicyArn'])
                    doc = client.get_policy_version(
                        PolicyArn=pol['PolicyArn'],
                        VersionId=policy['Policy']['DefaultVersionId']
                    )['PolicyVersion']['Document']
                    
                    statements = doc.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements]
                        
                    for stmt in statements:
                        if stmt.get('Effect') != 'Allow':
                            continue
                            
                        actions = stmt.get('Action', [])
                        if not isinstance(actions, list):
                            actions = [actions]
                        actions = [a.lower() for a in actions]
                        
                        if '*' in actions:
                            dot.edge(node_id, 'ROOT TAKEOVER', color='red', style='bold')
                            escalations += 1
                        elif 'iam:passrole' in actions and 'lambda:createfunction' in actions:
                            dot.edge(node_id, 'LAMBDA RCE', color='orange')
                            escalations += 1
                        elif 's3:putobject' in actions and 'lambda:invokefunction' in actions:
                            dot.edge(node_id, 'S3 → LAMBDA RCE', color='purple')
                            escalations += 1
                        elif 'ec2:runinstances' in actions and 'iam:passrole' in actions:
                            dot.edge(node_id, 'EC2 SSRF', color='green')
                            escalations += 1
                            
                except:
                    continue
        except:
            continue
    
    graph_path = 'static/iam-graph'
    dot.render(graph_path, format='png', cleanup=True)
    return total_users, total_policies, escalations, f'{graph_path}.png'

@app.route('/')
def home():
    users, policies, escalations, graph = scan_iam()
    html = f"""
    <h1>AWS IAM Privesc Lab (10 Users)</h1>
    <p><strong>Users: {users} | Policies: {policies} | Privesc Paths: {escalations}</strong></p>
    <img src="/{graph}" width="1400">
    <hr>
    <small>Elite Project #1 | TU Dresden Application | Nov 17, 2025</small>
    """
    return render_template_string(html)

if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    print("[+] Starting 10-User IAM Scanner...")
    app.run(host='0.0.0.0', port=5000)
