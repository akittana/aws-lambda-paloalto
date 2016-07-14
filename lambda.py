import boto3
import json
import ssl
import urllib
import urllib2
import xml.etree.ElementTree as ET
import gzip
import paloalto
import netaddr

ec2 = boto3.resource('ec2')
s3 = boto3.resource('s3')

def lambda_handler(event, context):
	pa_ip = '52.6.78.209' # Palo Alto Firewall IP address
	pa_key = 'LUFRPT1oWFBicy9ZMXpubk83aFNNSFFJV01tVVA1KzQ9eVROMTRBTmZGcTNvTkR1aS9mL1ZhQT09' # Palo Alto Access Key
	pa_bottom_rule = 'Clean up' # Rules added by this lambda function will be placed above this rule
	pa_zone_untrust = 'untrust' # Name of untrust (outside) zone configured in Palo Alto
	pa_zone_trust = 'trust' # Name of trust (inside) zone configured in Palo Alto
	pa_spg = 'strict_spg' # Name of the Security profile group to be configured in Palo Alto
	igwId = 'i-08272b1e193f1061e' # Instance ID of the Palo Alto firewall 
	
	# Get the location of the cloudtrail log file from the event
	bucket = event['Records'][0]['s3']['bucket']['name']
	key = urllib.unquote_plus(event['Records'][0]['s3']['object']['key']).decode('utf8')

	# Retreive the log file from S3 and uncompress it
	s3object = s3.Object(bucket,key)
	s3object.download_file('/tmp/tmp.gz')
	
	with gzip.open('/tmp/tmp.gz', 'rb') as f:
		contents = f.read()
    
	# Parse the file as json 
	logs = json.loads(contents)
	
	# Iterate through the records for events that match 'StartInstances','AuthorizeSecurityGroupIngress',..
	for record in logs['Records']:
		if record['eventName'] == 'StartInstances':
			rules_to_be_added = event_StartInstance(record,igwId) # Parse instance details to retrieve new rules to be added
			for rule in rules_to_be_added:
				pa_rule = aws_rules_to_pa(pa_ip,pa_key,rule) # convert the format of the rules to Palo Alto gateway fields
				pa_rule['srcZone'] = pa_zone_untrust
				pa_rule['dstZone'] = pa_zone_trust				
				pa_rule['dstPort'] = str(rule['dstPort'])
				pa_rule['spg'] = pa_spg
				matching_rules = paloalto.paloalto_find_matchingrule(pa_ip,pa_key,pa_rule) # find if there are already rules that correspond to the same parameters
				current_policy_action = ""
				if len(matching_rules) != 0: 
					for rulename in matching_rules:
						matching_rule_details = paloalto.paloalto_rule_getdetails(pa_ip,pa_key,rulename)
						if matching_rule_details['action'] == "deny": #if we encounter one deny, then the variable current_policy_action is set to deny, and the whole rule is added
							current_policy_action = "deny"			
				if current_policy_action != "deny" and len(matching_rules) != 0:
					continue
				pa_rule['action'] = 'allow'
				matching_rules = paloalto.paloalto_rule_add(pa_ip,pa_key,pa_rule) # Add rules on Palo Alto gateway
				paloalto.paloalto_rule_move(pa_ip,pa_key,{'location':'before','rule_name':pa_rule['name'],'dst_rule':pa_bottom_rule}) # move rule added to ensure it is above the configured pa_bottom_rule
			paloalto.paloalto_commit(pa_ip,pa_key) # Commit changes on the Palo Alto gateway to save changes 
		elif record['eventName'] == "AuthorizeSecurityGroupIngress":
			rules_to_be_added = event_AuthorizeSecurityGroupIngress(record) # Parse security group details to retrieve new rules to be added
			for rule in rules_to_be_added:
				pa_rule = aws_rules_to_pa(pa_ip,pa_key,rule) # convert the format of the rules to Palo Alto gateway fields
				pa_rule['srcZone'] = pa_zone_untrust
				pa_rule['dstZone'] = pa_zone_trust
				pa_rule['dstPort'] = str(rule['dstPort'])
				pa_rule['spg'] = pa_spg
				result = paloalto.paloalto_find_matchingrule(pa_ip,pa_key,pa_rule)
				print "params: ",pa_rule
				print "result:", result
				current_policy_action = ""
				if len(result) != 0:
					for rulename in result:
						matching_rule_details = paloalto.paloalto_rule_getdetails(pa_ip,pa_key,rulename)
						if matching_rule_details['action'] == "deny": #if we encounter at least one deny, then the variable current_policy_action is set to deny, and the whole rule is added
							current_policy_action = "deny"			
				if current_policy_action != "deny" and len(result) != 0:
					continue
				pa_rule['action'] = 'allow'
				result = paloalto.paloalto_rule_add(pa_ip,pa_key,pa_rule) # Add rules on Palo Alto gateway
				paloalto.paloalto_rule_move(pa_ip,pa_key,{'location':'before','rule_name':pa_rule['name'],'dst_rule':pa_bottom_rule}) # move rule added to ensure it is above the configured pa_bottom_rule
			paloalto.paloalto_commit(pa_ip,pa_key) # Commit changes on the Palo Alto gateway to save changes
		elif record['eventName'] == "StopInstances":
			list_of_instances = event_StopInstances(record) # get a list of instance ids from the log event
			for instance in list_of_instances:
				rule_names = paloalto.paloalto_rule_findbyname(pa_ip,pa_key,instance) # find all rules that have the instance id in their name (rules added by our code)
				if len(rule_names) != 0: # delete all returned rules
					for rule in rule_names:
						paloalto.paloalto_rule_delete(pa_ip,pa_key,rule)
			paloalto.paloalto_commit(pa_ip,pa_key) # Commit changes on the Palo Alto gateway to save changes
		elif record['eventName'] == "RevokeSecurityGroupIngress":
			sgid,params = event_RevokeSecurityGroupIngress(record)
			rules = paloalto.paloalto_rule_findbyname(pa_ip,pa_key,sgid)
			for param in params:
				if len(rules) > 0:
					rules_to_delete = []
					for rule in rules:
						rule_details = paloalto.paloalto_rule_getdetails(pa_ip,pa_key,rule)
						param['application'],param['service'] = aws_to_pa_services(pa_ip,pa_key,param['protocol'],param['dstPort'])
						rule_details['srcIP'].sort()
						param['srcIP'].sort()
						if (param['srcIP'] == rule_details['srcIP'] and param['service'] == rule_details['service'] and param['application'] == rule_details['application']):
							rules_to_delete.append(rule)
						else:
							print "rules didnt match. rule properties: ",param,rule_details
					if len(rules_to_delete) > 0:
						for rule in rules_to_delete:
							paloalto.paloalto_rule_delete(pa_ip,pa_key,rule)
			paloalto.paloalto_commit(pa_ip,pa_key) # Commit changes on the Palo Alto gateway to save changes


def event_AuthorizeSecurityGroupIngress(event):
    # Input: 1) Event: 'AuthorizeSecurityGroupIngress' log event
	# Output: List of rules that need to be added on the Palo Alto gateway. Each rule in  the list is a dictionary with the following parameters:
	# 	'instID': Instance ID
	#	'dstIP': List of relevant destination IPs
	#	'srcIP': List of relevant source IPs
	#	'dstPort': Destination Port for the rule
	#	'protocol': protocol used: tcp, udp, icmp, or -1 (for all protocols).
	
	security_group = event['requestParameters']['groupId']
	nw_ifs = ec2.network_interfaces.all()
	sg = ec2.SecurityGroup(event['requestParameters']['groupId'])
	vpc = ec2.Vpc(sg.vpc_id)
	
	
	rules = []
	rules_to_be_added =[]
	# Check if the item changed affects IP address
	for i in event['requestParameters']['ipPermissions']['items']:
		for j in i['ipRanges']['items']:
			rule = {}
			source_ips = []
			if 'cidrIp' in j:
				if "/" in j['cidrIp']:
					if netaddr.IPNetwork(j['cidrIp']) in netaddr.IPNetwork(vpc.cidr_block):
						continue
				else:
					if netaddr.IPAddress(j['cidrIp']) in netaddr.IPNetwork(vpc.cidr_block):
						continue
				source_ips.append(j['cidrIp'])
			else:
				continue
			if len(source_ips) >0:
				rule['protocol']=i['ipProtocol']
				rule['dstPort']=i['toPort']
				rule['srcIP']=source_ips
			rules.append(rule)
	# If no IP addresses are affected then exit
	if len(rules) == 0:
		return rules


	for i in nw_ifs:
		for j in i.groups:
			if j['GroupId'] == security_group:
				dst_ips = []
				for k in i.private_ip_addresses:
					dst_ips.append(k['PrivateIpAddress'])
				for x in rules:
					rules_to_be_added.append({'srcIP':x['srcIP'],'instID':security_group,'dstIP':dst_ips,'protocol':x['protocol'],'dstPort':x['dstPort']})

	return rules_to_be_added

def get_relevant_subnets(vpcs,igw_instId,vpcId):
    # Input: 1) vpcs: object referencing list of all VPCs
	#		 2) igw_instId: Inernet gateway instance id
	#		 3) vpcId: relevant vpcId
	# Output: List of all subnet Ids that use the instance igw_instId as their internet gateway

	relevantSubnets = []

	for i in vpcs:
		if i.vpc_id == vpcId:
			rtables = i.route_tables.all()
			for j in rtables:
				k = 0
				for l in j.routes_attribute:
					if l['DestinationCidrBlock'] == "0.0.0.0/0":
						if 'InstanceId' in l and l['InstanceId'] == igw_instId:
							for k in j.associations_attribute:
								if k['Main'] == True:
									continue
								else:
									relevantSubnets.append(k['SubnetId'])

						else:
							continue


	return relevantSubnets

def event_StartInstance(event,igwId):
	# Input: 1) Event: 'StartInstance' log event
	#		 2) igwId: Instance Id of the Palo Alto gateway 
	# Output: List of rules that need to be added on the Palo Alto gateway. Each rule in  the list is a dictionary with the following parameters:
	# 	'instID': Instance ID
	#	'dstIP': List of relevant destination IPs
	#	'srcIP': List of relevant source IPs
	#	'dstPort': Destination Port for the rule
	#	'protocol': protocol used: tcp, udp, icmp, or -1 (for all protocols).


	# get a list of all VPCs 
	vpcs = ec2.vpcs.all()

	# Compile a list of all Instance Ids found in the log event passed
	instanceIds = []
	for i in event['requestParameters']['instancesSet']['items']:
		instanceIds.append(i['instanceId'])

	# Compile a list of all rules to be created. 
	rules_to_be_created = []
	for instanceId in instanceIds:
		instance = ec2.Instance(instanceId)
		vpc = ec2.Vpc(instance.vpc_id)
		relevant_subnets = get_relevant_subnets(vpcs,igwId,instance.vpc_id)
		inst_nw_ifs = instance.network_interfaces_attribute
		for nw_if in inst_nw_ifs:
			if nw_if['SubnetId'] in relevant_subnets:
				for sg in nw_if['Groups']:
					security_group = ec2.SecurityGroup(sg['GroupId'])
					for rule in security_group.ip_permissions:
						if len(rule['IpRanges']) != 0:
							dstIPs=[]
							srcIPs=[]
							for source in rule['IpRanges']:
								if "/" in source['CidrIp']:
									if netaddr.IPNetwork(source['CidrIp']) in netaddr.IPNetwork(vpc.cidr_block):
										continue
								else:
									if netaddr.IPAddress(source['CidrIp']) in netaddr.IPNetwork(vpc.cidr_block):
										continue
								srcIPs.append(source['CidrIp'])
							if len(srcIPs) == 0:
								continue
							for m in nw_if['PrivateIpAddresses']:
								dstIPs.append(m['PrivateIpAddress'])
							rules_to_be_created.append({'instID':instanceId,'dstIP':dstIPs,'srcIP':srcIPs,'dstPort':rule['ToPort'],'protocol':rule['IpProtocol']})

	return rules_to_be_created

def event_StopInstances(event):
	# Input: log event of the type 'StopInstances'
	# Output: List of Instance Ids in that event
	instanceIds = []
	print "event: ",event
	for i in event['requestParameters']['instancesSet']['items']:
		instanceIds.append(i['instanceId'])
	return instanceIds

def event_RevokeSecurityGroupIngress(event):
    security_group = event['requestParameters']['groupId']
    rules = []
    for i in event['requestParameters']['ipPermissions']['items']:
        for j in i['ipRanges']['items']:
            source_ips = []
            rule = {}
            if 'cidrIp' in j:
                source_ips.append(j['cidrIp'])
            else:
                continue
            if len(source_ips) > 0:
                rule['protocol']=i['ipProtocol']
                rule['dstPort']=i['toPort']
                rule['srcIP']=source_ips
                rules.append(rule)
    
    return security_group,rules 

def aws_to_pa_services(pa_ip,pa_key,protocol,port):
    if protocol == 'icmp':
        return 'icmp', 'application-default'
    elif protocol == 'tcp':
        if port == 22: return 'ssh','application-default'
        elif port == 25: return 'smtp','application-default'
        elif port == 53: return 'dns','application-default'
        elif port == 80: return 'web-browsing','application-default'
        elif port == 110: return 'pop3','application-default'
        elif port == 143: return 'imap','application-default'
        elif port == 389: return 'ldap','application-default'
        elif port == 636: return 'ldap','application-default'
        elif port == 443: return 'ssl','application-default'
        elif port == 3306: return 'mysql','application-default'
        elif port == 3389: return 'rdp','application-default'
        elif port == 5439: return 'amazon-redshift','application-default'
        elif port == 1521: return 'oracle','application-default'
        elif port == -1:
            pa_service = paloalto.paloalto_service_find(pa_ip,pa_key,'tcp',"1-65535")
            if pa_service == "":
                pa_service = paloalto.paloalto_service_add(pa_ip,pa_key,'tcp',"1-65535")
            return 'any',pa_service
        else:
            pa_service = paloalto.paloalto_service_find(pa_ip,pa_key,'tcp',port)
            if pa_service == "":
                pa_service = paloalto.paloalto_service_add(pa_ip,pa_key,'tcp',str(port))
            return 'any',pa_service
    elif protocol == 'udp':
        if port == 53: return 'dns','application-default'
        elif port == -1:
            pa_service = paloalto.paloalto_service_find(pa_ip,pa_key,'udp',"1-65535")
            if pa_service == "":
                pa_service = paloalto.paloalto_service_add(pa_ip,pa_key,'udp',"1-65535")
            return 'any', pa_service
        else:
            pa_service = paloalto.paloalto_service_find(pa_ip,pa_key,'udp',port)
            if pa_service == "":
                pa_service = paloalto.paloalto_service_add(pa_ip,pa_key,'udp',port)
            return 'any', pa_service
    else:
        return 'any','any'
    
def aws_rules_to_pa(pa_ip,pa_key,aws_params):
	pa_params={}
	
	pa_params['name'] = aws_params['instID']
	
	# parse source IPs
	pa_params['srcIP'] = []
	pa_params['dstIP'] = []
	for i in aws_params['srcIP']:
		if i != '0.0.0.0/0':
			pa_params['srcIP'].append(i)
		else:
			pa_params['srcIP'] = ['any']
			break
	for i in aws_params['dstIP']:
		if i != '0.0.0.0/0':
			pa_params['dstIP'].append(i)
		else:
			pa_params['dstIP'] = ['any']
			break
	print "aws_params: ",aws_params
	pa_params['protocol'] = aws_params['protocol']
	pa_params['application'],pa_params['service'] = aws_to_pa_services(pa_ip,pa_key,aws_params['protocol'],aws_params['dstPort'])
	print "pa_params: ",pa_params
	return pa_params
