#!/usr/bin/python

import os
import time
import boto.ec2
import boto.ec2.elb
import urllib
import re
import subprocess

# ubuntu 14.10.  Change this to use a different version of Ubuntu.
DEMO_AMI='ami-431a1673'

# how many salt minions to start.
DEMO_MINIONS=2

# AWS security group for the demo.
DEMO_SECURITY_GROUP='demo-group'

# get the right ssh if there's more than one
SSH='/usr/bin/ssh'

# arguments for SSH.  suppress strict key checking because otherwise we'll be asked 
# if the remote host is okay or not when we first connect with ssh.
# the RSA key is passed in the ssh config.
SSH_FLAGS='-o StrictHostKeyChecking=no'

# list that will hold our hosts.  By convention, the [0] element will be the salt master.
hosts = list()

def check_env_vars(str):
	try:  
		os.environ[str]
	except KeyError: 
		print "Please set the environment variable " + str
		sys.exit(1)

	return;

# check once every 30 seconds until they're all fully up
def wait_for_servers_up():
	done=False

	while not done:
		completed = 0
		time.sleep(30)
		existing_instances = ec2.get_all_instance_status()
		for instance in existing_instances:
			if instance.system_status.status == 'ok' and instance.instance_status.status == 'ok':
				completed += 1

		print completed
		if completed == DEMO_MINIONS+1:
			done=True

	print "All instances online"
	return;

# get the external IP address for this machine.  Will need it to enable direct access to the EC2 instances.
def get_external_ip():
    site = urllib.urlopen("http://checkip.dyndns.org/").read()
    grab = re.findall('([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', site)
    address = grab[0]
    return address;

# Want to make sure SSH (port 22) is open to my IP address
def security_group_ssh():

	# If the demo security group exists, purge so it's known to be clean.
	groups = ec2.get_all_security_groups()
	for group in groups:
		if group.name == DEMO_SECURITY_GROUP:
			ec2.delete_security_group(DEMO_SECURITY_GROUP)

	# create new security group opening up ssh and tomcat7 ports
	group = ec2.create_security_group(DEMO_SECURITY_GROUP, 'Security group for demonstration')
	my_cidr = get_external_ip() + '/32'
	group.authorize('tcp', 22, 22, my_cidr)
	group.authorize('tcp', 8080, 8080, my_cidr)
	return;

# open ports 4505 and 4506 on the salt master.
def security_group_salt():

	groups = ec2.get_all_security_groups()
	for group in groups:
		if group.name == DEMO_SECURITY_GROUP:
			for i in range(1, DEMO_MINIONS+1):	
				group.authorize('tcp', 4505, 4506, hosts[i].private_ip_address + '/32')

	return;

# copy hostnames of running instances into the hosts list
def load_hosts_list():

	# first get a list of the id's of all the running instances.
	running = list()
	existing_instances = ec2.get_all_instance_status()
	for instance in existing_instances:
		if instance.system_status.status == 'ok' and instance.instance_status.status == 'ok':
			running.append(instance.id)

	# now get all the instances.
	instances = ec2.get_only_instances()

	# iterate through the instances list and copy out the ones that are running
	for instance in instances:
		for id in running:
			if instance.id == id:
				hosts.append(instance)
	
	return;

# more to look good in the console than anything else
def tag_salt_hosts():

	# by convention the [0] host is the salt master
	hosts[0].add_tag("Name","salt-master")

	# the rest are salt minions
	for i in range(1, DEMO_MINIONS+1):
		hosts[i].add_tag("Name","salt-minion-%d" % i)

	return;

# install the salt apt repo and appropriate salt packages on the instances
def install_salt_instances():

	# install the salt repo first
	for h in hosts:
		subprocess.call([SSH, SSH_FLAGS, h.public_dns_name, "sudo add-apt-repository -y ppa:saltstack/salt"])

	# install the salt master package on the salt master, [0] by convention
	subprocess.call([SSH, SSH_FLAGS, hosts[0].public_dns_name, "sudo apt-get install -y salt-master"])

	# define minion groups on the salt master
	subprocess.call([SSH, SSH_FLAGS, hosts[0].public_dns_name, "sudo chmod 666 /etc/salt/master"])
	subprocess.call([SSH, SSH_FLAGS, hosts[0].public_dns_name, "sudo echo \"nodegroups:\n  group1: 'L@%s'\n  group2: 'L@%s'\n\" >> /etc/salt/master" % (hosts[1].public_dns_name, hosts[2].public_dns_name)])
	subprocess.call([SSH, SSH_FLAGS, hosts[0].public_dns_name, "sudo chmod 640 /etc/salt/master"])
	subprocess.call([SSH, SSH_FLAGS, hosts[0].public_dns_name, "sudo service salt-master restart"])

	# install salt minion on the rest of them
	for i in range(1, DEMO_MINIONS+1):
		subprocess.call([SSH, SSH_FLAGS, hosts[i].public_dns_name, "sudo apt-get install -y salt-minion"])
		subprocess.call([SSH, SSH_FLAGS, hosts[i].public_dns_name, "sudo chmod 666 /etc/hosts"])
		subprocess.call([SSH, SSH_FLAGS, hosts[i].public_dns_name, "sudo echo \"%s %s salt\" >> /etc/hosts" % (hosts[0].private_ip_address, hosts[0].private_dns_name)])
		subprocess.call([SSH, SSH_FLAGS, hosts[i].public_dns_name, "sudo chmod 444 /etc/hosts"])
		subprocess.call([SSH, SSH_FLAGS, hosts[i].public_dns_name, "sudo service salt-minion start"])

	return;

# use the salt-master to install jdk and tomcat7 on the minions.  also sign the minion keys.
def install_jdk_tomcat():

	subprocess.call([SSH, SSH_FLAGS, hosts[0].public_dns_name, "sudo salt-key -A -y"])
	subprocess.call([SSH, SSH_FLAGS, hosts[0].public_dns_name, "sudo apt-get install default-jdk -y"])
	subprocess.call([SSH, SSH_FLAGS, hosts[0].public_dns_name, "sudo apt-get install tomcat7 tomcat7-admin tomcat7-user -y"])

	return;

# copy sample war files out to the salt master, then tell salt master to deploy to the minions
def deploy_sample():
	subprocess.call(["scp", "sample-1.0/sample-1.0.war", "ubuntu@%s:/tmp" % hosts[0].public_dns_name])
	subprocess.call(["scp", "sample-2.0/sample-2.0.war", "ubuntu@%s:/tmp" % hosts[0].public_dns_name])
	subprocess.call([SSH, SSH_FLAGS, hosts[0].public_dns_name, "sudo salt-cp '*' /tmp/sample-1.0.war /var/lib/tomcat7/webapps"])

	return;

# initialize a load balancer
def set_up_load_balancer():
	zones = [os.environ['AWS_DEFAULT_REGION']]
	ports = [(80, 8080, 'http')]
	balancer = elb_conn.create_load_balancer('demo-lb', zones, ports)

	# configure a health check
	hc = HealthCheck(interval = 20, healthy_threshold = 3, unhealthy_threshold = 5, target = 'HTTP:8080')
	balancer.configure_health_check(hc)

	# add the salt minions
	for x in range (1, DEMO_MINIONS+1):
		balancer.register_instances(hosts[x].id)

	print 'Load balancer address is balancer.dns_name'
	return balancer;

# check AWS environment variables and quit if they're not set
check_env_vars('AWS_SECRET_KEY')
check_env_vars('AWS_ACCESS_KEY')
check_env_vars('AWS_DEFAULT_REGION')

print "Connecting to Amazon..."
ec2 = boto.ec2.connect_to_region(os.environ['AWS_DEFAULT_REGION'], aws_access_key_id = os.environ['AWS_ACCESS_KEY'], aws_secret_access_key = os.environ['AWS_SECRET_KEY'])

# set up security group
print "Configuring security groups..."
security_group_ssh()

# start up a salt master and N minions, add one for the salt master
print "Starting instances..."
for x in range(0, DEMO_MINIONS+1):
	ec2.run_instances(DEMO_AMI, key_name='demo-key-pair', instance_type='t1.micro', security_groups=[DEMO_SECURITY_GROUP])

# check once every 30 seconds until they're all fully up
wait_for_servers_up()

# shortcut to have all the running servers
print "Setting up hosts list..."
load_hosts_list()

# tag server[0] as the salt master and server[1..N] as salt minions out of running instances
print "Tagging salt hosts..."
tag_salt_hosts()

# open up salt ports on the salt master
print "More configuration of security groups..."
security_group_salt()

# install salt master and salt minion packages, update host files
print "Installing salt..."
install_salt_instances()

# install jdk tomcat through salt
install_jdk_tomcat()

# copy sample war files to the salt master and deploy 1.0 through salt
deploy_sample()

# TODO:  pause to demo hello world app

# create load balancer, add salt minions to it
#elb_conn = boto.ec2.elb.connect_to_region(aws_access_key_id = os.environ['AWS_ACCESS_KEY'], aws_secret_access_key = os.environ['AWS_SECRET_KEY'], region_name='us-west-2b')
#lb = set_up_load_balancer()

# TODO:  rev the hello world app on one of the minions

# TODO:  flip the load balancer to point to the new app

# TODO:  pause to demo new hello world app

# TODO:  tear everything down and clean up
