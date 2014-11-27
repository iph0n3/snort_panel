from django.shortcuts import render, render_to_response
from django.http import HttpResponse
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.core.context_processors import csrf
# Create your views here.
import subprocess
import re
import ConfigParser
import os

global rules_path
global alerts_path
global query
path =  os.getcwd()+'//snort//config.ini'
cf = ConfigParser.ConfigParser()
cf.read(path)
rules_path = cf.get('path','rules_path')
alerts_path =cf.get('path','alerts_path')
query = cf.get('query','snort_query')

def WRITE_RULES(rules):
	try:
		global rules_path
		path = rules_path
		f = open(path, 'w')
		#print rules
		for key, rule in rules.iteritems():
			print key
			f.write(rule + '\n')
		f.close()
		return True
	except:
		return False




def get_alert():
	global alerts_path
	path = alerts_path
	f = open(path, 'r')
	alert_contents = f.read()
	alert_sections = alert_contents.split('[**] ')
	return alert_sections

def get_process():
	query = 'ps ax'
	p = subprocess.Popen(query.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=False)
	all_commands = p.stdout.readlines()

	snort_commands = {} 
	for i in all_commands:
		if 'snort ' in i:
			j = int(i[:5])
			snort_commands[j] = i
	return snort_commands

def get_rules():
	global rules_path
	path = rules_path
	f = open(path, 'r')
	rules_contents = f.readlines()
	rules_sections = {}
	pattern = 'sid:([\d]+);'
	regex = re.compile(pattern)
	j = 0
	for i in rules_contents:
		i = i.strip()
		if i.startswith('#') or len(i) ==0:
			pass
		else:
			sid_re = regex.findall(i)
			if len(sid_re) != 1:
				sid = '[]error%d'%j
			else:
				sid = sid_re[0]
			rules_sections[sid] = i
			j = j + 1
	return rules_sections

def add_rules(rule):
	try:
		global rules_path
		path = rules_path
		f = open(path, 'a+')
		rule = rule.strip()
		f.write(rule + '\n')
		f.close()
		return True
	except:
		return	False




def del_rules(id):
	rules = get_rules()
	del rules[id]
	status = WRITE_RULES(rules)
	if status:
		return True
	else:
		return False

def edit_rules(rule, id):

	rules = get_rules()
	rules[id] = rule
	status = WRITE_RULES(rules)
	if status:
		return True
	else:
		return False



def index_show(request):

	snort_commands = get_process()
	alert_sections = get_alert()[-5:]
	rules_sections = get_rules()
	rules_sections = sorted(rules_sections.items(), key=lambda d:d[0], reverse=True)[:5]
	return render_to_response('index.html', {'snort_commands':snort_commands, 'alert_sections':alert_sections,'rules_sections':rules_sections})
def about_show(request):
	return render_to_response('about.html')


def process_show(request):
	c = {}
	c.update(csrf(request))
	snort_commands = get_process()
	c.update({'snort_commands':snort_commands})
	return render_to_response('process.html', c)

def process_start(request):
	id = request.GET['id']
	global query 
	local_query = query
	p = subprocess.Popen(query.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=False)
	all_commands = p.stdout.readlines()
	if all_commands:
		return HttpResponse(1)

def process_kill(request):
	id = request.GET['id']
	snort_commands = get_process()
	id = int(id)
	print id
	if id in snort_commands.keys():
		query = 'kill %d'%(id)
		p = subprocess.Popen(query.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=False)
		all_commands = p.stdout.readlines()
		return HttpResponse(1)
	else:
		return HttpResponse(0)
	
def process_restart(request):
	pass



def rules_show(request):
	c = {}
	c.update(csrf(request))
	

	rules_sections = get_rules()
	rules_sections = sorted(rules_sections.items(), key=lambda d:d[0], reverse=True)
	#print rules_sections.keys()
	c.update({'rules_sections':rules_sections})

	return render_to_response('rules.html', c)



def rules_add(request):
	if request.method == 'POST':
		rule = request.POST['rule']
		if  len(rule)>10:
			status = add_rules(rule)
			if status:
				return HttpResponse(1)
	return HttpResponse(0)
def rules_edit(request):
	if request.method == 'POST':
		rule = request.POST['rule']
		id = request.POST['id']
		status = edit_rules(rule, id)
		if status:
			return HttpResponse(1)
	return HttpResponse(0)

def rules_del(request):
	id = request.GET['id']
	status = del_rules(id)
	if status:
		return HttpResponse(1)
	return HttpResponse(0)


def alert_show(request):
	alert_lists = get_alert()[::-1]
	paginator = Paginator(alert_lists, 10)
	page = request.GET.get('page')
	try:
		alert_sections = paginator.page(page)
	except PageNotAnInteger:
        # If page is not an integer, deliver first page.
		alert_sections = paginator.page(1)
	except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
		alert_sections = paginator.page(paginator.num_pages)

	return render_to_response('alert.html', {'alert_sections':alert_sections})
	
