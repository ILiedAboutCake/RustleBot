#!/bin/env python
# -*- coding: utf-8 -*-

import argparse, base64, cPickle, datetime, glob, json, logging, os, pprint, platform, random, sys, time, urllib, urllib2, socket, websocket, requests, paramiko, ConfigParser, pyotp

#makes error reporting work for websocket-client
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.disabled = False

#get the configuration file
config = ConfigParser.ConfigParser()
config.read("RustleBot.cfg")

#set the variables to make this shit run
ALLOWED = ['subscriber', 'flair1', 'flair3', 'flair4', 'flair5', 'flair8', 'protected', 'vip', 'moderator', 'admin', 'bot'] #tier1/tier2/tier3/trusted/tier4/contrib/protected/vip/mod/admin/bot
DANKMEMES = [e.strip() for e in config.get("general", "defaultemotes").split(',')] #failsafe emotes in case dgg cant serve them 
RATELIMIT = int(config.get("general", "ratelimit")) #seconds in between sending messages for plebs
cloudFlareAPI = config.get("cloudflare","apikey") #https://www.cloudflare.com/a/account/my-account
cloudFlareEmail = config.get("cloudflare","email") #email on the account
cloudFlareZone = config.get("cloudflare","zone") #zone for overrustle.com
apiEndpoint = config.get("healthcheck","api") #api server
coreEndpoint = config.get("healthcheck","core") #frontend server (pre-cloudflare) location
healthUsername = config.get("healthcheck","username") #ssh username
healthPassword = config.get("healthcheck","password") #password
apiAdminSecret = config.get("general","secret")#do not show this to anyone holyshit
totp = pyotp.TOTP(config.get("general","otpSecret")) #https://github.com/pyotp/pyotp

#load in the pickles gachiGASM
ADMINS = cPickle.load(open('adminlist.pkl', 'rb'))

SUPERLOGGEDIN = False
SUPERTIMER = 0

COOLDOWN = int(time.time() - RATELIMIT)
LASTMSG = random.choice(DANKMEMES)
LAUNCHTIME = time.time()

#fetch all the emotes from destiny.gg
def getDggEmotes():
	global DANKMEMES;

	print "[EMOTE]: Getting updated emote list from destiny.gg"

	try:
		emotesJson = urllib2.urlopen('https://www.destiny.gg/chat/emotes.json')
	except:
		print "[ERROR]: Unable to contact destiny.gg for the emotes list, falling back to static list."
		return "unable to contact destiny.gg for the emotes list DaFeels"

	DANKMEMES = json.load(emotesJson)

	#convert unicode list to UTF list
	[x.encode('utf-8') for x in DANKMEMES]

	#get rid of twitch emotes
	NEWMEMES = list()
	for meme in DANKMEMES:
		if 'nathan' in meme:
			continue
		NEWMEMES.append(meme)

	DANKMEMES = NEWMEMES

	print "[EMOTE]: Emotes loaded! using %s emotes " % len(DANKMEMES)
	return "Queried destiny.gg/chat/emotes.json for emotes list! Now using %s emotes (twitch emotes filtered)" % len(DANKMEMES)

#handle arguments
parser = argparse.ArgumentParser(description='HighlightBot')
parser.add_argument('-r','--runtime', help='Runtime (prod or dev)',required=True)
args = parser.parse_args()

if args.runtime == "prod":
	print "[CONN]: Connecting to production chat."
	endpoint = "wss://destiny.gg/ws"
	token = config.get("chat","prod")
elif args.runtime == "dev":
	print "[CONN]: Connecting to staging chat."
	endpoint = "ws://stage.destiny.gg/ws"
	token = config.get("chat","stage") #ILiedAboutCake - Stage
else:
	print "[CONN] wat."


#handle raw chat messages into a dict
def parse_chat_protocol(msg):
	parts = msg.split(" ", 1)
	if len(parts) != 2:
		return {}
	try:
		ret = json.loads(parts[1])
	except Exception:
		return {}
	if not isinstance(ret, dict):
		return {}
	ret["command"] = parts[0]
	return ret

#ty dharma for writing readable code
def tdformat(s,rough=""):
	days, remainder  = divmod(s, 86400)
	hours, remainder = divmod(remainder, 3600)
	minutes, seconds = divmod(remainder, 60)
	if days > 1:
		if hours != 0:
			return '%s days %s%sh' % (days, rough, hours)
		else:
			return '%s days' % (days)
	elif days == 1:
		if hours != 0:
			return '%s day %s%sh' % (days, rough, hours)
		else:
			return 'a day'
	elif days == 0:
		if hours != 0:
			if minutes != 0:
				return '%s%sh%sm' % (rough, hours, minutes)
			else:
				return '%s%sh' % (rough, hours)
		else:
				return '%s%sm' % (rough, minutes)
	else:
		return 'A few seconds'

#handles sending the message to the socket and rate limiting shitters
def sendMsg(msg, command, user, ws):
	global COOLDOWN
	global RATELIMIT
	global LASTMSG

	#handle duplicate messages
	if msg == LASTMSG:
		print '[DUPE]: Duplicate text caught, padding message to avoid filtering.'
		msg = msg + " " + random.choice(DANKMEMES)

	#allow admin users to bypass the rate limiter completely
	if user in ADMINS or user == config.get("general", "superuser"):
		ws.send('MSG {"data":"' + msg + '"}')
		LASTMSG = msg
		print '[NORATE][' + command + ']: Called by ' + user
	else:
		if (time.time() - COOLDOWN) >= RATELIMIT:
			ws.send('MSG {"data":"' + msg + '"}')
			LASTMSG = msg
			print '[' + command + ']: Called by ' + user 
			COOLDOWN = int(time.time())
		else:
			print '[' + command + ']: Called by ' + user 
			print "[RATE]: Rate Limited user " + user +", last message was sent to chat " + str(round(time.time() - COOLDOWN)) + " seconds ago."

#requires the superuser to be defined + logged in with OTP
def allowSuperuser(user):
	global SUPERLOGGEDIN
	global SUPERTIMER

	if user != config.get("general", "superuser"):
		return False

	if SUPERLOGGEDIN == False:
		return False

	if SUPERTIMER < time.time():
		return False
	else:
		return True


def on_message(ws, msg):
	global RATELIMIT
	global SUPERLOGGEDIN
	global SUPERTIMER

	#disect what we get
	m = parse_chat_protocol(msg)

	#time the message was recieved (server time fuck you GMT)
	unixstamp = int(time.time())

	#handle the data types we want
	if 'command' not in m or (m['command'] != 'PING' and m['command'] != 'MSG' and m['command'] != 'PRIVMSG'):
		return

	#add an empty features list to private messages/print out the PM in the console 
	if m['command'] == 'PRIVMSG':
		m['features'] = '[]'
		print "Private message recieved: " + m['nick'] + " sent: " + m['data']

	#play ping pong with the server
	if m['command'] == 'PING':
		ws.send('PONG ' + m['data'])
		return

	#allows admins to spit out status of the bot
	if m['nick'] in ADMINS and m['data'].lower().startswith('!rbstat'):
		sendMsg('AD:' + str(len(ADMINS)) + ', RL:' + str(RATELIMIT) + 's, RT:' + str(tdformat(unixstamp - int(LAUNCHTIME))) + ', ' + random.choice(DANKMEMES), "STATUS", m['nick'], ws)

	#allows anyone to use the !yee command
	#if m['data'].lower().startswith('!yee') and allowSuperuser(m['nick']):
	if m['nick'] in ADMINS and m['data'].lower().startswith('!yee'):
		if any(s in l for l in m['features'] for s in ALLOWED) or m['nick'] in ADMINS:
			sendMsg(m['nick'] + ' YEE hillshire.tv/YEE', "YEE", m['nick'], ws)

	#misc controls
	if m['nick'] in ADMINS and m['data'].lower().startswith('!rustlebot'):
		commandArray = m['data'].split()

		if "admin add" in m['data'] and allowSuperuser(m['nick']):
			ADMINS.append(commandArray[3])
			cPickle.dump(ADMINS, open('adminlist.pkl', 'wb'))
			sendMsg(commandArray[3] + ' has been added to the admin privileged group SOTRIGGERED', "RustleBot +adminad", m['nick'], ws)

		elif "admin remove" in m['data'] and allowSuperuser(m['nick']):
			ADMINS.remove(commandArray[3])
			cPickle.dump(ADMINS, open('adminlist.pkl', 'wb'))
			sendMsg(commandArray[3] + ' has been removed from the admin privileged group SOTRIGGERED', "RustleBot +adminrm", m['nick'], ws)

		elif "admin check" in m['data'] and m['nick'] == config.get("general", "superuser"): #soft superuser
			if commandArray[3] in ADMINS:
				sendMsg(commandArray[3] + ' found on admins list ', "RustleBot +adminck", m['nick'], ws)
			else:
				sendMsg(commandArray[3] + ' not found on admins list ', "RustleBot +adminck", m['nick'], ws)

		elif "ratelimit" in m['data']:
			RATELIMIT = int(commandArray[2])
			sendMsg('Reply ratelimit is now set to ' + commandArray[2] + ' seconds YEE', "RustleBot +ratelmt", m['nick'], ws)

		elif "save" in m['data']:
			cPickle.dump(ADMINS, open('adminlist.pkl', 'wb'))
			sendMsg('Forced syncing to disk completed', "RustleBot +savepkl", m['nick'], ws)

		elif "uptime" in m['data']:
			sendMsg(tdformat(unixstamp - int(LAUNCHTIME)), "RustleBot +uptime", m['nick'], ws)

		elif "emotes" in m['data']:
			sendMsg(getDggEmotes(), "RustleBot +emotes", m['nick'], ws)

		#handle OTP checks and authing the superuser
		elif "login" in commandArray[1] and m['nick'] == config.get("general", "superuser"):
			if int(totp.now()) == int(commandArray[2].strip()):
				sendMsg(m['nick'] + ' OTP looks good. Authenticated for 360 minutes (6 hours) or until !rustlebot logout', "RustleBot Login <otp>", m['nick'], ws)
				SUPERLOGGEDIN = True
				SUPERTIMER = unixstamp + (6*60*60) #hours * minutes * seconds
			else:
				sendMsg(m['nick'] + ' Incorrect OTP ', "RustleBot Login <otp>", m['nick'], ws)
				return

		#handle OTP checks and authing the superuser
		elif "logout" in commandArray[1] and allowSuperuser(m['nick']):
			SUPERLOGGEDIN = False
			SUPERTIMER = unixstamp
			sendMsg(m['nick'] + ' thanks for playing FrankerZ /', "RustleBot Login <otp>", m['nick'], ws)

		else:
			sendMsg('Read The Fucking Manual OhKrappa ' + m['nick'], "RustleBot +RTFM", m['nick'], ws)

	#superuser eval
	if m['data'].lower().startswith('!eval') and allowSuperuser(m['nick']):
		evalData = eval(m['data'][5:])
		sendMsg('/me ' + str(evalData), "EVAL", m['nick'], ws)

	#cloudflare purge cache
	if m['nick'] in ADMINS and m['data'].lower().startswith('!cloudflare'):
		if "purge" in m['data']:
			url = 'https://api.cloudflare.com/client/v4/zones/' + cloudFlareZone + '/purge_cache'
			headers = {'Content-Type': 'application/json', 'X-Auth-Email' : cloudFlareEmail, 'X-Auth-Key' : cloudFlareAPI}
			payload = '{"purge_everything":true}'
			r = requests.delete(url, headers=headers, data=payload)

			sendMsg(m['nick'] + ' cleared the OverRustle.com cache on CloudFlare', "CLOUFLARE PURGE", m['nick'], ws)

		elif "dev on" in m['data']:
			url = 'https://api.cloudflare.com/client/v4/zones/' + cloudFlareZone + '/settings/development_mode'
			headers = {'Content-Type': 'application/json', 'X-Auth-Email' : cloudFlareEmail, 'X-Auth-Key' : cloudFlareAPI}
			payload = '{"value":"on"}'

			r = requests.patch(url, headers=headers, data=payload)

			sendMsg(m['nick'] + ' disabled CloudFlare caching for overrustle.com for the next 3 hours', "CLOUFLARE DEV ON", m['nick'], ws)

		elif "dev off" in m['data']:
			url = 'https://api.cloudflare.com/client/v4/zones/' + cloudFlareZone + '/settings/development_mode'
			headers = {'Content-Type': 'application/json', 'X-Auth-Email' : cloudFlareEmail, 'X-Auth-Key' : cloudFlareAPI}
			payload = '{"value":"off"}'

			r = requests.patch(url, headers=headers, data=payload)

			sendMsg(m['nick'] + ' enabled CloudFlare caching for overrustle.com', "CLOUFLARE DEV OFF", m['nick'], ws)

		else:
			sendMsg(m['nick'] + ' can\'t remember the command DuckerZ', "CLOUFLARE RTFM", m['nick'], ws)


	#API health
	if m['nick'] in ADMINS and m['data'].lower().startswith('!apicheck'):
		url = 'https://' + apiEndpoint + '/api'

		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		try:
			ssh.connect(apiEndpoint, username=healthUsername, password=healthPassword)
		except paramiko.SSHException:
			sendMsg(m['nick'] + ': ' + apiEndpoint + ' could not be reached via SSH. Server is probably offline or fucking dead :( ', "HEALTH API SSHFAIL", m['nick'], ws)
			return
		 
		stdin,stdout,stderr = ssh.exec_command("cat /proc/loadavg")
		 
		loadavgRaw = stdout.readlines()
		apiLoad = loadavgRaw[0].split()

		ssh.close()

		try:
			r = requests.get(url, timeout=1)
		except:
			sendMsg(m['nick'] + ': ' + apiEndpoint + ' Connection reset or timed out. Something is fucked :(', "HEALTH API FAIL", m['nick'], ws)
			return

		if r.status_code != 200:
			sendMsg(m['nick'] + ': ' + apiEndpoint + ' API returned HTTP/' + str(r.status_code) +' :(', "HEALTH API FAIL", m['nick'], ws)
			return
		else:
			meme = r.json()
			apiCheckTime = r.elapsed.total_seconds()
			sendMsg(m['nick'] + ': ' + str(meme['connections']) + ' connections (API), took ' + str(apiCheckTime) + ' seconds to return HTTP/' + str(r.status_code) + '. Server Load: ' + str(apiLoad[0]) + ' / ' + str(apiLoad[1]) + ' / ' + str(apiLoad[2]), "HEALTH API SUCCESS", m['nick'], ws)

	#Core servers health
	if m['nick'] in ADMINS and m['data'].lower().startswith('!corecheck'):
		url = 'http://' + coreEndpoint + ':4200'

		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		try:
			ssh.connect(coreEndpoint, username=healthUsername, password=healthPassword)
		except paramiko.SSHException:
			sendMsg(m['nick'] + ': ' + apiEndpoint + ' could not be reached via SSH. Server is probably offline or fucking dead :( ', "HEALTH API SSHFAIL", m['nick'], ws)
			return
		 
		stdin,stdout,stderr = ssh.exec_command("cat /proc/loadavg")
		 
		loadavgRaw = stdout.readlines()
		coreLoad = loadavgRaw[0].split()

		ssh.close()

		try:
			r = requests.get(url, timeout=1)
		except:
			sendMsg(m['nick'] + ': us-ewr1-core.overrustle.com Connection reset or timed out. Something is fucked :(', "HEALTH CORE FAIL", m['nick'], ws)
			return

		if r.status_code != 200:
			sendMsg(m['nick'] + ': us-ewr1-core.overrustle.com returned HTTP/' + str(r.status_code) +' :(', "HEALTH CORE FAIL", m['nick'], ws)
			return
		else:
			coreCheckTime = r.elapsed.total_seconds()
			sendMsg(m['nick'] + ': Application server took ' + str(coreCheckTime) + ' seconds to return HTTP/' + str(r.status_code) + ' . Server Load: ' + str(coreLoad[0]) + ' / ' + str(coreLoad[1]) + ' / ' + str(coreLoad[2]), "HEALTH API SUCCESS", m['nick'], ws)


	#Moderation - !reload
	if m['nick'] in ADMINS and m['data'].lower().startswith('!reload'):
		reloadString = m['data'][8:].lower()
		url = 'https://' + apiEndpoint + '/admin/reload/' + reloadString
		headers = {'Content-Type': 'application/json', 'API_SECRET' : apiAdminSecret}

		try:
			r = requests.get(url, headers=headers)
		except:
			sendMsg(m['nick'] + ': Something fucked up, command NOT sent. ', "RELOAD FAIL EXCEPTION", m['nick'], ws)
			return

		if r.status_code == 200:
			sendMsg(m['nick'] + ': OK. Reload sent!', "RELOAD " + reloadString, m['nick'], ws)
		else:
			sendMsg(m['nick'] + ': Something fucked up, command NOT sent. ', "RELOAD FAIL NOT200", m['nick'], ws)
			return

	#Moderation - !punt/!redirect - [u'!punt', u'dickinmyass', u'twitch/gayporn']  - 0/1/2
	if m['nick'] in ADMINS and m['data'].lower().startswith('!punt'):
		commandArray = m['data'].split()	

		if len(commandArray) != 3:
			sendMsg(m['nick'] + ': Are you retarded? Command does not work that way OhKrappa ', "PUNT FAIL RETARDED", m['nick'], ws)
			return
	
		puntFrom = commandArray[1].lower() #from
		puntTo = commandArray[2].replace('/','%2F') #to

		url = 'https://' + apiEndpoint + '/admin/punt/' + puntFrom + '/' + puntTo
		headers = {'Content-Type': 'application/json', 'API_SECRET' : apiAdminSecret}

		try:
			r = requests.get(url, headers=headers)
		except:
			sendMsg(m['nick'] + ': Something fucked up, command NOT sent. ', "PUNT FAIL EXCEPTION", m['nick'], ws)
			return

		if r.status_code == 200:
			sendMsg(m['nick'] + ': OK. Punting ' + commandArray[1] + ' to ' + commandArray[2], "PUNT " + commandArray[1] + " -> " + commandArray[2], m['nick'], ws)
		else:
			sendMsg(m['nick'] + ': Something fucked up, command NOT sent. ', "PUNT FAIL NOT200", m['nick'], ws)
			return


	#print(m['nick'] + ':', m['data'].encode('utf-8'))


def on_open(ws):
	print('[CONN]: Connected to ' + endpoint)


def on_error(ws, error):
	print "[ERROR]: Error Caught:" + error


def on_close(ws):
	print("[CONN] Websocket closed, reconnecting in 1 second")
	time.sleep(config.get("general","retry"))
	main()


def main():
	try:
		print('\r[CONN]: Connecting to ' + endpoint)
		ws = websocket.WebSocketApp(endpoint,
			header={
				"Cookie: authtoken=" + token,
				"Origin: http://www.destiny.gg"
			},
			on_message=on_message,
			on_error=on_error,
			on_close=on_close,
			on_open=on_open)

		ws.run_forever()
	except Exception:
		print('\r [CONN] Connecting failed, trying again...')
		time.sleep(config.get("general","retry"))
		main()


getDggEmotes()
main()