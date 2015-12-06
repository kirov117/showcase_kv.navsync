#!/usr/bin/env python
# -*- coding: utf-8 -*-

# KV.NavSync

import sys, os, copy, time, json, hashlib, scrypt, binascii
import MySQLdb as mdb

from base64 import b64encode, b64decode
from datetime import datetime, timedelta
from pymongo import MongoClient
from bson.objectid import ObjectId

from twisted.internet import reactor, ssl
from twisted.python import log
from twisted.web.server import Site
from twisted.web.static import File
from twisted.internet.defer import \
	Deferred, \
	inlineCallbacks, \
	returnValue

from autobahn.twisted.websocket import \
	WebSocketServerProtocol, \
	WebSocketServerFactory, \
	listenWS


def delKeys(obj, keys):
	for key in keys:
		if key in obj:
			del obj[key]
def epochTime():

	return str(int(time.time() * 1000))


class KvRequestError(Exception):
	def __init__(self, request, code, msg):
		self.request	= request
		self.code		= code
		self.msg		= msg

class KvCH():
	def __init__(self):

		self.chStack = {}

	def getUniqueID(self):

		while True:
			_id = binascii.b2a_hex(os.urandom(16))
			if not _id in self.chStack:
				break

		return _id

	def register(self, identifier, channel):

		if not identifier in self.chStack:
			self.chStack[identifier] = channel
	def unregister(self, identifier):

		if identifier in self.chStack:
			del self.chStack[identifier]

	def getUserChannels(self, userID):

		_list = []
		for _id in self.chStack:
			_session = self.chStack[_id].session

			if _session['isValidated'] == True and _session['userData']['id'] == userID:
				_list.append(self.chStack[_id])

		return _list

class KvURQ():
	def __init__(self):

		self.queueStack = {}

	@inlineCallbacks
	def processFirst(self, ch):

		userID = str(ch.session['userData']['id'])
		if userID in self.queueStack and len(self.queueStack[userID]):

			_req = self.queueStack[userID][0]

			try:
				yield _req.processRequest()

			except KvRequestError as e:
				KvNavSync.sendResponse(ch, {
					'reqid': _req.data['reqid'],
					'mode': _req.data['mode'],
					'type': 'error', 'error': { 'msg': e.msg, 'code': e.code } # 'originalRequest': e.request
				})
			except mdb.Error as e:
				print('DB ERROR {0}- {1}'.format(e.args[0], e.args[1]))
				KvNavSync.sendResponse(ch, {
					'reqid': _req.data['reqid'],
					'mode': _req.data['mode'],
					'type': 'error', 'error': { 'msg': 'Database error', 'code': 7777 }
				})
			except scrypt.error as e:
				print(e)
				KvNavSync.sendResponse(ch, {
					'reqid': _req.data['reqid'],
					'mode': _req.data['mode'],
					'type': 'error', 'error': { 'msg': 'Internal system error', 'code': 6666 }
				})
			except Exception as e:
				print(e)
				KvNavSync.sendResponse(ch, {
					'reqid': _req.data['reqid'],
					'mode': _req.data['mode'],
					'type': 'error', 'error': { 'msg': 'Unhandled exception', 'code': 9999 }
				})

			self.clearFirst(ch)
	def clearFirst(self, ch):

		userID = str(ch.session['userData']['id'])
		self.queueStack[userID].pop(0)

		if len(self.queueStack[userID]):
			self.processFirst(ch)
		else:
			del self.queueStack[userID]
	def queue(self, req, ch):

		userID = str(ch.session['userData']['id'])
		if not userID in self.queueStack:
			self.queueStack[userID] = []

		_call = False
		if not len(self.queueStack[userID]):
			_call = True

		self.queueStack[userID].append(req)

		if _call:
			self.processFirst(ch)


class KvAuthRequest():
	def __init__(self, ch, request):
		self.data	= request
		self.ch		= ch

	def __generateToken(self):
		# not protocol visible else security hole

		if not self.ch.session['isValidated']:
			return

		while True:
			_uniqid	= b64encode(os.urandom(9))					# 9len binary	=> 12len radix
			if not self.ch.dbc.userTokenExists(_uniqid):
				break
		_token_raw	= b64encode(os.urandom(24))					# 24len binary	=> 32len radix
		_token_sha	= hashlib.sha256(_token_raw).hexdigest()	# 32len radix	=> 64len utf8 sha256 hexdigest

		self.ch.dbc.createUserToken(
			uniqid	= _uniqid,
			token	= _token_sha,
			userID	= self.ch.session['userData']['id'],
			expires	= 30 # days from current date (db handler manages conversions)
		)

		return {
			'uniqid':	_uniqid,
			'token':	_token_raw
		}
	def __generateNavigator(self):
		while True:
			_navUniqid = b64encode(os.urandom(9))
			if not self.ch.dbc.navigatorExists(_navUniqid):
				break

		_navID = self.ch.dbc.createNavigator(
			uniqid =	_navUniqid,
			userAgent =	self.data['navigatorData']['userAgent'],
			vendor =	self.data['navigatorData']['vendor'],
			platform =	self.data['navigatorData']['platform'],
			language =	self.data['navigatorData']['language'],
			type =		self.data['navigatorData']['type']
		)

		return {
			'uniqid': _navUniqid,
			'id': _navID
		}

	### Protocol Visible ###
	def __validate(self):

		if self.ch.session['isValidated']:
			raise KvRequestError(self.data, 107, 'Already validated');

		if not( \
			'userData' in self.data and all (k in self.data['userData'] for k in ('username', 'pw')) and \
			'navigatorID' in self.data and (self.data['navigatorID'] != False or \
			('navigatorData' in self.data and all(k in self.data['navigatorData'] for k in ('userAgent', 'vendor', 'platform', 'language', 'type')) )) \
		):
			raise KvRequestError(self.data, 111, 'Missing or incomplete request body');

		if self.data['navigatorID'] != False and len(self.data['navigatorID']) != 12:
			raise KvRequestError(self.data, 109, 'Browser profiling error');

		if not 5 <= len(self.data['userData']['username']) <= 30:
			raise KvRequestError(self.data, 108, 'Incorrect credentials');

		if not 6 <= len(self.data['userData']['pw']) <= 72:
			raise KvRequestError(self.data, 108, 'Incorrect credentials');

		if not self.ch.dbc.userExists(self.data['userData']['username']):
			raise KvRequestError(self.data, 108, 'Incorrect credentials');

		_pwsalt = self.ch.dbc.getUserSalt(self.data['userData']['username'])

		_userID = self.ch.dbc.validateUser(
			username = self.data['userData']['username'],
			password = scrypt.hash(self.data['userData']['pw'].encode('utf-8'), _pwsalt)
		)

		if not _userID:
			raise KvRequestError(self.data, 108, 'Incorrect credentials');

		if self.data['navigatorID'] == False:
			_sendNav = True
			_newNav = self.__generateNavigator()

			_navUniqid =	_newNav['uniqid']
			_navID =		_newNav['id']

		else:
			_sendNav = False
			_navID = self.ch.dbc.navigatorExists(self.data['navigatorID'])

			if not _navID: # nav supplied but does not exist
				_sendNav = True
				_newNav = self.__generateNavigator()

				_navUniqid =	_newNav['uniqid']
				_navID =		_newNav['id']


		self.ch.session.update({
			'isValidated': True,
			'validationType': 'auth',
			'userData': {
				'id':		int(_userID),
				'username':	self.data['userData']['username']
			},
			'navigatorID': int(_navID)
		})

		sendData = { # base object for response
			'reqid': self.data['reqid'],
			'mode': 'auth',
			'method': 'validate',
			'type': 'success',
			'userData': {
				'username': self.data['userData']['username']
			}
		}

		if 'requestToken' in self.data and self.data['requestToken'] == True: # add token data to response if requested
			tokenData = self.__generateToken()
			sendData.update({'tokenData': {
				'Q': b64encode(tokenData['uniqid']),
				'K': b64encode(tokenData['token'])
			}})
			self.ch.session.update({'tokenData': tokenData})

		if _sendNav: # send new navigator ID if new nav or invalid nav supplied
			sendData.update({
				'navigatorID': _navUniqid
			})

		KvNavSync.sendResponse(self.ch, sendData)
	def __register(self):

		if self.ch.session['isValidated']:
			raise KvRequestError(self.data, 105, 'Already validated');

		if not ( \
			'userData' in self.data and all (k in self.data['userData'] for k in ('username', 'email', 'pw1', 'pw2')) \
		):
			raise KvRequestError(self.data, 106, 'Missing or incomplete request body');

		if not 5 <= len(self.data['userData']['username']) <= 30:
			raise KvRequestError(self.data, 100, 'Invalid username');

		if len(self.data['userData']['email']) < 5:
			raise KvRequestError(self.data, 101, 'Invalid email address');

		if not 6 <= len(self.data['userData']['pw1']) <= 72:
			raise KvRequestError(self.data, 102, 'Invalid password length');

		if self.data['userData']['pw1'] != self.data['userData']['pw2']:
			raise KvRequestError(self.data, 103, 'Non-matching passwords');

		if self.ch.dbc.userExists(self.data['userData']['username']):
			raise KvRequestError(self.data, 104, 'Username is already registered');

		_pwsalt = os.urandom(16)
		newUserID = self.ch.dbc.createUser(
			username	= self.data['userData']['username'],
			email		= self.data['userData']['email'],
			password	= scrypt.hash(self.data['userData']['pw1'].encode('utf-8'), _pwsalt),
			pwsalt		= _pwsalt
		)

		sendData = {
			'reqid': self.data['reqid'],
			'mode': 'auth',
			'method': 'register',
			'type': 'success',
			'userData': {
				'username': self.data['userData']['username']
			}
		}
		KvNavSync.sendResponse(self.ch, sendData)
	def __token(self):
		# received token will be 32 length non-hashed radix urandom data
		# same value will be 64 length hexdigested sha-256 char value in DB
		# uniqid will be 12 length radix both client storage and DB

		if self.ch.session['isValidated']:
			raise KvRequestError(self.data, 115, 'Already validated');

		if not ( \
			'userData' in self.data and 'username' in self.data['userData'] \
			and 'tokenData' in self.data and all (k in self.data['tokenData'] for k in ('Q', 'K')) \
			and 'navigatorID' in self.data and (self.data['navigatorID'] != False \
				or ('navigatorData' in self.data and all(k in self.data['navigatorData'] for k in ('userAgent', 'vendor', 'platform', 'language', 'type')) )) \
		):
			raise KvRequestError(self.data, 112, 'Missing or incomplete request body');

		if self.data['navigatorID'] != False and len(self.data['navigatorID']) != 12:
			raise KvRequestError(self.data, 114, 'Browser profiling error');

		_uniqid = b64decode(self.data['tokenData']['Q']);
		if not len(_uniqid) == 12:
			raise KvRequestError(self.data, 113, 'Invalid token')

		_token = b64decode(self.data['tokenData']['K']);
		if not len(_token) == 32:
			raise KvRequestError(self.data, 113, 'Invalid token')

		if not self.ch.dbc.userExists(self.data['userData']['username']):
			raise KvRequestError(self.data, 113, 'Invalid token')

		_id = self.ch.dbc.getUserID(self.data['userData']['username'])
		_token_sha = hashlib.sha256(_token).hexdigest()

		if not self.ch.dbc.validateToken(_uniqid, _token_sha, _id):
			raise KvRequestError(self.data, 113, 'Invalid token')

		if self.data['navigatorID'] == False:
			_sendNav = True
			_newNav = self.__generateNavigator()

			_navUniqid =	_newNav['uniqid']
			_navID =		_newNav['id']

		else:
			_sendNav = False
			_navID = self.ch.dbc.navigatorExists(self.data['navigatorID'])

			if not _navID: # nav supplied but does not exist
				_sendNav = True
				_newNav = self.__generateNavigator()

				_navUniqid =	_newNav['uniqid']
				_navID =		_newNav['id']

		self.ch.session.update({
			'isValidated': True,
			'validationType': 'token',
			'userData': {
				'id':		int(_id),
				'username':	self.data['userData']['username']
			},
			'navigatorID': int(_navID)
		})

		self.ch.dbc.expireToken(_uniqid)
		tokenData = self.__generateToken()
		self.ch.session.update({'tokenData': tokenData})

		sendData = {
			'reqid': self.data['reqid'],
			'mode': 'auth',
			'method': 'token',
			'type': 'success',
			'userData': {
				'username': self.data['userData']['username']
			},
			'tokenData': {
				'Q': b64encode(tokenData['uniqid']),
				'K': b64encode(tokenData['token'])
			}
		}

		if _sendNav: # send new navigator ID if new nav or invalid nav supplied
			sendData.update({
				'navigatorID': _navUniqid
			})


		KvNavSync.sendResponse(self.ch, sendData)
	def __invalidate(self):

		if not self.ch.session['isValidated']:
			raise KvRequestError(self.data, 117, 'Already invalidated');

		if 'tokenData' in self.ch.session:
			self.ch.dbc.expireToken(self.ch.session['tokenData']['uniqid'])

		self.ch.session['isValidated'] = False
		delKeys(self.ch.session, [
			'validationType',
			'userData',
			'tokenData',
			'navigatorID'
		])

		sendData = {
			'reqid': self.data['reqid'],
			'mode': 'auth',
			'method': 'invalidate',
			'type': 'success'
		}

		KvNavSync.sendResponse(self.ch, sendData)

	def processRequest(self):
		if not 'method' in self.data:
			raise KvRequestError(self.data, 140, 'No auth method requested');

		elif self.data['method'] == 'validate':
			self.__validate()
		elif self.data['method'] == 'register':
			self.__register()
		elif self.data['method'] == 'token':
			self.__token()
		elif self.data['method'] == 'invalidate':
			self.__invalidate()

		else:
			raise KvRequestError(self.data, 150, 'Unsupported method requested');
class KvSyncRequest():
	def __init__(self, ch, request):
		self.data	= request
		self.ch		= ch
		self.epoch	= epochTime()

		if not self.ch.session['isValidated']:
			raise KvRequestError(self.data, 200, 'Not validated')

	def __groupNodeExists(self, tree, title):
		for k in tree:
			if 'children' in tree[k] and tree[k]['title'] == title:
				return k
		return False
	def __bookmarkNodeExists(self, tree, url):
		for k in tree:
			if 'url' in tree[k] and tree[k]['url'] == url:
				return k
		return False

	def __getNodeFromTree(self, tree, nodeOid):
		if nodeOid in tree:
			return tree[nodeOid]

		for oid in tree:
			if 'children' in tree[oid]:
				res = self.__getNodeFromTree(tree[oid]['children'], nodeOid)
				if res:
					return res

		return None

	def __addGroupNode(self, dst, parent, title, timeAdded, timeUpdated, timeMoved):

		# generate 24len unique id for bookmark
		_uniqid = binascii.b2a_hex(os.urandom(12))

		dst[_uniqid] = {
			'parent':		parent,
			'title':		title,
			'timeAdded':	timeAdded,
			'timeUpdated':	timeUpdated,
			'timeMoved':	timeMoved,
			'children':		{}
		}

		return _uniqid
	def __addBookmarkNode(self, dst, parent, title, url, timeAdded, timeUpdated, timeMoved):

		# generate 24len unique id for bookmark
		_uniqid = binascii.b2a_hex(os.urandom(12))

		dst[_uniqid] = {
			'parent':		parent,
			'title':		title,
			'url':			url,
			'timeAdded':	timeAdded,
			'timeUpdated':	timeUpdated,
			'timeMoved':	timeMoved
		}

		return _uniqid

	def __sendSync(self):
		if not 'operations' in self.data:
			raise KvRequestError(self.data, 205, 'Missing or incomplete request body');

		if not len(self.data['operations']):
			raise KvRequestError(self.data, 206, 'No sync operations');

		_equivTable = {}
		dbTree = self.ch.dbb.getBookmarkTree(self.ch.session['userData']['id'])

		for op in self.data['operations']:

			if not all (k in op for k in ('type', 'data')):
				raise KvRequestError(self.data, 207, 'Missing or incomplete operation body')

			# ADD Operation
			elif op['type'] == 'add':

				if not all(k in op['data'] for k in ('id', 'parentOid', 'title')):
					raise KvRequestError(self.data, 209, 'Missing or incomplete "add" data')

				if (op['data']['parentOid'] == None):
					_dst = dbTree
				else:
					_dst = self.__getNodeFromTree(dbTree, op['data']['parentOid'])['children']

				_exists = False

				# Bookmark Node
				if 'url' in op['data']:
					_uniqid = self.__bookmarkNodeExists(_dst, op['data']['url'])

					if _uniqid:
						_exists = True
					else:
						_uniqid = self.__addBookmarkNode(
							dst			= _dst,
							parent		= op['data']['parentOid'],
							title		= op['data']['title'],
							url			= op['data']['url'],
							timeAdded	= self.epoch,
							timeUpdated	= self.epoch,
							timeMoved	= self.epoch,
						)

				# Group Node
				else:
					_uniqid = self.__groupNodeExists(_dst, op['data']['title'])

					if _uniqid:
						_exists = True
					else:
						_uniqid = self.__addGroupNode(
							dst			= _dst,
							parent		= op['data']['parentOid'],
							title		= op['data']['title'],
							timeAdded	= self.epoch,
							timeUpdated	= self.epoch,
							timeMoved	= self.epoch
						)

				_equivTable.update( {str(op['data']['id']): _uniqid} )

				# delete useless data and actualize oid
				del op['data']['id']
				op['data']['oid'] = _uniqid

				if not _exists:
					# using _exists flag to prevent anomalous duplicate requests
					self.ch.dbc.registerOperation(
						ownerID			= self.ch.session['userData']['id'],
						navigatorID		= self.ch.session['navigatorID'],
						data			= json.dumps(op),
						clientTimestamp	= self.data['clientTimestamp'],
						serverTimestamp	= self.epoch
					)

			# UPDATE Operation
			elif op['type'] == 'update':

				if not all(k in op['data'] for k in ('oid', 'title')):
					raise KvRequestError(self.data, 210, 'Missing or incomplete "update" data')

				_sameTitle = _sameUrl = False

				_node = self.__getNodeFromTree(dbTree, op['data']['oid'])

				# skip current operation if node to be updated does not exist
				if not _node:
					continue

				if _node['title'] == op['data']['title']:
					_sameTitle = True
				else:
					_node['title'] = op['data']['title']

				if 'url' in op['data']:
					if _node['url'] == op['data']['url']:
						_sameUrl = True
					else:
						_node['url'] = op['data']['url']

				if not (_sameTitle and _sameUrl):
					# using _sameTitle/_sameUrl flags to prevent anomalous duplicate requests

					_node['timeUpdated'] = self.epoch

					self.ch.dbc.registerOperation(
						ownerID			= self.ch.session['userData']['id'],
						navigatorID		= self.ch.session['navigatorID'],
						data			= json.dumps(op),
						clientTimestamp	= self.data['clientTimestamp'],
						serverTimestamp	= self.epoch
					)

			# MOVE Operation
			elif op['type'] == 'move':

				if not all(k in op['data'] for k in ('oid', 'oldParentOid', 'newParentOid')):
					raise KvRequestError(self.data, 211, 'Missing or incomplete "move" data')

				# first enter old parent node's children list
				if op['data']['oldParentOid'] == None:
					_oldParent = dbTree
				else:
					_oldParent = self.__getNodeFromTree(dbTree, op['data']['oldParentOid'])['children']

				# check for parenting authenticity to prevent anomalous duplicate requests
				# and correct by alternately looking up node directly and getting parent from it
				if not op['data']['oid'] in _oldParent:
					_node = self.__getNodeFromTree(dbTree, op['data']['oid'])

					# skip current operation if node to be moved does not exist
					if not _node:
						continue

					if _node['parent'] == None:
						_oldParent = dbTree
					else:
						_oldParent = self.__getNodeFromTree(dbTree, _node['parent'])['children']

				# duplicate target node from old parent
				_targetCopy = copy.deepcopy(_oldParent[op['data']['oid']])

				# delete original reference from the old parent
				del _oldParent[op['data']['oid']]

				# secondly, enter new parent node's children list
				if op['data']['newParentOid'] == None:
					_newParent = dbTree
					_targetCopy['parent'] = None
				else:
					_newParent = self.__getNodeFromTree(dbTree, op['data']['newParentOid'])['children']
					_targetCopy['parent'] = op['data']['newParentOid']

				# update last move timestamp
				_targetCopy['timeMoved'] = self.epoch

				# add target copy to new parent
				_newParent[op['data']['oid']] = _targetCopy

				self.ch.dbc.registerOperation(
					ownerID			= self.ch.session['userData']['id'],
					navigatorID		= self.ch.session['navigatorID'],
					data			= json.dumps(op),
					clientTimestamp	= self.data['clientTimestamp'],
					serverTimestamp	= self.epoch
				)

			# DELETE Operation
			elif op['type'] == 'delete':

				if not all(k in op['data'] for k in ('oid', 'parentOid')):
					raise KvRequestError(self.data, 212, 'Missing or incomplete "delete" data')

				# enter parent node's children list
				if op['data']['parentOid'] == None:
					_parent = dbTree
				else:
					_parent = self.__getNodeFromTree(dbTree, op['data']['parentOid'])['children']

				# check for parenting authenticity to prevent anomalous duplicate requests
				# and correct by alternately looking up node directly and getting parent from it
				if not op['data']['oid'] in _parent:
					_node = self.__getNodeFromTree(dbTree, op['data']['oid'])

					# skip current operation if node to be moved does not exist
					if not _node:
						continue

					if _node['parent'] == None:
						_parent = dbTree
					else:
						_parent = self.__getNodeFromTree(dbTree, _node['parent'])['children']

				# delete reference from parent
				del _parent[op['data']['oid']]

				self.ch.dbc.registerOperation(
					ownerID			= self.ch.session['userData']['id'],
					navigatorID		= self.ch.session['navigatorID'],
					data			= json.dumps(op),
					clientTimestamp	= self.data['clientTimestamp'],
					serverTimestamp	= self.epoch
				)

			else:
				raise KvRequestError(self.data, 208, 'Unsupported operation type');

		self.ch.dbb.updateBookmarkTree(self.ch.session['userData']['id'], dbTree)
		self.ch.session['cxeq'].update(_equivTable)

		KvNavSync.sendResponse(self.ch, {
			'reqid': self.data['reqid'],
			'mode': 'sync',
			'method': 'sendSync',
			'type': 'success',
			'cxeq': _equivTable
		})

	def __treeInterleave(self, src, dst, treeID, skipChecks, equivTable):
		### Recursive function(!), combines source into destination, avoiding duplicates
		# src - from tree (source), obtained from client JS handler
		# dst - to tree (destination), obtained from server DB handler
		# treeID - id of current tree (level) - None/null if root
		# skipChecks - value True to be used at first sync, when db tree is empty ([])
		#			 - used for performance considerations
		# equivTable - reference to cxeq locally-scoped object for ID matching

		for node in src:

			# Group Node
			if not 'url' in node and 'children' in node:

				_groupID = self.__groupNodeExists(dst, node['title'])
				if not skipChecks and _groupID:
					# recurse into group that already exists and evaluate its nodes
					self.__treeInterleave(
						src			= node['children'],
						dst			= dst[_groupID]['children'],
						treeID		= _groupID,
						skipChecks	= False,
						equivTable	= equivTable
					)

					equivTable.update( {str(node['id']): _groupID} )
					continue

				### else add group to destination
				_uniqid = self.__addGroupNode(
					dst			= dst,
					parent		= treeID,
					title		= node['title'],
					timeAdded	= self.epoch,
					timeUpdated	= self.epoch,
					timeMoved	= self.epoch
				)

				# recurse into group after creation
				self.__treeInterleave(
					src			= node['children'],
					dst			= dst[_uniqid]['children'],
					treeID		= _uniqid,
					skipChecks	= True,
					equivTable	= equivTable
				)

				equivTable.update( {str(node['id']): _uniqid} )

			# Bookmark Node
			elif 'url' in node:

				_bookmarkID = self.__bookmarkNodeExists(dst, node['url'])
				if not skipChecks and _bookmarkID:
					equivTable.update( {str(node['id']): _bookmarkID} )
					# skip bookmark nodes that already exist
					continue

				### else add bookmark to destination
				_uniqid = self.__addBookmarkNode(
					dst			= dst,
					parent		= treeID,
					title		= node['title'],
					url			= node['url'],
					timeAdded	= self.epoch,
					timeUpdated = self.epoch,
					timeMoved	= self.epoch
				)

				equivTable.update( {str(node['id']): _uniqid} )
	def __sendFullSync(self):
		# does a full tree sync
		if not ('bookmarkData' in self.data and 'tree' in self.data['bookmarkData']):
			raise KvRequestError(self.data, 201, 'Missing or incomplete request body');

		_equivTable = {}
		dbTree = self.ch.dbb.getBookmarkTree(self.ch.session['userData']['id'])

		self.__treeInterleave(
			src			= self.data['bookmarkData']['tree'],
			dst			= dbTree,
			treeID		= None,
			skipChecks	= not len(dbTree.keys()), # True when no keys in tree (meaning empty)
			equivTable	= _equivTable
		)

		# Independently register macro type:full operation
		self.ch.dbc.registerOperation(
			ownerID			= self.ch.session['userData']['id'],
			navigatorID		= self.ch.session['navigatorID'],
			data			= json.dumps( {'type': 'full'} ),
			clientTimestamp	= self.data['clientTimestamp'],
			serverTimestamp	= self.epoch
		)

		self.ch.dbb.updateBookmarkTree(self.ch.session['userData']['id'], dbTree)
		self.ch.session['cxeq'].update(_equivTable)

		KvNavSync.sendResponse(self.ch, {
			'reqid': self.data['reqid'],
			'mode': 'sync',
			'method': 'sendFullSync',
			'type': 'success',
			'cxeq': _equivTable
		})


	def __getDiffSync(self):

		if not 'lastGetSyncTimestamp' in self.data:
			raise KvRequestError(self.data, 230, 'No timestamp provided');

		_diffOp = self.ch.dbc.getOperationsDiff(
			ownerID			= self.ch.session['userData']['id'],
			navigatorID		= self.ch.session['navigatorID'],
			serverTimestamp	= self.data['lastGetSyncTimestamp']
		)

		dbTree = self.ch.dbb.getBookmarkTree(self.ch.session['userData']['id'])

		# additional special step that assures move operations get target subtree/node included
		for op in _diffOp:
			if op['type'] == 'move':
				op['subtree'] = self.__getNodeFromTree(dbTree, op['data']['oid'])

		KvNavSync.sendResponse(self.ch, {
			'reqid': self.data['reqid'],
			'mode': 'sync',
			'method': 'getDiffSync',
			'type': 'success',
			'bookmarkData': {
				'operations': _diffOp
			}
		})

	def __cleanGetTree(self, tree):

		for k in tree:

			del tree[k]['parent']
			del tree[k]['timeAdded']

			# ????????
			del tree[k]['timeUpdated']
			del tree[k]['timeMoved']

			if 'children' in tree[k]:
				self.__cleanGetTree(tree[k]['children'])
	def __getFullSync(self):

		dbTree = self.ch.dbb.getBookmarkTree(self.ch.session['userData']['id'])

		# clean useless server-only data prior to sending get tree
		self.__cleanGetTree(dbTree)

		KvNavSync.sendResponse(self.ch, {
			'reqid': self.data['reqid'],
			'mode': 'sync',
			'method': 'getFullSync',
			'type': 'success',
			'bookmarkData': {
				'tree': dbTree
			}
		})


	def __getServerOffset(self):

		if not 'clientTimestamp' in self.data:
			raise KvRequestError(self.data, 240, 'No timestamp provided');

		KvNavSync.sendResponse(self.ch, {
			'reqid': self.data['reqid'],
			'mode': 'sync',
			'method': 'getServerOffset',
			'type': 'success',
			'serverOffset': int(epochTime()) - int(self.data['clientTimestamp'])
		})


	def processRequest(self):
		if not 'method' in self.data:
			raise KvRequestError(self.data, 280, 'No sync method requested');

		elif self.data['method'] == 'getDiffSync':
			self.__getDiffSync()
		elif self.data['method'] == 'getFullSync':
			self.__getFullSync()

		elif self.data['method'] == 'sendSync':
			self.__sendSync()
		elif self.data['method'] == 'sendFullSync':
			self.__sendFullSync()

		elif self.data['method'] == 'getServerOffset':
			self.__getServerOffset()

		else:
			raise KvRequestError(self.data, 290, 'Unsupported method requested');
class KvProtoRequest():
	def __init__(self, ch, request):
		# request must be JSON-encoded, b64decoded
		self.text = request
		self.ch = ch

	def interpretData(self):
		# interprets JSON data from b64 decoded payload data

		# Check #1: JSON data integrity
		try:
			self.data = json.loads(self.text)
		except:
			print('Invalid JSON- ignoring')
			KvNavSync.sendResponse(self.ch, { 'type': 'error', 'error': { 'msg': 'Invalid JSON', 'code': 30 } })
			return
		# Check #2: Request has reqid (unique request identifier)
		if not 'reqid' in self.data:
			print('No mode- ignoring')
			KvNavSync.sendResponse(self.ch, { 'type': 'error', 'error': { 'msg': 'No request identifier', 'code': 32 } })
			return
		# Check #3: Request contains mode
		if not 'mode' in self.data:
			print('No mode- ignoring')
			KvNavSync.sendResponse(self.ch, { 'reqid': self.data['reqid'], 'type': 'error', 'error': { 'msg': 'No mode requested', 'code': 31 } })
			return

		# OK, process request
		try:
			if self.data['mode'] == 'auth':
				authRequest = KvAuthRequest(self.ch, self.data)
				authRequest.processRequest()

			elif self.data['mode'] == 'sync': # sync requests should be asynchronous, so will be using the URQ
				syncRequest = KvSyncRequest(self.ch, self.data)
				URQ.queue(syncRequest, self.ch)

			else:
				print('Invalid mode- ignoring')
				KvNavSync.sendResponse(self.ch, { 'reqid': self.data['reqid'], 'type': 'error', 'error': { 'msg': 'Unsupported mode requested', 'code': 33 } })

		except KvRequestError as e:
			KvNavSync.sendResponse(self.ch, {
				'reqid': self.data['reqid'],
				'mode': self.data['mode'],
				'type': 'error', 'error': { 'msg': e.msg, 'code': e.code } # 'originalRequest': e.request
			})
		except mdb.Error as e:
			print('DB ERROR {0}- {1}'.format(e.args[0], e.args[1]))
			KvNavSync.sendResponse(self.ch, {
				'reqid': self.data['reqid'],
				'mode': self.data['mode'],
				'type': 'error', 'error': { 'msg': 'Database error', 'code': 7777 }
			})
		except scrypt.error as e:
			print(e)
			KvNavSync.sendResponse(self.ch, {
				'reqid': self.data['reqid'],
				'mode': self.data['mode'],
				'type': 'error', 'error': { 'msg': 'Internal system error', 'code': 6666 }
			})
		except Exception as e:
			print(e)
			KvNavSync.sendResponse(self.ch, {
				'reqid': self.data['reqid'],
				'mode': self.data['mode'],
				'type': 'error', 'error': { 'msg': 'Unhandled exception', 'code': 9999 }
			})

class KvNavSync(WebSocketServerProtocol):

	def __init__(self):

		# generate unique session identifier
		_id = CH.getUniqueID()

		# clean start session variables
		self.session = {
			'id': _id,
			'isValidated': False,
			'cxeq': {}				# cross equivalence list
									# (table that matches globally-unique server OIDs with client nav IDs)
									# is retrieved and parsed from client's local storage
									# list is session-scoped, regardless of logged in user (nav data is the same)
		}

		# add self to active channel pool
		CH.register(_id, self)

		# start up session db handlers
		self.dbc = KvSystemMySQLHandler()
		self.dbb = KvBookmarkMongoDBHandler()

	def onConnect(self, request):

		print('Client REQ- {0}'.format(request.peer))
		if 'kvnsproto-0' in request.protocols:
			print('PROTO match- accept client')
		else:
			print('PROTO bad- drop client')
			self.sendClose(3010, 'PROTO bad- drop client')
	def onOpen(self):

		print('KVNS open')
	def onMessage(self, payload, isBinary):

		if not isBinary:
			decPayload = b64decode(payload.decode('utf8'))
			print('IN- {0}'.format(decPayload))

			clientRequest = KvProtoRequest(self, decPayload)
			clientRequest.interpretData()
	def onClose(self, wasClean, code, reason):

		print('KVNS close- {0}'.format(reason))
		CH.unregister(self.session['id'])

	def sendResponse(self, obj):

		obj['serverTimestamp'] = epochTime()

		encPayload = json.dumps(obj)
		print('OUT- {0}'.format(encPayload))

		encPayload = b64encode(encPayload)

		self.sendMessage(encPayload, isBinary = False)


class KvSystemMySQLHandler():
	def __init__(self):

		self.__connect()

	def __connect(self):
		self.dbcon = mdb.connect('localhost', 'usr_kv_navsync', '93m~4\\".o}#va&^D', 'kv_navsync')
		self.dbcon.autocommit(True)

		self.dbcursor = self.dbcon.cursor(mdb.cursors.DictCursor)
	def __check(self):
		if self.dbcon is None:
			self.__connect()
		else:
			self.dbcon.ping(True)

	def userExists(self, username):
		self.__check()

		self.dbcursor.execute('SELECT COUNT(*) FROM users WHERE username = %s', [username])

		res = self.dbcursor.fetchone()
		return res.itervalues().next() != 0
	def createUser(self, username, email, password, pwsalt):
		self.__check()

		self.dbcursor.execute('INSERT INTO users (\
				username, \
				email, \
				password, \
				pwsalt, \
				time_created, \
				time_last_auth\
			) VALUES (\
				%s, \
				%s, \
				%s, \
				%s, \
				NOW(), \
				NOW() \
			)', [username, email, password, pwsalt])

		return self.dbcursor.lastrowid
	def validateUser(self, username, password):
		self.__check()

		self.dbcursor.execute('SELECT id FROM users WHERE username = %s AND password = %s', [username, password])

		if not self.dbcursor.rowcount:
			return False
		else:
			res = self.dbcursor.fetchone()

			# set last auth time to now
			self.dbcursor.execute('UPDATE users SET time_last_auth = NOW() WHERE username = %s', [username])

			return res['id']
	def getUserID(self, username):
		self.__check()

		self.dbcursor.execute('SELECT id FROM users WHERE username = %s', [username])

		if not self.dbcursor.rowcount:
			return False
		else:
			res = self.dbcursor.fetchone()
			return res['id']
	def getUserSalt(self, username):
		self.__check()

		self.dbcursor.execute('SELECT pwsalt FROM users WHERE username = %s', [username])

		if not self.dbcursor.rowcount:
			return None
		else:
			res = self.dbcursor.fetchone()
			return res['pwsalt']

	def navigatorExists(self, uniqid):
		self.__check()

		self.dbcursor.execute('SELECT id FROM navigators WHERE uniqid = %s', [uniqid])

		if not self.dbcursor.rowcount:
			return False
		else:
			res = self.dbcursor.fetchone()
			return res['id']
	def getNavigatorTypeID(self, type):
		self.__check()

		self.dbcursor.execute('SELECT id FROM navigator_types WHERE name = %s', [type])

		if not self.dbcursor.rowcount:
			return False
		else:
			res = self.dbcursor.fetchone()
			return res['id']
	def createNavigator(self, uniqid, userAgent, vendor, platform, language, type):
		self.__check()

		_navTypeID = self.getNavigatorTypeID(type)

		self.dbcursor.execute('INSERT INTO navigators (\
				uniqid, \
				useragent, \
				vendor, \
				platform, \
				language, \
				type_id, \
				active, \
				time_added \
			) VALUES (%s, %s, %s, %s, %s, %s, TRUE, NOW())', [uniqid, userAgent, vendor, platform, language, _navTypeID])

		return self.dbcursor.lastrowid

	def userTokenExists(self, uniqid):
		self.__check()

		self.dbcursor.execute('SELECT COUNT(*) FROM auth_tokens WHERE uniqid = %s', [uniqid])

		res = self.dbcursor.fetchone()
		return res.itervalues().next() != 0
	def createUserToken(self, uniqid, token, userID, expires):
		self.__check()

		expires = '{:%Y-%m-%d %H:%M:%S}'.format(datetime.now() + timedelta(days = expires))

		self.dbcursor.execute('INSERT INTO auth_tokens (\
				uniqid, \
				token, \
				user_id, \
				expires\
			) VALUES (%s, %s, %s, %s)', [uniqid, token, userID, expires])
	def validateToken(self, uniqid, token, userID):
		self.__check()
		self.dbcursor.execute('SELECT COUNT(*) FROM auth_tokens WHERE \
			uniqid	= %s AND \
			token	= %s AND \
			user_id	= %s \
			', [uniqid, token, userID])

		res = self.dbcursor.fetchone()
		return res.itervalues().next() != 0
	def expireToken(self, uniqid):
		self.__check()

		self.dbcursor.execute('DELETE FROM auth_tokens WHERE uniqid = %s', [uniqid])

	def registerOperation(self, ownerID, navigatorID, data, clientTimestamp, serverTimestamp):
		self.__check()

		self.dbcursor.execute('INSERT INTO operations (\
				owner_id, \
				navigator_id, \
				data, \
				timestamp_client, \
				timestamp_server \
			) VALUES (%s, %s, %s, %s, %s)', [ownerID, navigatorID, data, clientTimestamp, serverTimestamp])

		return self.dbcursor.lastrowid
	def getOperationsDiff(self, ownerID, navigatorID, serverTimestamp):
		self.__check()

		_diffList = []

		# Get differential data, but only from other navigators (not self)
		self.dbcursor.execute('SELECT data, timestamp_server FROM operations WHERE \
				owner_id			= %s AND \
				navigator_id		!= %s AND \
				timestamp_server	> %s \
			ORDER BY timestamp_server ASC', [ownerID, navigatorID, serverTimestamp])

		rows = self.dbcursor.fetchall()

		for r in rows:
			_data = json.loads(r['data'])
			_data['serverTimestamp'] = r['timestamp_server']

			_diffList.append(_data)

		return _diffList

class KvBookmarkMongoDBHandler():
	def __init__(self):

		self.__connect()

	def __connect(self):
		self.client = MongoClient('mongodb://localhost:27017/')

		self.db = self.client.kv_navsync
		self.db.authenticate('usr_kv_navsync', 'AV2@2*.BdN+{iM7q')

		self.col = self.db.bookmarks

	def getBookmarkTree(self, ownerID):
		ret = self.col.find( {'ownerID': ownerID} )

		if not ret.count():
			# if no previous tree exists, create placeholder and return empty list
			self.createBookmarkTree(ownerID)
			return {}
		else:
			return ret[0]['tree']
	def createBookmarkTree(self, ownerID):
		# creates an empty tree, to be populated later
		self.col.insert({
			'ownerID': ownerID,
			'tree': {}
		})
	def updateBookmarkTree(self, ownerID, tree):
		# presumes prior existence of tree in DB
		self.col.update( {'ownerID': ownerID}, {
			'$set': {
				'tree': tree
			}
		})


if __name__ == '__main__':

	log.startLogging(sys.stdout)

	print('DB CONN establish')

	CH	= KvCH()	# global memory store for active CHannels (aka ws connections)
	URQ	= KvURQ()	# User Request Queue (part of partially sequential locking concept)
					# - assures data consistency when simultaneous distinct cross-session requests occur
					# - fires up only for SYNC requests, both for read and write
					# (ex: only pass out response for read request when previous write requests finish)
					# - partial: only delays same-user responses, maintaining cross-user asynchronicity

	#contextFactory = ssl.DefaultOpenSSLContextFactory('keys/server.key', 'keys/server.crt')
	factory = WebSocketServerFactory(
		url			= 'ws://localhost:17833',
		protocols	= ['kvnsproto-0'],
		headers		= {'Sec-WebSocket-Protocol': 'kvnsproto-0'},
		server		= 'KvNavSync_server/1.0',
		debug		= False
	)
	factory.protocol = KvNavSync

	# Rock 'N' Roll
	reactor.listenTCP(17833, factory)
	reactor.run()
