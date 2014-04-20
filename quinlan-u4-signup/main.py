#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import re
import random
import string
import hashlib
import logging

from string import letters
from google.appengine.ext import db

import webapp2
import jinja2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)

class User(db.Model):
	username = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt=make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s|%s' % (h, salt)

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def valid_pw(name, pw, h):
	logging.info("h: %s", h)
	salt = h.split('|')[1]
	return h == make_pw_hash(name, pw, salt)

def render(self, template, **params):
	t = jinja_env.get_template(template)
	self.response.out.write(t.render(params))

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

class MainHandler(webapp2.RequestHandler):
	def get(self):
		render(self, "signup-form.html")

	def post(self):
		have_error = False
		username = self.request.get("username")
		password = self.request.get("password")
		confirm = self.request.get("verify")
		email = self.request.get("email")
		params = dict(username = username,
					  email = email)
		if not valid_username(username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(password, confirm):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif password != confirm:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(email):
			params['error_email'] = "That's not a valid email."
			have_error = True

		if have_error:
			render(self, 'signup-form.html', **params)
		else:
			logging.info("make_pw_hash(username, password): %s", make_pw_hash(username, password))
			self.response.headers.add_header('Set-Cookie', 'user='+username.encode('ascii','replace')+'; Path=/')
			self.response.headers.add_header('Set-Cookie', 'username='+make_pw_hash(username, password).encode('ascii','replace')+'; Path=/')
			#u = Users(username = username, pw_hash = make_pw_hash(username, password))
			#u.put()
			self.redirect('/welcome')

def valid_user(username,password,confirm,email):
	if not valid_username(username):
		return False
	if not valid_password(password,confirm):
		return False
	if not valid_email(email):
		return False
	return True

def valid_username(username):
	return USER_RE.match(username)

def valid_password(password, confirm):
	if (PASSWORD_RE.match(password)):
		return True
	else:
		return False

def valid_email(email):
	if len(email) == 0:
		return True
	return EMAIL_RE.match(email)

class Welcome(webapp2.RequestHandler):
	def get(self):
		username = self.request.cookies.get('user')
		if valid_username(username):
			render(self, 'welcome.html', username = username)
		else:
			self.redirect('/signup')

def valid_login(self, username, password):
	#query = "SELECT * FROM User WHERE username = \'" + username + "\'"
	#users = db.GqlQuery(query)
	if username == None or password == None:
		return False
	else:
		user_pw_hash = self.request.cookies.get('username')
		logging.info("user_pw_hash: %s", user_pw_hash)
		return valid_pw(username, password, user_pw_hash)

class LoginHandler(webapp2.RequestHandler):
	def get(self):
		render(self, "login-form.html")
	def post(self):
		have_error = False
		username = self.request.get("username")
		password = self.request.get("password")
		params = dict(username = username)
		if not valid_login(self, username, password):
			params['error_username'] = "Invalid login."
			have_error = True

		if have_error:
			render(self, 'login-form.html', **params)
		else:
			self.response.headers.add_header('Set-Cookie', 'user='+username.encode('ascii','replace')+'; Path=/')
			self.redirect('/welcome')

class Logout(webapp2.RequestHandler):
	def get(self):
		self.response.delete_cookie('username')
		self.response.delete_cookie('user')
		self.redirect('/signup')

app = webapp2.WSGIApplication([
	('/signup', MainHandler),
	('/login', LoginHandler),
	('/welcome', Welcome),
	('/logout', Logout)
], debug=True)