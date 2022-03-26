# -*- coding:utf-8 -*-
import os
import flask
import requests
import ssl
from flask import request

import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build

CLIENT_SECRETS_FILE = "client_secrets.json"

SCOPES = ['https://www.googleapis.com/auth/youtube.readonly']
API_SERVICE_NAME = 'youtube'
API_VERSION = 'v3'

app = flask.Flask(__name__)

app.secret_key = '' #랜덤 값으로 

@app.route('/')
def authorize():
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES)
  flow.redirect_uri = flask.url_for('callback', _external=True)

  authorization_url, state = flow.authorization_url(
      access_type='offline',
      include_granted_scopes='true')

  flask.session['state'] = state

  return flask.redirect(authorization_url)


@app.route('/callback')
def callback():
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('callback', _external=True)

  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)
  credentials = flow.credentials
  youtube = build("youtube", "v3", credentials=credentials)
  response = youtube.subscriptions().list(part='snippet', mine=True, forChannelId='UCd92NIlxsFxKu3Zm2H3FNxg').execute() #자신의 채널 id를 넣으세요
  for hacc in response.get("items", []):
    if hacc["snippet"]["resourceId"]["kind"] == "youtube#channel":
        return flask.redirect('') #버그판 링크
  return "eesdf 유튜브 구독 안됨" #구독 안 했을때

@app.before_request
def before_request():
    if request.url.startswith('http://'):
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return redirect(url, code=code)


if __name__ == '__main__':
  ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
  ssl_context.load_cert_chain(certfile='server.crt', keyfile='server.key') #자신의 키로~
  app.run('0.0.0.0', port=443, ssl_context=ssl_context)
