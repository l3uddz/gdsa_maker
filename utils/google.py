import json
import os
from threading import Lock
from time import time

from loguru import logger
from requests_oauthlib import OAuth2Session


class Google:
    auth_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    token_url = 'https://www.googleapis.com/oauth2/v4/token'
    api_url = 'https://iam.googleapis.com/v1/'
    redirect_url = 'urn:ietf:wg:oauth:2.0:oob'
    scopes = ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/drive']

    def __init__(self, client_id, client_secret, project_name, token_path):
        self.client_id = client_id
        self.client_secret = client_secret
        self.project_name = project_name
        self.token_path = token_path
        self.token = self._load_token()
        self.token_refresh_lock = Lock()
        self.http = self._new_http_object()

    ############################################################
    # CORE CLASS METHODS
    ############################################################

    def get_auth_link(self):
        auth_url, state = self.http.authorization_url(self.auth_url, access_type='offline', prompt='select_account')
        return auth_url

    def exchange_code(self, code):
        token = self.http.fetch_token(self.token_url, code=code, client_secret=self.client_secret)
        if 'access_token' in token:
            self._token_saver(token)
        return self.token

    def query(self, path, method='GET', page_type='changes', fetch_all_pages=False, **kwargs):
        resp_json = {}
        pages = 1
        resp = None
        request_url = self.api_url + path.lstrip('/') if not path.startswith('http') else path

        try:
            while True:
                resp = self._do_query(request_url, method, **kwargs)
                logger.debug(f"Request URL: {resp.url}")
                logger.debug(f"Request ARG: {kwargs}")
                logger.debug(f'Response Status: {resp.status_code} {resp.reason}')

                if 'Content-Type' in resp.headers and 'json' in resp.headers['Content-Type']:
                    if fetch_all_pages:
                        resp_json.pop('nextPageToken', None)
                    new_json = resp.json()
                    # does this page have changes
                    extended_pages = False
                    page_data = []
                    if page_type in new_json:
                        if page_type in resp_json:
                            page_data.extend(resp_json[page_type])
                        page_data.extend(new_json[page_type])
                        extended_pages = True

                    resp_json.update(new_json)
                    if extended_pages:
                        resp_json[page_type] = page_data
                else:
                    return False if resp.status_code != 200 else True, resp, resp.text

                # handle nextPageToken
                if fetch_all_pages and 'nextPageToken' in resp_json and resp_json['nextPageToken']:
                    # there are more pages
                    pages += 1
                    logger.info(f"Fetching extra results from page {pages}")
                    if 'params' in kwargs:
                        kwargs['params'].update({'pageToken': resp_json['nextPageToken']})
                    elif 'json' in kwargs:
                        kwargs['json'].update({'pageToken': resp_json['nextPageToken']})
                    elif 'data' in kwargs:
                        kwargs['data'].update({'pageToken': resp_json['nextPageToken']})
                    continue

                break

            return True if resp_json and len(resp_json) else False, resp, resp_json if (
                    resp_json and len(resp_json)) else resp.text

        except Exception:
            logger.exception(f"Exception sending request to {request_url} with kwargs={kwargs}: ")
            return False, resp, None

    ############################################################
    # GOOGLE METHODS
    ############################################################

    def get_service_accounts(self):
        success, resp, resp_data = self.query(f'projects/{self.project_name}/serviceAccounts', fetch_all_pages=True,
                                              page_type='accounts', params={'pageSize': 100})
        return success, resp_data

    def get_service_account_keys(self, service_account):
        success, resp, resp_data = self.query(f'projects/{self.project_name}/serviceAccounts/{service_account}/keys',
                                              fetch_all_pages=True, page_type='keys', params={'pageSie': 100})
        return success, resp_data

    def create_service_account(self, name):
        success, resp, resp_data = self.query(f'projects/{self.project_name}/serviceAccounts', 'POST', json={
            'accountId': f'{name}'
        })
        return success, resp_data

    def create_service_account_key(self, name):
        success, resp, resp_data = self.query(f'projects/{self.project_name}/serviceAccounts/{name}/keys', 'POST',
                                              json={
                                                  'privateKeyType': 'TYPE_GOOGLE_CREDENTIALS_FILE',
                                                  'keyAlgorithm': 'KEY_ALG_RSA_2048'
                                              })
        return success, resp_data

    def get_teamdrives(self):
        success, resp, resp_data = self.query('https://www.googleapis.com/drive/v3/teamdrives',
                                              params={'pageSize': 100}, fetch_all_pages=True, page_type='teamDrives')
        return success, resp_data

    def create_teamdrive(self, name):
        success, resp, resp_data = self.query(f'https://www.googleapis.com/drive/v3/teamdrives', 'POST',
                                              params={'requestId': name}, json={'name': name})
        return success, resp_data

    def get_teamdrive_permissions(self, teamdrive_id):
        success, resp, resp_data = self.query(f'https://www.googleapis.com/drive/v3/files/{teamdrive_id}/permissions',
                                              params={'pageSize': 100,
                                                      'fields': 'permissions(deleted,domain,emailAddress,id,type)',
                                                      'supportsTeamDrives': True},
                                              fetch_all_pages=True, page_type='permissions')
        return success, resp_data

    def set_teamdrive_share_user(self, teamdrive_id, user):
        success, resp, resp_data = self.query(f'https://www.googleapis.com/drive/v3/files/{teamdrive_id}/permissions',
                                              'POST', params={'supportsTeamDrives': True},
                                              json={'role': 'fileOrganizer',
                                                    'type': 'user',
                                                    'emailAddress': user
                                                    })
        return success, resp_data

    def delete_teamdrive_share_user(self, teamdrive_id, permission_id):
        success, resp, resp_data = self.query(
            f'https://www.googleapis.com/drive/v3/files/{teamdrive_id}/permissions/{permission_id}',
            'DELETE', params={'supportsTeamDrives': True})
        return True if resp.status_code == 204 else False, resp_data

    ############################################################
    # INTERNALS
    ############################################################

    def _do_query(self, request_url, method, **kwargs):
        tries = 0
        max_tries = 2
        lock_acquirer = False
        resp = None
        use_timeout = 30

        # override default timeout
        if 'timeout' in kwargs and isinstance(kwargs['timeout'], int):
            use_timeout = kwargs['timeout']
            kwargs.pop('timeout', None)

        # do query
        while tries < max_tries:
            if self.token_refresh_lock.locked() and not lock_acquirer:
                logger.debug("Token refresh lock is currently acquired... trying again in 500ms")
                time.sleep(0.5)
                continue

            if method == 'POST':
                resp = self.http.post(request_url, timeout=use_timeout, **kwargs)
            elif method == 'PATCH':
                resp = self.http.patch(request_url, timeout=use_timeout, **kwargs)
            elif method == 'DELETE':
                resp = self.http.delete(request_url, timeout=use_timeout, **kwargs)
            else:
                resp = self.http.get(request_url, timeout=use_timeout, **kwargs)
            tries += 1

            if resp.status_code == 401 and tries < max_tries:
                # unauthorized error, lets refresh token and retry
                self.token_refresh_lock.acquire(False)
                lock_acquirer = True
                logger.warning(f"Unauthorized Response (Attempts {tries}/{max_tries})")
                self.token['expires_at'] = time() - 10
                self.http = self._new_http_object()
            else:
                break

        return resp

    def _load_token(self):
        try:
            if not os.path.exists(self.token_path):
                return {}

            with open(self.token_path, 'r') as fp:
                return json.load(fp)
        except Exception:
            logger.exception(f"Exception loading token from {self.token_path}: ")
        return {}

    def _dump_token(self):
        try:
            with open(self.token_path, 'w') as fp:
                json.dump(self.token, fp, indent=2)
            return True
        except Exception:
            logger.exception(f"Exception dumping token to {self.token_path}: ")
        return False

    def _token_saver(self, token):
        # update internal token dict
        self.token.update(token)
        try:
            if self.token_refresh_lock.locked():
                self.token_refresh_lock.release()
        except Exception:
            logger.exception("Exception releasing token_refresh_lock: ")
        self._dump_token()
        logger.info("Renewed access token!")
        return

    def _new_http_object(self):
        return OAuth2Session(client_id=self.client_id, redirect_uri=self.redirect_url, scope=self.scopes,
                             auto_refresh_url=self.token_url, auto_refresh_kwargs={'client_id': self.client_id,
                                                                                   'client_secret': self.client_secret},
                             token_updater=self._token_saver, token=self.token)
