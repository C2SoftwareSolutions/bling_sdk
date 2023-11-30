import os
import sys
import uuid
import signal
import base64
import logging
import requests
import environs

class Bling:
    API_URL = 'https://bling.com.br/Api/v3/'
    REFRESH_TOKEN_FILE = 'refresh_token.txt'

    def __init__(self, client_id, client_secret, redirect_uri, loglevel=logging.INFO, refresh_token=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.access_token = None
        self.refresh_token = refresh_token
  
        self.setup_logger(loglevel)
        self.logger.debug("Bling API client initialized")

    def setup_logger(self, loglevel):
        self.logger = logging.getLogger('Bling')
        self.logger.setLevel(loglevel)
        formatter = logging.Formatter('Bling.%(funcName)s - %(levelname)s - %(message)s')
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    def api_request(self, path, params={}, method='GET', headers={}, authorized=True):
        self.logger.debug("Calling {} with params: {}".format(path, params))

        if authorized and not headers and self.access_token:
            headers = {'Authorization': 'Bearer ' + self.access_token}
        elif not headers:
            self.logger.warning("Attempting to make authorized request without access token")

        if method == 'GET':
            try:
                req = requests.get(self.API_URL + path, params=params, headers=headers)
                if req:
                    return req.json()
                else:
                    self.logger.error(f'{req.status_code} - {req.text}')
                    return None
            except Exception as e:
                self.logger.error(str(e))
                return None
        elif method == 'POST':
            try:
                req = requests.post(self.API_URL + path, data=params, headers=headers)

                if req:
                    return req.json()
                else:
                    self.logger.error(f'{req.status_code} - {req.text}')
                    return None
            except Exception as e:
                self.logger.error(str(e))
                return None
        elif method == 'DELETE':
            try:
                req = requests.post(self.API_URL + path, data=params, headers=headers)

                if req:
                    return req.json()
                else:
                    self.logger.error(f'{req.status_code} - {req.text}')
                    return None
            except Exception as e:
                self.logger.error(str(e))
                return None
        else:
            raise ValueError("Invalid method: " + method)

    def gen_basic_auth_header(self):
        b64_credentials = base64.b64encode(f'{self.client_id}:{self.client_secret}'.encode('utf-8')).decode('utf-8')
        return {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': '1.0',
            'Authorization': 'Basic ' + b64_credentials
        }

    def get_auth_url(self):
        state = uuid.uuid4().hex
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'state': state
        }

        return self.API_URL + 'oauth/authorize?' + '&'.join([f'{k}={v}' for k, v in params.items()])

    def _update_tokens(self, _dict):
        if _dict and isinstance(_dict, dict) and 'access_token' in _dict \
                and 'refresh_token' in _dict:
            self.access_token = _dict['access_token']
            self.refresh_token = _dict['refresh_token']
            return True
        return False

    def get_access_token_from_code(self, code):
        params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': self.redirect_uri,
            'grant_type': 'authorization_code',
            'code': code
        }
        
        return self._update_tokens(self.api_request('oauth/token', params=params, headers=self.gen_basic_auth_header(), method='POST'))

    def get_access_token(self):
        params = {'grant_type': 'refresh_token', 'refresh_token': self.refresh_token}
        
        return self._update_tokens(self.api_request('oauth/token', params=params, headers=self.gen_basic_auth_header(), method='POST'))

    def get_all_products(self):
        return self.api_request('produtos')

    def get_product(self, product_id):
        return self.api_request('produtos/' + str(product_id))
    
    def delete_products(self, product_ids):
        params = {"idsProdutos": product_ids}
        # TODO: Check if this works; could be expecting comma separated string
        return self.api_request('produtos/', params=params, method='DELETE')

    def delete_product(self, product_id):
        return self.api_request('produtos/' + str(product_id), method='DELETE')

    def create_product(self, product):
        return self.api_request('produtos/', params=product, method='POST')

    def read_refresh_token_from_file(self):
        if os.path.isfile(self.REFRESH_TOKEN_FILE):
            with open('refresh_token.txt', 'r') as f:
                self.refresh_token = f.read().strip().lstrip()
                return True

    def write_refresh_token_to_file(self):
        with open(self.REFRESH_TOKEN_FILE, 'w') as f:
            if self.refresh_token:
                self.logger.debug("Writing tokens to file")
                f.write(self.refresh_token)
        return True

    def cleanup(self):
        self.write_refresh_token_to_file()

# Handle CTRL + C ( cleanup on exit )
def signal_handler(sig, frame):
    bling.cleanup()
    sys.exit(0)

# Testing
if __name__ == "__main__":
    env = environs.Env()
    env.read_env()
    try:
        bling = Bling(
            env('BLING_CLIENT_ID'),
            env('BLING_CLIENT_SECRET'),
            env('BLING_REDIRECT_URI'),
        )
    except environs.EnvError as e:
        print("Missing environment variables: " + str(e))
        exit(1)

    signal.signal(signal.SIGINT, signal_handler)

    if len(sys.argv) > 1:
        bling.refresh_token = sys.argv[1]
        print("Using refresh token from command line argument: " + bling.refresh_token)
    elif bling.read_refresh_token_from_file():
        refresh_token = bling.refresh_token
        print("Using refresh token from file: " + str(refresh_token))
    else:
        print("No refresh token provided, will attempt to get one from authorization code")

    if bling.refresh_token is None:
        print("Go to the following URL to authorize the app:")
        print(bling.get_auth_url())

        auth_code = input("\nEnter the code from the redirect URL: ")

        print("\nGetting access token from code...")
        token = bling.get_access_token_from_code(auth_code)
        if token:
            print(f"Access token: {bling.access_token}, Refresh token: {bling.refresh_token}")
        else:
            print("Error getting new tokens")
    else:
        print("Getting new access token from refresh token")
        token = bling.get_access_token()

    print(bling.get_all_products())
    bling.cleanup()
