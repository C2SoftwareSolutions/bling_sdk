import uuid
import base64
import logging
import requests
import environs

class Bling:
    API_URL = 'https://bling.com.br/Api/v3/'

    def __init__(self, client_id, client_secret, redirect_uri, loglevel=logging.INFO):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.access_token = None
        self.refresh_token = None
  
        self.setup_logger(loglevel)
        self.logger.debug("Bling API client initialized")

    def setup_logger(self, loglevel):
        self.logger = logging.getLogger('Bling')
        self.logger.setLevel(loglevel)
        formatter = logging.Formatter('Bling.%(funcName)s - %(levelname)s - %(message)s')
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    def api_request(self, path, params, method='GET'):
        if method == 'GET':
            req = requests.get(self.API_URL + path, params=params)
            # TODO: Handle exceptions and return json?
            return req
        elif method == 'POST':
            # TODO: check if all POST endpoints actually need authorization
            # otherwise setup a separate method or specific argument to send
            # authorized POST requests
            b64_credentials = base64.b64encode(f'{self.client_id}:{self.client_secret}'.encode('utf-8')).decode('utf-8')
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': '1.0',
                'Authorization': 'Basic ' + b64_credentials
            }
           
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

        return self._update_tokens(self.api_request('oauth/token', params=params, method='POST'))

    def get_access_token(self, refresh_token):
        params = {'grant_type': 'refresh_token', 'refresh_token': refresh_token}
        
        return self._update_tokens(self.api_request('oauth/token', params=params, method='POST'))

# Testing
if __name__ == "__main__":
    env = environs.Env()
    env.read_env()
    try:
        bling = Bling(
            env('BLING_CLIENT_ID'),
            env('BLING_CLIENT_SECRET'),
            env('BLING_REDIRECT_URI')
        )
    except environs.EnvError as e:
        print("Missing environment variables: " + str(e))
        exit(1)

    print("Go to the following URL to authorize the app:")
    print(bling.get_auth_url())

    auth_code = input("\nEnter the code from the redirect URL: ")

    print("\nGetting access token from code...")
    token = bling.get_access_token_from_code(auth_code)
    if token:
        print(f"Access token: {bling.access_token}, Refresh token: {bling.refresh_token}")
    else:
        print("Error getting new tokens")

    print("\nGetting access token from refresh token...")
    token = bling.get_access_token(bling.refresh_token)

    if token:
        print(f"Access token: {bling.access_token}, Refresh token: {bling.refresh_token}")
    else:
        print("Error getting new tokens")
