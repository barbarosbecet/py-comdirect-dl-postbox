from datetime import datetime, timedelta
import uuid
import requests
import json
import base64
import os
import re

# where to get credentials from
credentials_file = os.path.join(os.getcwd(), 'actual_credentials.json')
creds = None

with open(credentials_file) as jf:
    creds = json.load(jf)

# client id and secret from "Entwicklerzugang"
client_id = creds['client_id']
client_secret = creds['client_secret']
# regular internet banking credentials
zugangsnummer = creds['zugangsnummer']
pin = creds['pin']

api_url = 'https://api.comdirect.de/api'
base_url = 'https://api.comdirect.de'

def get_request_id() -> str:
    now_ms = str(int(datetime.now().timestamp() * 1000.))
    return now_ms[-9:]

def pretty_print_dict(dict) -> None:
    print(json.dumps(dict, indent=2, default=str))

def process_response(response, step) -> None:
    if response.status_code in [200, 201]:
        print(f'{step}: SUCCESS')
        pretty_print_dict(response.json())
    else:
        print(response.text)
        response.raise_for_status()

session_id = str(uuid.uuid4()).replace('-', '')

### Step 2.1 Oauth2 token initial generation

step = '2.1 Oauth2 token initial generation'
request_id = get_request_id()

payload = f'client_id={client_id}&client_secret={client_secret}&grant_type=password&username={zugangsnummer}&password={pin}'

headers = {
    'x-http-request-info': f'{{"clientRequestId":{{"sessionId":"{session_id}","requestId":"{request_id}"}}}}',
    'Accept': 'application/json',
    'Content-Type': 'application/x-www-form-urlencoded',
}

print(f'Sending request: {step}')

response = requests.request(
    'POST', base_url+'/oauth/token', headers=headers, data=payload)

process_response(response, step)

response_json = response.json()

assert('access_token' in response_json.keys()), 'access_token missing'
assert('refresh_token' in response_json.keys()), 'refresh_token missing'

access_token = response_json['access_token']
refresh_token = response_json['refresh_token']

### Step 2.2 Probe Session Status

step = '2.2 Probe Session Status'
request_id = get_request_id()

headers = {
    'x-http-request-info': f'{{"clientRequestId":{{"sessionId":"{session_id}","requestId":"{request_id}"}}}}',
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {access_token}',
}

print(f'Sending request: {step}')

response = requests.request(
    'GET',
    api_url+'/session/clients/user/v1/sessions',
    headers=headers)

process_response(response, step)

response_json = response.json()

assert('identifier' in response_json[0].keys()), 'identifier missing'

sessionUUID = response_json[0]['identifier']

### Step 2.3 Initial validate Session-TAN status

step = 'Step 2.3 Initial validate Session-TAN status'
request_id = get_request_id()

payload = json.dumps({
    'identifier': sessionUUID,
    'sessionTanActive': True,
    'activated2FA': True,
})

headers = {
    'x-http-request-info': f'{{"clientRequestId":{{"sessionId":"{session_id}","requestId":"{request_id}"}}}}',
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {access_token}',
}

print(f'Sending request: {step}')

response = requests.request(
    'POST',
    api_url+f'/session/clients/user/v1/sessions/{sessionUUID}/validate',
    headers=headers,
    data=payload)

process_response(response, step)

response_json = response.json()
response_headers = response.headers

assert(response_json['sessionTanActive'] == True), 'sessionTanActive not true'
assert('x-once-authentication-info' in response_headers.keys()), 'x-once-authentication-info header missing'

tan_info = json.loads(response_headers['x-once-authentication-info'])

pretty_print_dict(tan_info)

assert(all(item in tan_info.keys() for item in ['id', 'typ'])), 'TAN info missing id and typ'

challenge_id = tan_info['id']
challenge_type = tan_info['typ']

supported_tan = ['P_TAN_PUSH', 'P_TAN', 'P_TAN_APP']

assert(challenge_type in supported_tan), f'Unsupported TAN type. Supported: {supported_tan}'

print(f'Using 2FA type: {challenge_type}')

if challenge_type in ['P_TAN', 'P_TAN_APP']:
    # Need to show photoTAN challenge QR code here
    assert('challenge' in tan_info.keys()), 'Challenge missing'
    filename = f'phototan_{request_id}.png'
    print(f'Saving photoTAN challenge QR code in {filename}')
    png_bytes = base64.b64decode(tan_info['challenge'])
    with open(filename, 'wb') as f:
        f.write(png_bytes)
    os.startfile(filename)

print('Use your photoTAN app to solve the photoTAN challenge!')
input('Press Enter to continue once photoTAN is solved...')

### Step 2.4 Activate session-TAN

step = 'Step 2.4 Activate session-TAN'
request_id = get_request_id()

payload = json.dumps({
    'identifier': sessionUUID,
    'sessionTanActive': True,
    'activated2FA': True,
})

headers = {
    'x-http-request-info': f'{{"clientRequestId":{{"sessionId":"{session_id}","requestId":"{request_id}"}}}}',
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {access_token}',
    'x-once-authentication-info': f'{{"id":"{challenge_id}"}}',
    'x-once-authentication': '', # filled for mTAN by the user
}

print(f'Sending request: {step}')

response = requests.request(
    'PATCH',
    api_url+f'/session/clients/user/v1/sessions/{sessionUUID}',
    headers=headers,
    data=payload)

process_response(response, step)

response_json = response.json()

assert(response_json['sessionTanActive'] == True), 'sessionTanActive not true'
assert('identifier' in response_json.keys()), 'identifier missing'

sessionUUID = response_json['identifier']

### Step 2.5 Oauth2 CD Secondary-Flow

step = '2.5 Oauth2 CD Secondary-Flow'
request_id = get_request_id()

payload = f'client_id={client_id}&client_secret={client_secret}&grant_type=cd_secondary&token={access_token}'

headers = {
    'x-http-request-info': f'{{"clientRequestId":{{"sessionId":"{session_id}","requestId":"{request_id}"}}}}',
    'Accept': 'application/json',
    'Content-Type': 'application/x-www-form-urlencoded',
}

print(f'Sending request: {step}')

response = requests.request(
    'POST', base_url+'/oauth/token', headers=headers, data=payload)

process_response(response, step)

response_json = response.json()

assert('access_token' in response_json.keys()), 'access_token missing'
assert('refresh_token' in response_json.keys()), 'refresh_token missing'
assert('expires_in' in response_json.keys()), 'expiry missing'

access_token = response_json['access_token']
refresh_token = response_json['refresh_token']
expires_in = int(response_json['expires_in'])
expiry_time = datetime.now() + timedelta(seconds=expires_in)

print('Authentication to comdirect API successful!')
print(f'access_token: {access_token}')
print(f'refresh_token: {refresh_token}')
print(f'expires at: {expiry_time}')

### Step 9.1.1 Get PostBox Documents

step = '9.1.1 Get PostBox Documents'

print(f'Sending requests: {step}')

documents = []

while True:
    request_id = get_request_id()

    headers = {
        'x-http-request-info': f'{{"clientRequestId":{{"sessionId":"{session_id}","requestId":"{request_id}"}}}}',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}',
    }
    index = len(documents)
    paging_count = 50

    response = requests.request(
        'GET',
        api_url+f'/messages/clients/user/v2/documents?paging-first={index}&paging-count={paging_count}',
        headers=headers)

    process_response(response, step)

    response_json = response.json()

    if len(response_json['values']) == 0:
        break

    documents.extend(response_json['values'])

### Step 9.1.2 Download each PostBox Document

step = '9.1.2 Download each PostBox Document'

print(f'Sending requests: {step}')

directory_to_save = os.path.join(os.getcwd(), 'documents')

if not os.path.exists(directory_to_save):
    os.mkdir(directory_to_save)

file_extension_map = {
    'application/pdf' : '.pdf',
    'text/html' : '.html',
}

for item in documents:
    document_id = item['documentId']
    document_name = item['name']
    date_creation = item['dateCreation']

    print(f'Downloading file "{document_name}" with id {document_id}, created {date_creation}')

    request_id = get_request_id()

    headers = {
        'x-http-request-info': f'{{"clientRequestId":{{"sessionId":"{session_id}","requestId":"{request_id}"}}}}',
        'Accept': 'application/pdf',
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}',
    }

    response = requests.request(
        'GET',
        api_url+f'/messages/v2/documents/{document_id}',
        headers=headers)

    if response.status_code != 200:
        print(response.text)
        continue
    
    file_ext = file_extension_map.get(item['mimeType'], '.txt')
    valid_name = re.sub(r'[^\w\-_\. ]', '_', document_name)
    full_path = os.path.join(directory_to_save, f'{date_creation}_{valid_name}'+file_ext)
    with open(full_path, 'wb') as f:
        f.write(response.content)

print('Done!')
