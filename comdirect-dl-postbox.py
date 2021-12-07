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

# preferred TAN selection: 
# ''           -> Use your default
# 'P_TAN_PUSH' -> Use photoTAN-Push, approve notification, no input required
# 'P_TAN'      -> Use photoTAN, get QR code on computer, scan with camera, input TAN
# 'M_TAN'      -> Use mTAN (might get charged!), receive SMS, input TAN
preferred_tan = creds.get('tan_verfahren', '')

base_url = 'https://api.comdirect.de'
api_url = f'{base_url}/api'

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

payload = {
    'client_id' : f'{client_id}',
    'client_secret' : f'{client_secret}',
    'grant_type' : 'password',
    'username' : f'{zugangsnummer}',
    'password' : f'{pin}'
}

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

assert(all(item in tan_info.keys() for item in ['id', 'typ', 'availableTypes'])), 'TAN info missing data'

challenge_id = tan_info['id']
challenge_type = tan_info['typ']
challenge = tan_info.get('challenge', '')

# switch TAN method if necessary
if preferred_tan and preferred_tan != tan_info['typ'] and preferred_tan in tan_info['availableTypes']:
    step = 'Step 2.3 repeat: Switch TAN method'
    request_id = get_request_id()
    headers['x-http-request-info'] = f'{{"clientRequestId":{{"sessionId":"{session_id}","requestId":"{request_id}"}}}}'
    headers['x-once-authentication-info'] = f'{{"typ":"{preferred_tan}"}}'

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
    assert(all(item in tan_info.keys() for item in ['id', 'typ', 'availableTypes'])), 'TAN info missing data'
    challenge_id = tan_info['id']
    challenge_type = tan_info['typ']
    challenge = tan_info.get('challenge', '')

supported_tan = ['P_TAN_PUSH', 'P_TAN', 'M_TAN']

assert(challenge_type in supported_tan), f'Unsupported TAN type. Supported: {supported_tan}'

print(f'Using 2FA type: {challenge_type}')

tan = ''

if challenge_type == 'P_TAN':
    # Need to show photoTAN challenge QR code here
    assert(challenge), 'Challenge missing'
    filename = f'phototan_{request_id}.png'
    print(f'Saving photoTAN challenge QR code in {filename}')
    png_bytes = base64.b64decode(challenge)
    with open(filename, 'wb') as f:
        f.write(png_bytes)
    os.startfile(filename)
    print('Use your photoTAN app to solve the photoTAN challenge and ...')
    tan = input('Please enter TAN: ')
elif challenge_type == 'M_TAN':
    # Need to get the SMS TAN input here
    assert(challenge), 'Challenge missing'
    print(f'Check for SMSes on phone number "{challenge}"" and ...')
    tan = input('Please enter TAN: ')
elif challenge_type == 'P_TAN_PUSH':
    print('Use your photoTAN app to solve the photoTAN challenge')
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
    'x-once-authentication': tan,
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

    file_ext = file_extension_map.get(item['mimeType'], '.txt')
    valid_name = re.sub(r'[^\w\-_\. ]', '_', document_name)
    full_path = os.path.join(directory_to_save, f'{date_creation}_{valid_name}'+file_ext)

    if os.path.exists(full_path):
        print(f'Skipping existing file "{document_name}" with id {document_id}, created {date_creation}')
        continue

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

    with open(full_path, 'wb') as f:
        f.write(response.content)

print('Done!')
