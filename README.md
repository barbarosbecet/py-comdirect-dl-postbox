## comdirect-dl-postbox

This is a simple python script to download your entire comdirect bank Postbox through comdirect API.
Details of comdirect API documentation is on [here](https://developer.comdirect.de/).

Use at your own risk! I can't be held responsible from any charges to your account. 
Be warned, that there are potential cases that your account might get charged:
- mTAN 2FA per sent SMS
- Online Banking access being blocked
- maybe more...

## Usage

- Add actual_credentials.json file with following values:
```json
{
    "client_id" : "client_id_from_entwicklerzugang",
    "client_secret" : "client_secret_from_entwicklerzugang",
    "zugangsnummer" : "internet_banking_zugangsnummer",
    "pin" : "internet_banking_pin",
    "tan_verfahren" : "optional - empty, P_TAN_PUSH, P_TAN, M_TAN"
}
```

- Run the script: `python comdirect-dl-postbox.py`
    -- Pay attention to TAN process (and input TAN when necessary)