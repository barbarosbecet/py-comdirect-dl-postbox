## comdirect-dl-postbox

This is a simple python script to download your entire comdirect bank Postbox through comdirect API.
Details of comdirect API documentation can be found [here](https://developer.comdirect.de/).

Use at your own risk! I can't be held responsible of any damage, theft or charges to your account. 

Be warned, that there are potential cases that your account might incur charges from comdirect bank.
Some examples are:
- mobileTAN, per sent SMS
- Online banking access getting blocked, after requesting too many or entering too many TANs
- could be more as comdirect AGB (Terms) change

All these potential charges are the responsibility of the user, account owner or user of this piece of software.

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
  - Pay attention to TAN process (and input TAN when asked)