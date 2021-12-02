## comdirect-dl-postbox

This is a simple python script to download your entire comdirect bank Postbox through comdirect API. Details of comdirect API documentation is on [here](https://developer.comdirect.de/).

## Usage

- Add actual_credentials.json file with following values:
```json
{
    "client_id" : "client_id_from_entwicklerzugang",
    "client_secret" : "client_secret_from_entwicklerzugang",
    "zugangsnummer" : "internet_banking_zugangsnummer",
    "pin" : "internet_banking_pin"
}
```

- Run the script: `python comdirect-dl-postbox.py` 