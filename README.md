# Rock 'N' Roll 

## Overview
The Rock 'N' Roll Python script is a tool designed to perform various cybersecurity-related searches. It leverages external APIs to query databases and retrieve information related to email addresses, compromised credentials, and leaked passwords. The script incorporates searches from HudsonRock (Cavalier API), COMB (Combination Of Many Breaches), and IntelX (Phonebook.cz).

## Features
1. **HudsonRock Search:**
   - Queries the HudsonRock database for information related to a given email address.
   - Extracts details such as stealer family, date uploaded, date compromised, computer name, operating system, and antiviruses.
   - Optionally saves the results to an Excel file.

2. **COMB Search:**
   - Performs a leaked password search using the COMB database (Combination Of Many Breaches).
   - Extracts usernames and passwords associated with the provided email addresses.
   - Optionally saves the results to an Excel file.

3. **IntelX Domain Search:**
   - Utilizes the IntelX API to search for emails, subdomains, or links related to a specified domain.
   - Requires a valid IntelX API key.
   - Optionally saves the extracted information to a file.

## What is Cavalier API? 

Hudson Rock provides its clients the ability to query a database of over 20,774,497 computers which were compromised through global info-stealer campaigns performed by threat actors. The database is updated with new compromised computers every day, offering cybersecurity providers the ability to alert security teams ahead of imminent attacks, when users get compromised and have their credentials stolen.

## What is Phonebook.cz? 

Phonebook lists all domains, email addresses, or URLs for the given input domain. You can search 121 billion records. In some instances the path or query part may contain clear-text password.

## Prerequisites
- Python 3.6 or later
- Required Python packages (install using `pip install -r requirements.txt`):
  - `argparse`
  - `requests`
  - `json`
  - `time`
  - `datetime`
  - `tqdm`
  - `pandas`
  - `colorama`

## Usage

### Command Line Arguments
- `-f, --file-path`: Path to the text file containing email addresses for HudsonRock and COMB Search.
- `--houtput`: Path to the HudsonRock Search results output Excel file (default: HudsonRock-results.xlsx).
- `--coutput`: Path to the COMB Search results output Excel file (default: COMB-results.xlsx).
- `--verbose`: Display detailed results in the terminal.
- `-e, --email`: Search all emails for the provided domain.
- `-k, --apikey`: IntelX API key.
- `-d, --domain`: Search all subdomains for the provided domain.
- `-l, --links`: Search all links for the provided domain (may include cleartext passwords from stealer logs).
- `--ioutput`: Stores all items in a file *_cz.txt for IntelX domain search.


### Running the Script
1. Open a terminal.
2. Navigate to the directory containing the script.
3. Run the script using the command:
   ```
   python rockNroll.py [arguments]
   ```

### Examples
- Run HudsonRock search:
  ```
  python rockNroll.py -f emails.txt --houtput HudsonRock-results.xlsx --verbose
  ```

- Run IntelX domain search:
  ```
  python rockNroll.py -l example.com -k your_intelx_api_key --ioutput
  ```

- Run COMB search:
  ```
  python rockNroll.py -f emails.txt --coutput COMB-results.xlsx
  ```
### Screenshots

![Screenshot 2024-06-19 at 21 32 57_censored](https://github.com/yasinyilmaz/rockNroll/assets/37842751/330f731d-9115-4ca5-b293-938d6e5e2387)

![Screenshot 2024-06-19 at 21 33 15_censored](https://github.com/yasinyilmaz/rockNroll/assets/37842751/cc23d3e5-1103-4e61-8d13-856073742679)

![Screenshot 2024-06-19 at 21 39 33_censored(1)](https://github.com/yasinyilmaz/rockNroll/assets/37842751/6121c54d-8a81-4ae8-b6b0-5931c4d75cfe)



## Notes
- Throttling is implemented to avoid exceeding API rate limits (e.g., one request every 10 seconds).
- The IntelX domain search requires a valid API key.

Feel free to customize and extend the script based on your specific use case or integrate additional functionalities.
