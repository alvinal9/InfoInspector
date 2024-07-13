# Infoinspector
InfoInspector🔍 is a comprehensive tool designed to gather a wide array of information about a specified domain 🌐. This tool is invaluable for cybersecurity professionals 🛡️, network administrators 📡, and researchers 💻 who need to collect and analyze domain-related data efficiently.
## **Features**
### InfoInspector provides the following functionalities:
1. **Network Information**: 
   - **IP Address**: The numerical label assigned to the domain, used to identify and locate the domain on the internet.
   - **DNS Records**:
     - **A (Address)**: Maps a domain to an IPv4 address.
     - **AAAA (IPv6 Address)**: Maps a domain to an IPv6 address.
     - **MX (Mail Exchange)**: Specifies the mail servers responsible for receiving email on behalf of the domain.
     - **NS (Name Server)**: Indicates the authoritative name servers for the domain.
     - **SOA (Start of Authority)**: Contains administrative information about the domain, including the primary name server, email of the domain administrator, domain serial number, and timers for refreshing the zone.
     - **TXT (Text)**: Used to store arbitrary text data, often for verification purposes such as domain ownership or email authentication.
     - **SPF (Sender Policy Framework)**: A type of TXT record that helps prevent email spoofing by specifying which mail servers are allowed to send email on behalf of the domain.

2. **Domain Registration Information**: 
   - **WHOIS Data**: Includes details about the domain's registration, such as:
     - Registrant's name
     - Organization
     - Email
     - Phone number
     - Registration date
     - Expiration date

3. **SSL/TLS Certificate Information**: 
   - Details about the domain's SSL/TLS certificate, including:
     - Issuer (the certificate authority)
     - Subject (the entity the certificate is issued to)
     - Expiration date
     - Serial number

4. **Email Addresses**: 
   - Extracts email addresses from the domain's webpage by searching for `mailto` links.

5. **Geolocation Information**: 
   - Determines the geographical location of the domain's IP address, including:
     - Country
     - Region
     - City
     - Latitude
     - Longitude

6. **HTTP Header Information**: 
   - Fetches HTTP headers from the domain to identify details such as:
     - Server types (e.g., Apache, Nginx)
     - Content types (e.g., text/html, application/json)
     - Caching policies (e.g., cache-control settings)

### Requirements

To run the domain inspection tool on a Linux system, you will need the following:

1. **Python 3**: Ensure that Python 3 is installed on your system.
2. **pip**: Python package installer.
3. **Required Python packages**:
   - `socket`
   - `dnspython`
   - `requests`
   - `whois`
   - `ssl`
   - `geoip2`
   - `beautifulsoup4`
   - `re`
   - `json`
   - `pprint`
4. **GeoLite2-City database**: The GeoLite2-City database has been downloaded from  [MaxMind](https://www.maxmind.com/en/geoip-databases).

### Installation Steps

1. **Ensure Python 3 is installed**:
   Make sure you have Python 3 installed on your system. You can check this by running:
   ```sh
   python3 --version
   ```
   If Python 3 is not installed, you can install it using your package manager. For example, on Ubuntu:
   ```sh
   sudo apt-get update
   sudo apt-get install python3
   ```

2. **Install `pip`**:
   If `pip` is not already installed, you can install it by running:
   ```sh
   sudo apt-get install python3-pip
   ```


3. **Clone the GitHub repository**:
   Clone the repository containing your script:
   ```sh
   git clone https://github.com/alvinal9/InfoInspector.git
   ```
4. **Unzip the GeoLite2-City database**:
   Unzip the file GeoLite2-City_20240709 and place it in the specified directory:
   ```sh
   unzip GeoLite2-City_20240709.zip   ```
   Adjust the path if necessary (infoinspector.py, line 87) .

Move into the directory tool
   ```
   cd infoinspector
   ```
5. **Install required Python packages**:
   Use `pip3` to install the necessary packages:
   ```sh
   pip3 install dnspython requests python-whois geoip2 beautifulsoup4
   ```

6. **Make your script executable**:
   ```sh
   chmod +x infoinspector.py
   ```

7. **Run your script**:
   You can run the script directly using:
   ```sh
  python3  infoinspector.py
   ```
### Example Output
The tool provides detailed output for each domain, including network information, domain registration details, SSL/TLS certificate information, email addresses, geolocation information, HTTP header information, and website structure and content information.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.

## Contributions
Contributions are welcome! If you have suggestions for improvements or new features, feel free to open an issue or submit a pull request.
