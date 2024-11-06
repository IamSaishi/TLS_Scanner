import subprocess
import time
from colorama import Fore, Back, Style
from datetime import datetime


###############################
######## ALL TLS CHECKS #######
###############################

# 1. Weak SSL Cipher and Protocol Checks Module
# 2. SSL Verification Checks
# 3. SSL Expiration
# 4. SSL Forward Secrecy Verification


###############################




# Set up Global Variables

# The below is used with additional code to move the cursor up.

CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'


# Target Domain Variable.

TARGET_DOMAIN = ""


# List of weak ciphers


weak_ciphers = [
    # Null Ciphers (No Encryption)
    "TLS_NULL_WITH_NULL_NULL",  # No encryption or authentication, data is sent in plaintext.
    "eNULL",  # Ciphers that provide no encryption, exposing data to eavesdropping.
    "NULL",  # No encryption, no integrity protection.

    # EXPORT Ciphers (Weak Encryption)
    "EXP-DES-CBC-SHA",  # DES with 40-bit encryption, originally designed for export, now insecure.
    "EXP-RC4-MD5",  # RC4 with 40-bit encryption, weak and vulnerable.
    "EXP-RC2-CBC-MD5",  # RC2 with 40-bit encryption, outdated and insecure.
    "EXPORT",  # General label for export-grade ciphers with weak encryption.

    # DES Ciphers (56-bit Key, Weak)
    "DES-CBC-SHA",  # DES with 56-bit key, easily broken by modern standards.
    "DES-CBC3-SHA",  # 3DES (Triple DES), while slightly better than DES, it's still considered weak.
    "EDH-RSA-DES-CBC3-SHA",  # 3DES with ephemeral Diffie-Hellman, still weak due to 3DES.
    "EDH-DSS-DES-CBC3-SHA",  # 3DES with DSS and ephemeral DH, weak due to 3DES.

    # RC4 Ciphers (Vulnerable to Several Attacks)
    "RC4-SHA",  # RC4 stream cipher, known for biases and vulnerabilities.
    "RC4-MD5",  # RC4 with MD5 hashing, both of which are considered weak.
    "EXP-RC4-MD5",  # Export-grade RC4 with MD5, very weak encryption.

    # 3DES Ciphers (Triple DES)
    "DES-CBC3-SHA",  # 3DES uses 112-bit effective key length, which is weak by modern standards.
    "EDH-RSA-DES-CBC3-SHA",  # 3DES with RSA and ephemeral DH, weak due to 3DES.
    "EDH-DSS-DES-CBC3-SHA",  # 3DES with DSS and ephemeral DH, weak due to 3DES.

    # MD5 Ciphers (Weak Hashing Algorithm)
    "EXP-RC4-MD5",  # MD5 is vulnerable to collision attacks, making it unsuitable for secure hashing.
    "EXP-RC2-CBC-MD5",  # Weak encryption with weak MD5 hashing.
    "RC4-MD5",  # RC4 combined with MD5, both of which are insecure.
    "EDH-RSA-DES-CBC-SHA",  # Uses MD5 for integrity, which is weak.
]


# List of weak protocols


weak_protocols = [
    "SSLv2",  # Severely outdated, vulnerable to multiple attacks, and considered insecure.
    "SSLv3",  # Vulnerable to POODLE attack and other weaknesses, deprecated in favor of TLS.
    "TLSv1.0",  # Lacks modern security features, vulnerable to several attacks, deprecated.
    "TLSv1.1"  # Somewhat better than TLS 1.0 but still lacks modern security features, deprecated.
]




################################################################################################################

################################################################################################################







############################ Message Function To Show Start of SSL Module ############################

def Start_SSL_Module():
    message = "[.] Starting SSL Module"
    for i in range(5):
        if "[.]" in message:
            message = "[ ] Starting SSL Module"
            print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)
            print(Fore.MAGENTA + message + Style.RESET_ALL)
            time.sleep(0.5)
        else:
            message = "[.] Starting SSL Module"
            print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)
            print(Fore.MAGENTA + message + Style.RESET_ALL)
            time.sleep(0.5)
    print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)






################################################################################################################
################################################################################################################





############################ Weak SSL Cipher and Protocol Checks Module ############################



def Weak_Cipher_Protocol_Suite_Module(weak_ciphers, weak_protocols, TARGET_DOMAIN):
    print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)
    print(Fore.MAGENTA + "[ ] Checking For Weak Cipher Suites and SSL Protocols..." + Style.RESET_ALL)
    command = f"openssl s_client -connect {TARGET_DOMAIN}:443 -cipher ALL | grep 'Cipher is'"
    openSSL_process = subprocess.run(command, shell=True, capture_output=True, text=True)
    SSL_output = openSSL_process.stdout
    SSL_output = SSL_output.replace("Cipher is", "")
    SSL_output = SSL_output.split(",")
    SSL_Protocol = SSL_output[1].replace(" ","")
    SSL_Cipher = SSL_output[2].replace("\n", "").replace(" ","")
    print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)
    print(Fore.GREEN + f"SSL Protocol: {SSL_Protocol}" + Style.RESET_ALL)
    print(Fore.GREEN + f"SSL Cipher: {SSL_Cipher}" + Style.RESET_ALL)
    print()

    
    # Check For Weak Protocols

    for wp in weak_protocols:
        if wp == SSL_Protocol:
            print(Back.LIGHTRED_EX + f"[Low Impact Bug] Weak SSL Protocol Found: {wp}" + Style.RESET_ALL)
            break
    print(Fore.GREEN + f"[*] Target has Secure SSL Protocol!" + Style.RESET_ALL)
        

    # Check For Weak Ciphers

    for wc in weak_ciphers:
        if wc == SSL_Cipher:
            print(Back.LIGHTRED_EX + f"[Low Impact Bug] Weak SSL Cipher Found: {wc}")
            break
    print(Fore.GREEN + f"[*] Target has Secure SSL Cipher!" + Style.RESET_ALL)



################################################################################################################
################################################################################################################






############################ SSL Verification Checks ############################


def SSL_Verification_Module(TARGET_DOMAIN):

    print(Fore.MAGENTA + "[ ] Checking SSL Verification..." + Style.RESET_ALL)
    command = f"openssl s_client -connect {TARGET_DOMAIN}:443 -showcerts | grep 'Verification'"
    openSSL_Verify_process = subprocess.run(command, shell=True, capture_output=True, text=True)
    SSL_Verification = openSSL_Verify_process.stdout
    print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)
    print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)
    print()
    SSL_Verification = ' '.join(SSL_Verification.strip().split())

    if SSL_Verification == "Verification: OK":
        print(Fore.GREEN + f"[*] Target SSL {SSL_Verification}" + Style.RESET_ALL)
    else:
        print(Back.LIGHTRED_EX + f"[Low Impact Bug] SSL Verification Error: {SSL_Verification}" + Style.RESET_ALL)


################################################################################################################
################################################################################################################




############################ SSL Expiration ############################


def SSL_Expiration_Module(TARGET_DOMAIN):

    bugs_found = 0

    print(Fore.MAGENTA + "[ ] Verifying Target's SSL Certificate Validity Period..." + Style.RESET_ALL)
    command = f"openssl s_client -connect {TARGET_DOMAIN}:443 -cipher ALL | grep ':NotBefore:'"
    openSSL_validity_process = subprocess.run(command, shell=True, capture_output=True, text=True)
    SSL_Validity_output = openSSL_validity_process.stdout
    SSL_Validity_output = SSL_Validity_output.replace("v:", "")
    SSL_Validity_output = SSL_Validity_output.split("GMT")
    print(len(SSL_Validity_output))
    SSL_Validity_output.pop(len(SSL_Validity_output)-1)
    print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)
    
    for index,date in enumerate(SSL_Validity_output):
        current_time = datetime.now()
        if "Before" or "After" in date:
            if "Before" in date:
                date = date.replace("NotBefore: ", "").replace("\n","").replace("   ","")
                

            if "After" in date:
                date = date.replace("NotAfter: ", "").replace("; ","").replace("\n","")
            

            cleaned_date_string = ' '.join(date.strip().split())
            SSL_date_time_object = datetime.strptime(cleaned_date_string.replace("  ", " "), "%b %d %H:%M:%S %Y")
            current_time = datetime.now()

            if index in [0,2,4]:                        # NotBefore
                if SSL_date_time_object > current_time:
                    print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)
                    print()
                    print(Back.LIGHTRED_EX + f"[Low Impact Bug] Target has 'NotBefore' Validity Period Date Set For Future: {SSL_date_time_object}" + Style.RESET_ALL)
                    bugs_found = bugs_found + 1


            if index in [1,3,5]:                        # NotAfter
                if SSL_date_time_object < current_time:
                    print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)
                    print()
                    print(Back.LIGHTRED_EX + f"[Low Impact Bug] Target has 'NotAfter' Validity Period Date Set In Past: {SSL_date_time_object}" + Style.RESET_ALL)
                    bugs_found = bugs_found + 1
                    
    
    if bugs_found == 0:
        print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)
        print(Fore.GREEN + f"[*] No Validity Period Issues Found" + Style.RESET_ALL)




################################################################################################################
################################################################################################################


############################ SSL Forward Secrecy Verification ############################


def SSL_Forward_Secrecy_Module(TARGET_DOMAIN):

    print(Fore.MAGENTA + "[ ] Verifying if Target Supports Forward Secrecy..." + Style.RESET_ALL)
    command = f"openssl s_client -connect {TARGET_DOMAIN}:443 -cipher ECDHE -tls1_2 | grep 'Cipher is'"
    openSSL_FS_Verify_process = subprocess.run(command, shell=True, capture_output=True, text=True)
    SSL_FS_output = openSSL_FS_Verify_process.stdout
    SSL_FS_output = SSL_FS_output.replace("Cipher is", "")
    SSL_FS_output = SSL_FS_output.split(",")
    SSL_FS_output = SSL_FS_output[2].replace("\n", "").replace(" ","")
    print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)

    
    if "DHE" in SSL_FS_output:
        print(Fore.GREEN + f"[*] Target has SSL Forward Secrecy: Confirmation: {SSL_FS_output}" + Style.RESET_ALL)
    else:
        print(Back.LIGHTRED_EX + f"[Low Impact Bug] Target Has No Forward Secrecy: {SSL_FS_output}" + Style.RESET_ALL)




################################################################################################################
################################################################################################################




print(Fore.LIGHTGREEN_EX)
TARGET_DOMAIN = input(Fore.GREEN + "Enter Target Domain (eg, target.com): ")
print(Style.RESET_ALL)

print()
print(Fore.BLUE + "##########################################################" + Style.RESET_ALL)
print()
print(Fore.BLUE + "#############   Reconnaissance: TLS Scanner   ############" + Style.RESET_ALL)
print()
print(Fore.BLUE + "##########################################################" + Style.RESET_ALL)
print()
print()
Start_SSL_Module()
print()
Weak_Cipher_Protocol_Suite_Module(weak_ciphers, weak_protocols, TARGET_DOMAIN)
print()
SSL_Verification_Module(TARGET_DOMAIN)
print()
SSL_Forward_Secrecy_Module(TARGET_DOMAIN)
print()
SSL_Expiration_Module(TARGET_DOMAIN)





