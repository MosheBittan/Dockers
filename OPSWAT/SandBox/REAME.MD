
Application that upload file to sandbox opswat and give you verdict .
This application create on python , build image and run as docker . 

#RUN this command :
docker rm -f my-scanner
docker build -t opswat-scanner .
docker run -d -p 5000:5000 -e OPSWAT_API_KEY="XXXXXXXXXXXXXXXXXXX" --name my-scanner opswat-scanner
docker logs -f my-scanner


#Test File :
#SUSPCIOUS:
URGENT: Your account has been compromised.
Please click the link below to verify your password and download the security update:

http://www.amtso.org/check-desktop-phishing-page/

Backup server connection:
http://www.amtso.org/check-desktop-malware-file/

Contact admin at:
phishing-test@wicar.orgs


#VALID:
20.3.20.140
# IP IOC Test (Google DNS - Usually marked as Informational/Safe)
8.8.8.8

# Known Malicious IP Test (Example of a flagged C2 IP)
20.3.20.140

# Phishing/Malicious Email Test
bad-actor@malicious-domain.com

Connecting to server at 1.1.1.1
Sending logs to admin-test@company.local
