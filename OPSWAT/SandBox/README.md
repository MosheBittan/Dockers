# 🛡️ OPSWAT Sandbox File Scanner

A lightweight, Dockerized Python web application that uploads files to the OPSWAT MetaDefender Sandbox, analyzes them, and returns a detailed threat verdict and forensic dashboard.

## 🚀 Features
* **Python Backend:** Handles API communication and asynchronous polling.
* **Containerized:** Fully Dockerized for easy, cross-platform deployment.
* **Deep Forensics Extraction:** Maps OSINT reputation and behavioral network/email Indicators of Compromise (IOCs).
* **Modern Web Interface:** Clean, user-friendly dashboard to view the analysis results.

---

## 🛠️ Quick Start

### Prerequisites
* [Docker](https://www.docker.com/) installed on your machine.
* A valid OPSWAT MetaDefender Sandbox API Key.

### Build and Run
Execute the following commands in your terminal to build the image and spin up the container:

```bash
# 1. Remove any existing container with the same name (optional)
docker rm -f my-scanner

# 2. Build the Docker image
docker build -t opswat-scanner .

# 3. Run the container (Replace XXXXX with your actual API Key)
docker run -d -p 5000:5000 -e OPSWAT_API_KEY="XXXXXXXXXXXXXXXXXXX" --name my-scanner opswat-scanner

# 4. Follow the application logs
docker logs -f my-scanner
