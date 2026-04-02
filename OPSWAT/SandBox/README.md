# 🛡️ OPSWAT Sandbox File Scanner

A lightweight, Dockerized Python web application that uploads files to the OPSWAT MetaDefender Sandbox, analyzes them, and returns a detailed threat verdict and forensic dashboard.

## 🚀 Features
* **Python Backend:** Handles API communication and asynchronous polling.
* **Containerized:** Fully Dockerized for easy, cross-platform deployment.
* **Deep Forensics Extraction:** Maps OSINT reputation and behavioral network/email Indicators of Compromise (IOCs).
* **Modern Web Interface:** Clean, user-friendly dashboard to view the analysis results.
* **Comment:** The Sandbox API only uses an asynchronous connection.

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
```


## 📮 Testing via Postman

If you want to interact with the OPSWAT Sandbox API directly bypassing the Python application, you can use the following Postman configuration.

*Note: If you are using a local appliance with a self-signed certificate, ensure you turn off **"SSL certificate verification"** in your Postman settings.*

### Step 1: Upload the File (Asynchronous POST)
This request submits the file to the Sandbox for detonation. 

* **Method:** `POST`
* **URL:** `https://192.168.170.130/api/scan/file`
* **Headers:**
  * `X-Api-Key`: `XXXXXXXXXXXXXXXXXXXXXXXX` *(Replace with your actual API key)*
* **Body:** * Select the **form-data** radio button.
  * **Key:** `file` *(Change the hidden dropdown type from "Text" to "File")*
  * **Value:** Upload your `testfile.txt`

> **Expected Result:** A `200 OK` response containing a JSON object with a `flow_id`. Copy this ID number for the next step.

### Step 2: Fetch the Report (GET)
Because the Sandbox takes time to detonate the file, you must poll this endpoint until the report is finished.

* **Method:** `GET`
* **URL:** `https://192.168.170.130/api/scan/<DATA_ID_NUMBER>/report` 
  *(Replace `<DATA_ID_NUMBER>` with the `flow_id` from Step 1)*
* **Headers:**
  * `X-Api-Key`: `XXXXXXXXXXXXXXXXXXXXXXXX`

> **Expected Result:** A large JSON payload containing the deep forensics, OSINT reputation, and behavioral indicators.
