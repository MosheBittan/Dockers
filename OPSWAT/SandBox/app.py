from flask import Flask, request, jsonify, render_template_string
import requests
import time
import os
import urllib3

# Suppress the warning Python throws when verifying SSL is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# The Sandbox uses the /api/scan endpoint architecture
# Defaulting to your local IP so it works out of the box
BASE_URL = os.environ.get("OPSWAT_BASE_URL", "https://192.168.170.130/api/scan")
OPSWAT_API_KEY = os.environ.get("OPSWAT_API_KEY")

# --- FRONTEND GUI HTML ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OPSWAT Sandbox Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f4f8; color: #333; margin: 0; padding: 40px; display: flex; justify-content: center; }
        .container { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 8px 20px rgba(0,0,0,0.05); width: 100%; max-width: 1000px; }
        h2 { margin-top: 0; color: #102a43; border-bottom: 2px solid #f0f4f8; padding-bottom: 10px; }
        
        /* Form Styles */
        .form-group { margin-bottom: 20px; }
        input[type="file"] { width: 100%; padding: 12px; border: 2px dashed #bcccdc; border-radius: 8px; background: #f8fafc; box-sizing: border-box; }
        button { background-color: #2680eb; color: white; border: none; padding: 12px 20px; border-radius: 6px; cursor: pointer; font-size: 16px; width: 100%; font-weight: bold; transition: 0.2s; }
        button:hover { background-color: #1a66c2; }
        
        /* Status */
        #loading { display: none; margin-top: 20px; color: #d69e2e; font-weight: bold; text-align: center; }
        #resultDiv { display: none; margin-top: 30px; }
        
        /* Dashboard Layout - Upgraded to auto-fit grid */
        .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }
        .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.02); }
        .card h4 { margin-top: 0; color: #4a5568; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #edf2f7; padding-bottom: 8px; }
        
        /* Info Rows */
        .info-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f7fafc; font-size: 14px; }
        .info-row:last-child { border-bottom: none; }
        .info-label { font-weight: 600; color: #718096; }
        .info-value { color: #2d3748; word-break: break-all; text-align: right; margin-left: 15px; }
        .monospace { font-family: 'Courier New', Courier, monospace; font-size: 11px; background: #edf2f7; padding: 2px 4px; border-radius: 4px; }
        
        /* Badges */
        .verdict-header { display: flex; align-items: center; justify-content: space-between; background: #f8fafc; padding: 15px 20px; border-radius: 8px; border-left: 5px solid #cbd5e0; margin-bottom: 20px; }
        .verdict-badge { padding: 6px 12px; border-radius: 4px; font-weight: bold; color: white; font-size: 18px; text-transform: uppercase; }
        .clean-border { border-left-color: #38a169; }
        .threat-border { border-left-color: #e53e3e; }
        .bg-clean { background-color: #38a169; }
        .bg-threat { background-color: #e53e3e; }
        
        /* Raw JSON toggle */
        details { margin-top: 30px; background: #f8fafc; padding: 15px; border-radius: 8px; border: 1px solid #e2e8f0; }
        summary { cursor: pointer; color: #2680eb; font-weight: 600; }
        pre { background: #1a202c; color: #a0aec0; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 12px; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🛡️ OPSWAT Advanced Forensics</h2>
        <p>Select a file to detonate. The dashboard will extract deep file inspection data from the JSON API.</p>
        
        <form id="uploadForm">
            <div class="form-group">
                <input type="file" id="fileInput" name="file" required>
            </div>
            <button type="submit">Detonate File</button>
        </form>

        <div id="loading">Detonation in progress... extracting forensics...</div>
        
        <div id="resultDiv"></div>
    </div>

<script>
    document.getElementById('uploadForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // 1. Lock the UI so we don't accidentally send multiple requests
        const submitBtn = document.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.innerText = "Analyzing... This may take a minute";
        document.getElementById('loading').style.display = 'block';
        
        // 2. Clear and hide the result div while loading
        const resultDiv = document.getElementById('resultDiv');
        resultDiv.innerHTML = '';
        resultDiv.style.display = 'none'; 
        
        const formData = new FormData();
        formData.append('file', document.getElementById('fileInput').files[0]);

        try {
            const response = await fetch('/scan', { method: 'POST', body: formData });
            const data = await response.json();
            
            // 3. THE FIX: Make the dashboard visible!
            resultDiv.style.display = 'block';
            
            if (response.ok) {
                const apiResponse = data.full_report;
                
                // Dynamically get the first report object ignoring the UUID key
                const reportsArray = Object.values(apiResponse.reports || {});
                const report = reportsArray.length > 0 ? reportsArray[0] : null;

                if (!report) {
                    resultDiv.innerHTML = `<div class="card" style="border-left: 5px solid red;"><h4>Error</h4><p>No report data found in the response.</p></div>`;
                    return;
                }

                // Extract core variables
                const verdict = report.finalVerdict?.verdict || "UNKNOWN";
                const isClean = verdict === 'NO_THREAT';
                const threatLevel = report.finalVerdict?.threatLevel || 0;
                const fileHash = report.file?.hash || "N/A";
                
                // Extract Scan Options that are set to 'true'
                const scanOptions = report.scanOptions || {};
                const enabledOptions = Object.keys(scanOptions)
                    .filter(key => scanOptions[key] === true)
                    .map(opt => `<span class="tag" style="background:#edf2f7; padding:4px 8px; border-radius:4px; font-size:11px; margin:2px; display:inline-block;">${opt.replace(/_/g, ' ')}</span>`)
                    .join('');

                // Build the GUI
                resultDiv.innerHTML = `
                    <div class="verdict-header" style="border-left: 5px solid ${isClean ? '#38a169' : '#e53e3e'}; background: #f8fafc; padding: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                        <div>
                            <h3 style="margin: 0; color: #2d3748;">Analysis Complete</h3>
                            <div style="color: #718096; font-size: 13px; margin-top: 5px;">Flow ID: ${apiResponse.flowId}</div>
                        </div>
                        <div style="background: ${isClean ? '#38a169' : '#e53e3e'}; color: white; padding: 8px 16px; border-radius: 6px; font-weight: bold; font-size: 16px;">
                            ${verdict.replace(/_/g, ' ')}
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                        <div style="background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px;">
                            <h4 style="margin-top: 0; color: #4a5568; border-bottom: 1px solid #edf2f7; padding-bottom: 10px;">File Identification</h4>
                            <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f7fafc; font-size: 14px;">
                                <strong>Name</strong> <span>${report.file?.name}</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f7fafc; font-size: 14px;">
                                <strong>Size</strong> <span>${apiResponse.fileSize} bytes</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f7fafc; font-size: 14px;">
                                <strong>Scan Date</strong> <span>${apiResponse.scanStartedDate}</span>
                            </div>
                            <div style="display: flex; flex-direction: column; padding: 8px 0; font-size: 14px;">
                                <strong style="margin-bottom: 4px;">SHA-256 Hash</strong> 
                                <span style="font-family: monospace; font-size: 11px; background: #edf2f7; padding: 4px; border-radius: 4px; word-break: break-all;">${fileHash}</span>
                            </div>
                        </div>

                        <div style="background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px;">
                            <h4 style="margin-top: 0; color: #4a5568; border-bottom: 1px solid #edf2f7; padding-bottom: 10px;">Detonation Environment</h4>
                            <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f7fafc; font-size: 14px;">
                                <strong>Threat Level</strong> <span>${threatLevel}</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f7fafc; font-size: 14px;">
                                <strong>Engine</strong> <span>${report.scanEngine}</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #f7fafc; font-size: 14px;">
                                <strong>Profile</strong> <span>${report.scanProfile}</span>
                            </div>
                            <div style="display: flex; justify-content: space-between; padding: 8px 0; font-size: 14px;">
                                <strong>Uploader</strong> <span>${report.uploader?.email}</span>
                            </div>
                        </div>
                    </div>

                    <div style="background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-top: 20px;">
                        <h4 style="margin-top: 0; color: #4a5568; border-bottom: 1px solid #edf2f7; padding-bottom: 10px;">Enabled Analysis Modules</h4>
                        <div style="margin-top: 10px;">
                            ${enabledOptions || '<span style="color: #a0aec0; font-size: 14px;">Default options used</span>'}
                        </div>
                    </div>
                `;
            } else {
                resultDiv.innerHTML = `<div style="border-left: 5px solid red; padding: 15px; background: white;"><h4>API Error</h4><p>${data.error}</p></div>`;
            }
        } catch (err) {
            resultDiv.style.display = 'block';
            resultDiv.innerHTML = `<div style="border-left: 5px solid red; padding: 15px; background: white;"><h4>Connection Error</h4><p>Failed to parse response. Check the terminal logs.</p></div>`;
        } finally {
            // 4. Reset the UI state
            document.getElementById('loading').style.display = 'none';
            submitBtn.disabled = false;
            submitBtn.innerText = "Detonate File";
        }
    });
</script>

</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/scan', methods=['POST'])
def scan_file():
    if not OPSWAT_API_KEY:
        return jsonify({"error": "OPSWAT_API_KEY environment variable is missing"}), 500

    if 'file' not in request.files:
        return jsonify({"error": "No file provided in the request"}), 400

    uploaded_file = request.files['file']
    headers = {"X-Api-Key": OPSWAT_API_KEY}
    files = {"file": (uploaded_file.filename, uploaded_file.stream, uploaded_file.content_type)}
    
    try:
        # Step 1: Upload the file
        upload_url = f"{BASE_URL}/file"
        upload_response = requests.post(upload_url, headers=headers, files=files, verify=False)
        upload_response.raise_for_status() 
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to reach OPSWAT Sandbox Upload API", "details": str(e)}), 502

    # Step 2: Retrieve the Sandbox flow_id
    flow_id = upload_response.json().get("flow_id")
    if not flow_id:
        return jsonify({"error": "Did not receive flow_id from Sandbox", "details": upload_response.json()}), 500

    # Step 3: Poll ONLY the /report endpoint until 'allFinished' is true
    # Notice we completely removed the old Step 3 status check
    report_url = f"{BASE_URL}/{flow_id}/report"
    
    while True:
        try:
            report_response = requests.get(report_url, headers=headers, verify=False)
            report_response.raise_for_status()
            report_data = report_response.json()
        except requests.exceptions.RequestException as e:
            return jsonify({"error": "Failed while polling Sandbox report API", "details": str(e)}), 502
        
        # Check if the Sandbox is 100% done
        if report_data.get("allFinished") is True:
            break
            
        time.sleep(3) # Wait 3 seconds before polling again

    # Step 4: Extract the final verdict from the nested dynamic dictionary
    final_verdict = "Unknown"
    reports_dict = report_data.get("reports", {})
    
    for report_id, report_details in reports_dict.items():
        verdict_info = report_details.get("finalVerdict", {})
        
        if isinstance(verdict_info, dict):
            final_verdict = verdict_info.get("verdict", "Unknown")
        else:
            final_verdict = str(verdict_info)
            
        break # We only need the first report's verdict

    return jsonify({
        "status": "success",
        "filename": uploaded_file.filename,
        "verdict": final_verdict, 
        "full_report": report_data 
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)