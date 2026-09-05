const $ = (id) => document.getElementById(id);

const urlParams = new URLSearchParams(window.location.search);
const ztxCurrentTarget = urlParams.get('xapp') || "unknown";

function initializeForensics() {
  if ($("ztxTargetPodName")) {
    $("ztxTargetPodName").textContent = ztxCurrentTarget;
  }
  
  // Asynchronously query the real-time triple-lock status parameters from app.py
// Replace the fetch block in initializeForensics() with this:
fetch(`/get-forensics-logs?xapp=${encodeURIComponent(ztxCurrentTarget)}`)
    .then(res => {
        if (!res.ok) throw new Error("Server error: " + res.status);
        return res.json();
    })
    .then(data => {
        // ... (keep your existing logic to update lock1/2/3 and console box here)
    })
    .catch(err => {
        console.error("Forensic payload fetch failed", err);
        $("ztxForensicConsoleBox").textContent = "Error loading forensics: " + err.message;
    });
}

async function executeZtxAction(actionType) {
  const endpoint = actionType === "terminate" ? "/csm/containment/apply" : "/csm/containment/restore";
  const promptMsg = actionType === "terminate" 
    ? `⚠️ WARNING: Execute absolute eviction and purge workload runtime space for ${ztxCurrentTarget}?`
    : `🔄 CONFIRM RECOVERY: Roll back isolation barriers and instantiate pristine image template for ${ztxCurrentTarget}?`;

  if (confirm(promptMsg)) {
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ xapp: ztxCurrentTarget })
      });
      const data = await res.json();
      alert(`[SYSTEM ACTION SUCCESS]: ${data.message || "Operation executed successfully."}`);
      window.location.href = "/dashboard";
    } catch (err) {
      alert(`[-] Action failed: Communication channel failure.`);
    }
  }
}

window.executeZtxAction = executeZtxAction;
document.addEventListener("DOMContentLoaded", initializeForensics);

