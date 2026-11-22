// DOM Elements
const emailInput = document.getElementById("emailInput");
const btnDeleteUser = document.getElementById("btnDeleteUser");
const statusBox = document.getElementById("statusBox");
const alertBox = document.getElementById("alertBox");

// Modal Elements
const confirmModal = document.getElementById("confirmModal");
const modalUserEmail = document.getElementById("modalUserEmail");
const modalBtnCancel = document.getElementById("modalBtnCancel");
const modalBtnConfirm = document.getElementById("modalBtnConfirm");

// State
let foundUser = null;
let debounceTimer = null;
let isChecking = false;

// Helper: Show Alert Message
function showAlert(message, type = "success") {
  alertBox.className = type === "success" 
    ? "rounded-xl p-4 text-sm font-semibold bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 flex items-center space-x-2 shadow-lg"
    : "rounded-xl p-4 text-sm font-semibold bg-red-500/15 border border-red-500/30 text-red-300 flex items-center space-x-2 shadow-lg";
  
  const icon = type === "success" 
    ? `<svg class="w-5 h-5 flex-shrink-0 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`
    : `<svg class="w-5 h-5 flex-shrink-0 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`;
  
  alertBox.innerHTML = `${icon}<span>${message}</span>`;
  alertBox.classList.remove("hidden");

  setTimeout(() => {
    alertBox.classList.add("hidden");
  }, 6000);
}

// Check Email via Backend API (connected directly to Firebase Authentication)
async function verifyEmailInFirebase(email) {
  const trimmed = email.trim();
  if (!trimmed) {
    statusBox.classList.add("hidden");
    foundUser = null;
    return;
  }

  // Basic email validation
  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed);
  if (!isValidEmail) {
    statusBox.className = "p-3.5 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-400 flex items-center space-x-2";
    statusBox.innerHTML = `<span>Please enter a complete and valid email address.</span>`;
    statusBox.classList.remove("hidden");
    foundUser = null;
    return;
  }

  isChecking = true;
  statusBox.className = "p-3.5 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-400 flex items-center space-x-2";
  statusBox.innerHTML = `
    <div class="w-3.5 h-3.5 border-2 border-brand-500 border-t-transparent rounded-full animate-spin"></div>
    <span>Checking Firebase Authentication for <strong class="text-white">${trimmed}</strong>...</span>
  `;
  statusBox.classList.remove("hidden");

  try {
    const res = await fetch("/api/check-user", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: trimmed })
    });

    const data = await res.json();

    if (data.exists && data.user) {
      foundUser = data.user;
      const user = data.user;
      const providersText = (user.providers && user.providers.length > 0) ? user.providers.join(", ") : "email/password";

      statusBox.className = "p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 space-y-2 shadow-sm animate-in fade-in";
      statusBox.innerHTML = `
        <div class="flex items-center space-x-2 font-bold text-sm text-emerald-400">
          <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
          <span>User Found in Firebase Authentication!</span>
        </div>
        <div class="bg-slate-950/70 rounded-lg p-3 border border-emerald-500/20 text-slate-300 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
          <div>
            <div class="font-bold text-white text-sm">${user.displayName || "Registered User"}</div>
            <div class="text-slate-400 font-mono">${user.email}</div>
          </div>
          <div class="flex items-center space-x-2">
            <span class="px-2 py-0.5 rounded-full bg-brand-500/20 text-brand-300 font-semibold text-[11px]">${providersText}</span>
            <span class="px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-semibold text-[11px]">Active</span>
          </div>
        </div>
        <div class="text-[11px] text-emerald-400/90 font-mono">
          User UID: ${user.uid}
        </div>
      `;
    } else if (data.error === "SERVICE_KEY_REQUIRED") {
      foundUser = null;
      statusBox.className = "p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-xs text-amber-300 space-y-2 shadow-sm";
      statusBox.innerHTML = `
        <div class="font-bold text-amber-400 flex items-center space-x-2">
          <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
          <span>Service Account Key Required</span>
        </div>
        <p class="text-slate-300 leading-relaxed">
          To delete users directly from the <strong>Firebase Authentication tab</strong>, place your Firebase Service Account JSON key as <code class="bg-slate-900 px-1 py-0.5 rounded font-mono text-amber-300">serviceAccountKey.json</code> in this folder.
        </p>
        <p class="text-slate-400 text-[11px]">
          Download it in 5 seconds: <em>Firebase Console ➔ Project Settings (⚙️) ➔ Service accounts ➔ Generate new private key</em>.
        </p>
      `;
    } else {
      foundUser = null;
      statusBox.className = "p-3.5 rounded-xl bg-red-500/10 border border-red-500/25 text-xs text-red-300 flex items-start space-x-2 shadow-sm";
      statusBox.innerHTML = `
        <svg class="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
        <div>
          <strong class="font-semibold">User Not Found in Firebase:</strong>
          <span> No registered user with email <strong>${trimmed}</strong> exists in the database. Only signed-in and registered users can be deleted.</span>
        </div>
      `;
    }
  } catch (err) {
    console.error("API check error:", err);
    statusBox.className = "p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-xs text-amber-300 flex items-center space-x-2";
    statusBox.innerHTML = `<span>Checking notice: Please ensure server is running (node server.js). Details: ${err.message}</span>`;
  } finally {
    isChecking = false;
  }
}

// Live typing debounce listener on email input
emailInput.addEventListener("input", (e) => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    verifyEmailInFirebase(e.target.value);
  }, 350);
});

// Delete User Button Click Handler
btnDeleteUser.addEventListener("click", async () => {
  const email = emailInput.value.trim();
  if (!email) {
    showAlert("Please enter an email ID first.", "error");
    emailInput.focus();
    return;
  }

  // If not yet verified or still checking, trigger a fresh check
  if (!foundUser) {
    await verifyEmailInFirebase(email);
    if (!foundUser) {
      showAlert(`Cannot delete: No user with email '${email}' is registered in Firebase.`, "error");
      return;
    }
  }

  // Open confirmation modal
  modalUserEmail.textContent = `${foundUser.email} (UID: ${foundUser.uid})`;
  confirmModal.classList.remove("hidden");
});

// Modal Actions
modalBtnCancel.addEventListener("click", () => {
  confirmModal.classList.add("hidden");
});

modalBtnConfirm.addEventListener("click", async () => {
  if (!foundUser) return;

  const targetEmail = foundUser.email;
  const targetUid = foundUser.uid;

  modalBtnConfirm.disabled = true;
  modalBtnConfirm.innerHTML = `
    <div class="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin inline-block mr-1"></div>
    Deleting from Firebase...
  `;

  try {
    const res = await fetch("/api/delete-user", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: targetEmail, uid: targetUid })
    });

    const data = await res.json();

    if (res.ok && data.success) {
      confirmModal.classList.add("hidden");
      showAlert(`User '${targetEmail}' has been permanently deleted from Firebase Authentication and database!`, "success");
      emailInput.value = "";
      statusBox.classList.add("hidden");
      foundUser = null;
    } else {
      confirmModal.classList.add("hidden");
      showAlert(`Deletion notice: ${data.message || data.error}`, "error");
    }
  } catch (err) {
    console.error("Deletion error:", err);
    confirmModal.classList.add("hidden");
    showAlert(`Deletion failed: ${err.message}`, "error");
  } finally {
    modalBtnConfirm.disabled = false;
    modalBtnConfirm.innerHTML = `Yes, Delete`;
  }
});
