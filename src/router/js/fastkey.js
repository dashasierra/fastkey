/*

Fastkey Javascript Implementation

You must change your API_BASE_URL constant before deployment, or,
FastKey application will attempt to change it dynamically if you
leave {{API_BASE_URL}} intact.

*/

// Define API base URL
const API_BASE_URL = "{{API_BASE_URL}}";

window.addEventListener("DOMContentLoaded", () => {
    const savedUsername = localStorage.getItem("username");
    if (savedUsername) {
        // Populate login box
        document.getElementById("username").value = savedUsername;

        // Hide the Register field
        document.getElementById("register-button").style.display = "none";

        // Hide the username field
        document.getElementById("username").style.display = "none";

        // Login Automatically
        document.getElementById("login-button").click();
    } else {
        document.getElementById("login-button").style.display = "none";
    }
});

// Base64url <-> ArrayBuffer helpers
function base64urlToUint8Array(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
    const str = atob(base64 + pad);
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
    return bytes;
}

async function register() {
    const username = document.getElementById("username").value.trim();

    if (!username) {
        alert("Please enter a username.");
        return;
    }

    // 1) Get registration options from backend
    register_challenge = new URL(`${API_BASE_URL}/auth/register/challenge/`);
    register_challenge.searchParams.append("user_name", username);
    const res = await fetch(register_challenge, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
    });
    const status = await res.status;
    const options = await res.json();

    if (status == 422) {
        document.getElementById("result").textContent = JSON.stringify(options, null, 2);
    }

    // 2) Convert base64url strings to ArrayBuffers
    const publicKey = {
        ...options,
        challenge: base64urlToUint8Array(options.challenge),
        user: {
            ...options.user,
            id: base64urlToUint8Array(options.user.id)
        },
        pubKeyCredParams: options.pub_key_cred_params,
        excludeCredentials: (options.exclude_credentials || []).map(cred => ({
            ...cred,
            id: base64urlToUint8Array(cred.id)
        }))
    };

    // 3) Create credential
    const credential = await navigator.credentials.create({ publicKey });

    // 4) Send credential back to backend using toJSON()
    const payload = {
        username,
        credential: JSON.stringify(credential.toJSON())
    };

    const verifyRes = await fetch(`${API_BASE_URL}/auth/register/challenge/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    const result = await verifyRes.json();
    document.getElementById("result").textContent = JSON.stringify(result, null, 2);

    if (result.message === "User registered successfully.") {
        // Save username in localStorage
        localStorage.setItem("username", username);
        document.getElementById("register-button").style.display = "none";
        document.getElementById("login-button").style.display = "";
    }
}

async function login() {
    const username = document.getElementById("username").value.trim();
    if (!username) {
        alert("Please enter a username.");
        return;
    }

    // 1) Get authentication options from backend
    login_challenge = new URL(`${API_BASE_URL}/auth/login/challenge/`);
    login_challenge.searchParams.append("user_name", username);

    const res = await fetch(login_challenge, {
        method: "GET",
        headers: { "Content-Type": "application/json" },
    });
    const status = await res.status;
    const options = await res.json();

    if (status == 422) {
        document.getElementById("register-button").style.display = "";
        document.getElementById("login-button").style.display = "none";
    }

    // 2) Convert base64url strings to ArrayBuffers
    const publicKey = {
        ...options,
        challenge: base64urlToUint8Array(options.challenge),
        allowCredentials: (options.allow_credentials || []).map(cred => ({
            ...cred,
            id: base64urlToUint8Array(cred.id)
        }))
    };

    // 3) Request assertion
    const assertion = await navigator.credentials.get({ publicKey });

    // 4) Send assertion back to backend using toJSON()
    const payload = {
        username,
        credential: JSON.stringify(assertion.toJSON())
    };

    const verifyRes = await fetch(`${API_BASE_URL}/auth/login/challenge/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });

    const result = await verifyRes.json();
    if (result.status == 404) {
        document.getElementById("username").style.display = "show";
    }
    document.getElementById("result").textContent = JSON.stringify(result, null, 2);
}

