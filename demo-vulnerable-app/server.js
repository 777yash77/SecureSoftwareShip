const express = require('express');
const child_process = require('child_process');
const https = require('https');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Vulnerability 10: Hardcoded JWT Secret Key in signing function
const JWT_SECRET = "super-secret-hardcoded-signing-token-xyz123";

function generateToken(user) {
    return jwt.sign({ sub: user.id, role: 'admin' }, "super-secret-hardcoded-signing-token-xyz123");
}

// Vulnerability 11: Disabled TLS/SSL Certificate Verification (rejectUnauthorized: false)
const insecureAgent = new https.Agent({
    rejectUnauthorized: false
});

app.get('/fetch-external', (req, res) => {
    https.get('https://untrusted-internal-host.local/api', { agent: insecureAgent }, (resp) => {
        res.send("Fetched with disabled TLS verification");
    });
});

app.post('/execute-cmd', (req, res) => {
    const userFilename = req.body.file;
    // Vulnerability 12: Command Injection via child_process.exec
    child_process.exec("cat " + userFilename, (err, stdout) => {
        res.send(stdout);
    });
});

app.post('/eval-code', (req, res) => {
    // Vulnerability 13: Arbitrary Code Execution via eval()
    const result = eval(req.body.code);
    res.json({ result });
});

app.get('/search-account', (req, res) => {
    const accountId = req.query.id;
    // Mock db client
    const db = { query: (q) => console.log("Executing SQL:", q) };
    // Vulnerability 14: SQL Injection via String Concatenation
    db.query("SELECT * FROM accounts WHERE id = " + accountId);
    res.send("Query dispatched");
});

app.post('/render-profile', (req, res) => {
    const profileHtml = req.body.html;
    // Vulnerability 15: Cross-Site Scripting via innerHTML / dangerouslySetInnerHTML pattern
    const mockElement = {};
    mockElement.innerHTML = profileHtml;
    res.send("Profile rendered");
});

app.listen(3000, () => {
    console.log("Vulnerable Node server running on port 3000");
});
