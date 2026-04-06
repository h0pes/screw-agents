// Fixture: js-ejs-render — ejs.render() with user-controlled template
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-1336
// Agent: ssti
// Pattern: User input passed as template source to ejs.render() or ejs.compile()

import express, { Request, Response } from "express";
import ejs from "ejs";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

interface CardRequest {
  template: string;
  name?: string;
  role?: string;
}

// VULNERABLE: user-controlled template source passed to ejs.render()
// Attacker sends: {"template": "<%= global.process.mainModule.require('child_process').execSync('id').toString() %>"}
app.post("/api/render-card", (req: Request, res: Response) => {
  const { template, name, role }: CardRequest = req.body;

  const data = {
    name: name || "User",
    role: role || "Member",
    date: new Date().toLocaleDateString(),
  };

  // VULNERABLE: template from request body is the template source
  const rendered = ejs.render(template, data);
  res.send(rendered);
});

// VULNERABLE: custom signature block from user input compiled as EJS
// Attacker sends: ?signature=<%- global.process.mainModule.require('child_process').execSync('cat /etc/passwd').toString() %>
app.get("/email/compose", (req: Request, res: Response) => {
  const signature = (req.query.signature as string) || "<p>Regards</p>";
  const from = (req.query.from as string) || "user@example.com";

  // VULNERABLE: signature is user-controlled and becomes template source
  const templateSrc =
    `<div class="email-editor">` +
    `<div class="toolbar">Compose</div>` +
    `<div class="body"><textarea></textarea></div>` +
    `<div class="signature">${signature}</div>` +
    `<div class="from"><%= from %></div>` +
    `</div>`;

  const rendered = ejs.render(templateSrc, { from });
  res.send(rendered);
});

// VULNERABLE: user-supplied EJS compiled and cached
// Attacker sends: POST with body containing EJS RCE payload
app.post("/api/compile-template", (req: Request, res: Response) => {
  const { source, context } = req.body;

  // VULNERABLE: user-controlled source compiled into executable template function
  const compiledFn = ejs.compile(source);
  const rendered = compiledFn(context || {});
  res.json({ html: rendered });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
