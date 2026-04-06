// Fixture: js-nunjucks-renderstring — nunjucks.renderString() with user input
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-1336
// Agent: ssti
// Pattern: User input passed as template source to nunjucks.renderString()

import express, { Request, Response } from "express";
import nunjucks from "nunjucks";

const app = express();
app.use(express.json());

nunjucks.configure("views", { autoescape: true, express: app });

interface WidgetRequest {
  template: string;
  title?: string;
  items?: string[];
}

// VULNERABLE: user-supplied template string rendered by nunjucks
// Attacker sends: {"template": "{{ range.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\").toString()')() }}"}
app.post("/api/render-widget", (req: Request, res: Response) => {
  const { template, title, items }: WidgetRequest = req.body;

  const context = {
    title: title || "Widget",
    items: items || [],
    timestamp: new Date().toISOString(),
  };

  // VULNERABLE: user-controlled template is the template source
  const rendered = nunjucks.renderString(template, context);
  res.send(rendered);
});

interface EmailPreview {
  subject: string;
  body: string;
  recipientName: string;
}

// VULNERABLE: email body template from user input
// Attacker sends: {"body": "{% set cmd = cycler.__init__.__globals__.os.popen('id') %}{{ cmd.read() }}"}
app.post("/api/email-preview", (req: Request, res: Response) => {
  const { subject, body, recipientName }: EmailPreview = req.body;

  const fullTemplate =
    `<div class="email">` +
    `<h2>${subject}</h2>` +
    `<p>Dear ${recipientName},</p>` +
    body +
    `<p>Best regards,<br/>The Team</p>` +
    `</div>`;

  // VULNERABLE: body (user input) is embedded in the template source
  const rendered = nunjucks.renderString(fullTemplate, {
    subject,
    recipientName,
  });
  res.json({ preview: rendered });
});

// VULNERABLE: custom page layout from query parameter
// Attacker sends: ?layout={{ range.constructor("return global.process.mainModule.require('child_process').execSync('whoami').toString()")() }}
app.get("/page", (req: Request, res: Response) => {
  const layout = (req.query.layout as string) || "<p>Default layout</p>";
  const pageTitle = (req.query.title as string) || "Page";

  const template = `<html><head><title>{{ title }}</title></head><body>${layout}</body></html>`;

  const rendered = nunjucks.renderString(template, { title: pageTitle });
  res.send(rendered);
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
