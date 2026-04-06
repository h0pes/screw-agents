// Fixture: js-nunjucks-render-file — nunjucks.render() with file template and user data
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-1336
// Agent: ssti
// Pattern: Template loaded from file via nunjucks.render(), user input as context data only

import express, { Request, Response } from "express";
import nunjucks from "nunjucks";

const app = express();
app.use(express.json());

// Configure nunjucks with file-based template loading
const nunjucksEnv = nunjucks.configure("views", {
  autoescape: true,
  express: app,
  watch: false,
});

interface WidgetData {
  title?: string;
  items?: string[];
  theme?: string;
}

// SAFE: nunjucks.render() loads template from file, user input is context data
app.post("/api/render-widget", (req: Request, res: Response) => {
  const { title, items, theme }: WidgetData = req.body;

  const context = {
    title: title || "Widget",
    items: items || [],
    theme: theme || "default",
    timestamp: new Date().toISOString(),
  };

  // SAFE: "widget.njk" is a file path, not user-controlled template source
  nunjucks.render("widget.njk", context, (err, result) => {
    if (err) {
      res.status(500).json({ error: "Template rendering failed" });
      return;
    }
    res.send(result);
  });
});

// SAFE: template file with user data in context
app.get("/profile/:username", (req: Request, res: Response) => {
  const username = req.params.username;
  const bio = req.query.bio as string || "No bio provided";

  // SAFE: template loaded from views/profile.njk, user data is context only
  res.render("profile.njk", {
    username,
    bio,
    joinDate: "2024-01-15",
    postCount: 42,
  });
});

// SAFE: search results rendered from file template
app.get("/search", (req: Request, res: Response) => {
  const query = req.query.q as string || "";
  const page = parseInt(req.query.page as string) || 1;

  // Simulate search results
  const results = Array.from({ length: 10 }, (_, i) => ({
    title: `Result ${i + 1}`,
    snippet: `Match for "${query}"...`,
    url: `/item/${i + 1}`,
  }));

  // SAFE: template from file, all user input flows as data
  res.render("search_results.njk", {
    query,
    results,
    page,
    totalPages: 10,
  });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
