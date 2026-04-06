// Fixture: js-react-jsx-safe — React JSX auto-escaping and textContent assignment
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-79
// Agent: xss
// Pattern: JSX {expression} auto-escapes strings, textContent is a safe DOM API

import React, { useState, useEffect, useRef } from "react";
import { useSearchParams } from "react-router-dom";
import DOMPurify from "dompurify";

interface Comment {
  id: number;
  author: string;
  body: string;
}

// SAFE: React JSX expressions auto-escape string values
// {userInput} in JSX is equivalent to textContent — React converts
// special characters to HTML entities before inserting into the DOM
function CommentList() {
  const [comments, setComments] = useState<Comment[]>([]);

  useEffect(() => {
    fetch("/api/comments")
      .then((res) => res.json())
      .then((data) => setComments(data));
  }, []);

  return (
    <div className="comments">
      {comments.map((comment) => (
        <div key={comment.id} className="comment">
          {/* SAFE: JSX auto-escapes — <script> becomes &lt;script&gt; */}
          <strong>{comment.author}</strong>
          <p>{comment.body}</p>
        </div>
      ))}
    </div>
  );
}

// SAFE: Search query displayed via JSX auto-escaping
function SearchResults() {
  const [searchParams] = useSearchParams();
  const query = searchParams.get("q") || "";

  return (
    <div className="search-results">
      {/* SAFE: query is auto-escaped by React */}
      <h1>Results for: {query}</h1>
      <p>Found 3 results</p>
    </div>
  );
}

// SAFE: When HTML rendering IS needed, sanitize with DOMPurify first
function SanitizedContent({ html }: { html: string }) {
  // SAFE: DOMPurify.sanitize() strips dangerous tags and attributes
  const cleanHtml = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ["b", "i", "em", "strong", "p", "br"],
    ALLOWED_ATTR: [],
  });

  return <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />;
}

// SAFE: Using ref with textContent instead of innerHTML
function DynamicLabel() {
  const labelRef = useRef<HTMLSpanElement>(null);
  const [searchParams] = useSearchParams();
  const label = searchParams.get("label") || "Default";

  useEffect(() => {
    if (labelRef.current) {
      // SAFE: textContent is a safe DOM API — does not parse HTML
      labelRef.current.textContent = label;
    }
  }, [label]);

  return <span ref={labelRef} className="dynamic-label" />;
}

export { CommentList, SearchResults, SanitizedContent, DynamicLabel };
