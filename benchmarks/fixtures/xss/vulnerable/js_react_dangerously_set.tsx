// Fixture: js-react-dangerously-set — React dangerouslySetInnerHTML and javascript: href
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-79
// Agent: xss
// Pattern: dangerouslySetInnerHTML with user input, javascript: protocol in href with user data

import React, { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";

interface Comment {
  id: number;
  author: string;
  body: string;
}

// VULNERABLE: dangerouslySetInnerHTML with user-controlled content from API
// If the API returns unsanitized HTML (e.g., stored XSS), it executes in the DOM
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
          <strong>{comment.author}</strong>
          {/* VULNERABLE: unsanitized HTML from API rendered directly */}
          {/* Stored XSS if attacker submits: <img src=x onerror=alert(1)> as comment body */}
          <div dangerouslySetInnerHTML={{ __html: comment.body }} />
        </div>
      ))}
    </div>
  );
}

// VULNERABLE: User input from URL search params used in dangerouslySetInnerHTML
function SearchHighlight() {
  const [searchParams] = useSearchParams();
  const query = searchParams.get("q") || "";
  const resultText = "Found 3 results for your search term";

  // VULNERABLE: query from URL params embedded in HTML string
  // Attacker sends: ?q=<svg/onload=alert(document.domain)>
  const highlighted = `<p>${resultText}: <strong>${query}</strong></p>`;

  return (
    <div className="search-results">
      <div dangerouslySetInnerHTML={{ __html: highlighted }} />
    </div>
  );
}

interface UserProfile {
  name: string;
  website: string;
}

// VULNERABLE: javascript: protocol in href with user-controlled URL
// React does NOT sanitize href attributes — javascript: URIs execute on click
function ProfileCard({ profile }: { profile: UserProfile }) {
  return (
    <div className="profile-card">
      <h3>{profile.name}</h3>
      {/* VULNERABLE: user-supplied website URL used directly in href */}
      {/* Attacker sets website to: javascript:alert(document.cookie) */}
      <a href={profile.website}>Visit Website</a>
    </div>
  );
}

export { CommentList, SearchHighlight, ProfileCard };
