// Fixture: java-jstl-cout — JSTL <c:out>, fn:escapeXml(), Thymeleaf th:text
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-79
// Agent: xss
// Pattern: Proper output encoding via JSTL tags, EL functions, and Thymeleaf th:text (auto-escaped)

package com.example.xss;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;

@Controller
public class SafeOutputController {

    // SAFE: Thymeleaf th:text auto-escapes all output
    // Unlike th:utext, th:text applies HTML entity encoding to the variable value
    // Template: <h1 th:text="${username}">Default</h1>
    // Input "Alice <script>" renders as: <h1>Alice &lt;script&gt;</h1>
    @GetMapping("/profile")
    public String profile(
            @RequestParam(defaultValue = "Guest") String username,
            @RequestParam(defaultValue = "") String bio,
            Model model) {

        model.addAttribute("username", username);
        model.addAttribute("bio", bio);
        // Template uses th:text — auto-escaping is applied
        return "profile";
    }

    // SAFE: Search results with Thymeleaf auto-escaping
    // Template: <p th:text="'Results for: ' + ${query}">Results</p>
    @GetMapping("/search")
    public String search(
            @RequestParam(defaultValue = "") String q,
            @RequestParam(defaultValue = "1") int page,
            Model model) {

        model.addAttribute("query", q);
        model.addAttribute("page", page);
        return "search_results";
    }

    // SAFE: Forward to JSP using JSTL <c:out> for output
    // JSP template uses:
    //   <c:out value="${username}" />           — auto-escapes by default
    //   ${fn:escapeXml(bio)}                    — explicit XML/HTML escaping
    //   <c:out value="${query}" escapeXml="true" />  — explicit escapeXml flag
    //
    // JSTL <c:out> escapes &, <, >, ", ' by default (escapeXml="true" is the default)
    // fn:escapeXml() applies the same encoding as a function call
    @GetMapping("/legacy/profile")
    public String legacyProfile(
            @RequestParam(defaultValue = "Guest") String username,
            @RequestParam(defaultValue = "") String bio,
            HttpServletRequest request) {

        request.setAttribute("username", username);
        request.setAttribute("bio", bio);
        // Forward to JSP that uses <c:out> for all user-controlled output
        return "forward:/WEB-INF/views/profile.jsp";
    }
}

// JSP template reference (profile.jsp):
//
// <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
// <%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
//
// <html><body>
//   <h1>Profile: <c:out value="${username}" /></h1>
//   <p>Bio: ${fn:escapeXml(bio)}</p>
// </body></html>
