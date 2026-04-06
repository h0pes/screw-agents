// Fixture: java-servlet-response-writer — response.getWriter().print() with request.getParameter()
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-79
// Agent: xss
// Pattern: User input from request parameters written directly to response via PrintWriter

package com.example.xss;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.annotation.WebServlet;
import java.io.IOException;
import java.io.PrintWriter;

@WebServlet("/search")
public class SearchServlet extends HttpServlet {

    // VULNERABLE: request.getParameter() output written directly via response writer
    // No HTML encoding applied; attacker sends: ?q=<script>alert(1)</script>
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String query = request.getParameter("q");
        String page = request.getParameter("page");

        response.setContentType("text/html");
        PrintWriter out = response.getWriter();

        out.println("<!DOCTYPE html>");
        out.println("<html><head><title>Search Results</title></head><body>");
        // VULNERABLE: query echoed directly into HTML body
        out.println("<h1>Results for: " + query + "</h1>");
        out.println("<p>Page: " + page + "</p>");

        // Simulate results
        out.println("<ul>");
        out.println("<li>Result 1 matching '" + query + "'</li>");
        out.println("<li>Result 2 matching '" + query + "'</li>");
        out.println("</ul>");
        out.println("</body></html>");
    }
}

@WebServlet("/profile")
class ProfileServlet extends HttpServlet {

    // VULNERABLE: user input reflected via getOutputStream() as raw bytes
    // Attacker sends: ?name=<img src=x onerror=alert(document.cookie)>
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException {

        String name = request.getParameter("name");
        String bio = request.getParameter("bio");

        response.setContentType("text/html; charset=UTF-8");

        // VULNERABLE: string concatenation with user input into HTML output stream
        String html = "<html><body>"
                + "<h2>Profile: " + name + "</h2>"
                + "<div class=\"bio\">" + bio + "</div>"
                + "</body></html>";

        response.getOutputStream().write(html.getBytes("UTF-8"));
    }
}
