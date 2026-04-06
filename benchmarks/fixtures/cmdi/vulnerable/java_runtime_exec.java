// Fixture: java-runtime-exec — Runtime.exec() with string concatenation
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-78
// Agent: cmdi
// Pattern: User input concatenated into Runtime.exec() command string

package com.example.admin;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

@WebServlet("/api/admin/*")
public class AdminToolsServlet extends HttpServlet {

    // VULNERABLE: user-controlled host concatenated into Runtime.exec() shell command
    // Attacker sends: GET /api/admin/ping?host=127.0.0.1;+cat+/etc/passwd
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String action = req.getPathInfo();
        resp.setContentType("application/json");
        PrintWriter out = resp.getWriter();

        if ("/ping".equals(action)) {
            String host = req.getParameter("host");
            // VULNERABLE: string concatenation into shell command
            String[] cmd = {"/bin/sh", "-c", "ping -c 3 " + host};
            Process proc = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            out.printf("{\"output\": \"%s\"}", output.toString().replace("\"", "\\\""));

        } else if ("/disk".equals(action)) {
            String path = req.getParameter("path");
            // VULNERABLE: user-controlled path in du command
            // Attacker sends: ?path=/tmp;+rm+-rf+/var/data
            String[] cmd = {"/bin/sh", "-c", "du -sh " + path};
            Process proc = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            String result = reader.readLine();
            out.printf("{\"usage\": \"%s\"}", result != null ? result : "unknown");

        } else if ("/process".equals(action)) {
            String name = req.getParameter("name");
            // VULNERABLE: user-controlled process name in pgrep
            // Attacker sends: ?name=java;+id+>+/tmp/pwned
            Process proc = Runtime.getRuntime().exec("/bin/sh -c pgrep -la " + name);
            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            StringBuilder output = new StringBuilder("[");
            String line;
            boolean first = true;
            while ((line = reader.readLine()) != null) {
                if (!first) output.append(",");
                output.append("\"").append(line.replace("\"", "\\\"")).append("\"");
                first = false;
            }
            output.append("]");
            out.printf("{\"processes\": %s}", output);
        }
    }
}
