// Fixture: Safe ProcessBuilder with separate args — Java
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-78
// Agent: cmdi
// Pattern: ProcessBuilder with argument list (no shell), input validation

package com.example.admin;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

@WebServlet("/api/safe/*")
public class SafeAdminToolsServlet extends HttpServlet {

    private static final Pattern IP_PATTERN =
            Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    private static final Pattern FILENAME_PATTERN =
            Pattern.compile("^[\\w\\-]+\\.[a-z]{1,5}$");
    private static final Set<String> ALLOWED_TOOLS =
            Set.of("df", "uptime", "whoami", "free");
    private static final String UPLOAD_DIR = "/var/app/uploads";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String action = req.getPathInfo();
        resp.setContentType("application/json");
        PrintWriter out = resp.getWriter();

        if ("/ping".equals(action)) {
            handlePing(req, out);
        } else if ("/checksum".equals(action)) {
            handleChecksum(req, out);
        } else if ("/tool".equals(action)) {
            handleTool(req, out);
        }
    }

    // SAFE: ProcessBuilder with separate arguments — no shell involved
    // Each string is a separate argv entry; semicolons are literal characters
    private void handlePing(HttpServletRequest req, PrintWriter out) throws IOException {
        String host = req.getParameter("host");

        // Strict IP address validation
        if (host == null || !IP_PATTERN.matcher(host).matches()) {
            out.print("{\"error\": \"invalid IP address\"}");
            return;
        }

        // SAFE: ProcessBuilder passes each arg separately to execvp, no shell
        ProcessBuilder pb = new ProcessBuilder(List.of("ping", "-c", "3", "-W", "5", host));
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        String output = readProcessOutput(proc);
        out.printf("{\"reachable\": %b, \"output\": \"%s\"}",
                proc.exitValue() == 0,
                output.replace("\"", "\\\"").replace("\n", "\\n"));
    }

    // SAFE: ProcessBuilder with validated filename and -- separator
    private void handleChecksum(HttpServletRequest req, PrintWriter out) throws IOException {
        String filename = req.getParameter("filename");

        if (filename == null || !FILENAME_PATTERN.matcher(filename).matches()) {
            out.print("{\"error\": \"invalid filename\"}");
            return;
        }

        Path filePath = Paths.get(UPLOAD_DIR, filename).normalize();
        // Path traversal check
        if (!filePath.startsWith(UPLOAD_DIR)) {
            out.print("{\"error\": \"path traversal\"}");
            return;
        }
        if (!Files.exists(filePath)) {
            out.print("{\"error\": \"file not found\"}");
            return;
        }

        // SAFE: separate args, -- prevents option injection
        ProcessBuilder pb = new ProcessBuilder(List.of("sha256sum", "--", filePath.toString()));
        Process proc = pb.start();
        String output = readProcessOutput(proc);
        String checksum = output.split("\\s+")[0];
        out.printf("{\"checksum\": \"%s\"}", checksum);
    }

    // SAFE: allowlisted command — user cannot inject arbitrary binaries
    private void handleTool(HttpServletRequest req, PrintWriter out) throws IOException {
        String tool = req.getParameter("tool");

        if (tool == null || !ALLOWED_TOOLS.contains(tool)) {
            out.print("{\"error\": \"unknown tool\"}");
            return;
        }

        // SAFE: tool name is from server-controlled allowlist
        ProcessBuilder pb = new ProcessBuilder(List.of(tool));
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        String output = readProcessOutput(proc);
        out.printf("{\"output\": \"%s\"}", output.replace("\"", "\\\"").replace("\n", "\\n"));
    }

    private String readProcessOutput(Process proc) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString().trim();
    }
}
