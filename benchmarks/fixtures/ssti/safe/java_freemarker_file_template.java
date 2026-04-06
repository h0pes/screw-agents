// Fixture: java-freemarker-file-template — FreeMarker loading template from classpath
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-1336
// Agent: ssti
// Pattern: Template loaded from file via Configuration.getTemplate(), user input in data model only

package com.example.safe;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class SafeTemplateController {

    private final Configuration freemarkerConfig;

    public SafeTemplateController() {
        this.freemarkerConfig = new Configuration(Configuration.VERSION_2_3_32);
        this.freemarkerConfig.setClassForTemplateLoading(this.getClass(), "/templates");
        this.freemarkerConfig.setDefaultEncoding("UTF-8");
        this.freemarkerConfig.setTemplateExceptionHandler(
                TemplateExceptionHandler.RETHROW_HANDLER);
    }

    // SAFE: Template loaded from classpath file, user input only in model
    // User data is rendered as content within the pre-defined template structure
    @PostMapping("/render-notification")
    public void renderNotification(
            @RequestBody Map<String, Object> request,
            HttpServletResponse response) throws IOException, TemplateException {

        String username = (String) request.getOrDefault("username", "User");
        String message = (String) request.getOrDefault("message", "You have updates");
        String priority = (String) request.getOrDefault("priority", "normal");

        // SAFE: template loaded from file, not from user input
        Template template = freemarkerConfig.getTemplate("notification.ftl");

        Map<String, Object> model = new HashMap<>();
        model.put("username", username);
        model.put("message", message);
        model.put("priority", priority);

        response.setContentType("text/html");
        template.process(model, response.getWriter());
    }

    // SAFE: Report template from file with user data in model
    @GetMapping("/report")
    public void generateReport(
            @RequestParam(defaultValue = "Monthly Report") String title,
            @RequestParam(defaultValue = "2024-01") String period,
            HttpServletResponse response) throws IOException, TemplateException {

        // SAFE: template loaded from classpath, not from user input
        Template template = freemarkerConfig.getTemplate("report.ftl");

        Map<String, Object> model = new HashMap<>();
        model.put("title", title);
        model.put("period", period);
        model.put("generatedAt", java.time.LocalDateTime.now().toString());
        model.put("items", List.of(
                Map.of("name", "Revenue", "value", "$10,000"),
                Map.of("name", "Expenses", "value", "$7,500")
        ));

        response.setContentType("text/html");
        template.process(model, response.getWriter());
    }
}
