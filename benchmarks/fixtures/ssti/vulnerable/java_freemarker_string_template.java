// Fixture: java-freemarker-string-template — FreeMarker Template from StringReader with user input
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-1336
// Agent: ssti
// Pattern: User input used as template source via new Template(name, new StringReader(userInput), cfg)

package com.example.ssti;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class TemplateController {

    private final Configuration freemarkerConfig;

    public TemplateController(Configuration freemarkerConfig) {
        this.freemarkerConfig = freemarkerConfig;
    }

    // VULNERABLE: User-supplied template string compiled as FreeMarker template
    // Attacker sends: {"template": "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"}
    @PostMapping("/render-notification")
    public Map<String, String> renderNotification(@RequestBody Map<String, Object> request)
            throws IOException, TemplateException {

        String templateBody = (String) request.getOrDefault("template",
                "<p>Hello ${username}</p>");
        String username = (String) request.getOrDefault("username", "User");

        Template template = new Template(
                "notification",
                new StringReader(templateBody),
                freemarkerConfig
        );

        Map<String, Object> model = new HashMap<>();
        model.put("username", username);

        StringWriter writer = new StringWriter();
        template.process(model, writer);

        Map<String, String> result = new HashMap<>();
        result.put("rendered", writer.toString());
        return result;
    }

    // VULNERABLE: Report header template from request parameter
    // Attacker sends: ?header=<#assign ob="freemarker.template.utility.ObjectConstructor"?new()>${ob("java.lang.Runtime").getRuntime().exec("whoami")}
    @GetMapping("/report")
    public void generateReport(
            @RequestParam(defaultValue = "<h1>${title}</h1>") String header,
            @RequestParam(defaultValue = "Monthly Report") String title,
            HttpServletResponse response) throws IOException, TemplateException {

        String fullTemplate = header + "<div class='report-body'>${body}</div>";

        Template template = new Template(
                "report-header",
                new StringReader(fullTemplate),
                freemarkerConfig
        );

        Map<String, Object> model = new HashMap<>();
        model.put("title", title);
        model.put("body", "Report content here...");

        StringWriter writer = new StringWriter();
        template.process(model, writer);

        response.setContentType("text/html");
        response.getWriter().write(writer.toString());
    }
}
