// Fixture: java-thymeleaf-preprocessing — Thymeleaf __${...}__ preprocessing with user input
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-1336
// Agent: ssti
// Pattern: User input flows into Thymeleaf view name or fragment expression, enabling preprocessing injection

package com.example.ssti;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class ThymeleafController {

    private final TemplateEngine templateEngine;

    public ThymeleafController(TemplateEngine templateEngine) {
        this.templateEngine = templateEngine;
    }

    // VULNERABLE: User-controlled view name enables SSTI via Thymeleaf preprocessing
    // Thymeleaf resolves __${...}__ expressions before template parsing
    // Attacker sends: ?section=__${T(java.lang.Runtime).getRuntime().exec('id')}__::main
    @GetMapping("/doc")
    public String viewDocument(
            @RequestParam String section,
            @RequestParam(defaultValue = "en") String lang,
            Model model) {

        model.addAttribute("lang", lang);
        // VULNERABLE: user-controlled section becomes part of the view name
        // Thymeleaf preprocessing evaluates __${...}__ before resolution
        return "documents/" + section;
    }

    // VULNERABLE: User input in fragment expression with preprocessing
    // Attacker sends: ?module=__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd').getInputStream()).useDelimiter('\\A').next()}__
    @GetMapping("/dashboard")
    public String dashboard(
            @RequestParam(defaultValue = "overview") String module,
            Model model) {

        model.addAttribute("user", "admin");
        // VULNERABLE: module is user-controlled and used in fragment expression
        return "dashboard :: " + module;
    }

    // VULNERABLE: User input rendered directly via TemplateEngine.process()
    // Attacker sends: ?greeting=[[${T(java.lang.Runtime).getRuntime().exec('id')}]]
    @GetMapping("/welcome")
    public void welcome(
            @RequestParam(defaultValue = "Hello!") String greeting,
            HttpServletResponse response) throws IOException {

        Context ctx = new Context();
        ctx.setVariable("appName", "MyApp");

        // VULNERABLE: user input is the template source itself
        String template = "<html><body><h1>" + greeting + "</h1>"
                + "<p>Welcome to <span th:text=\"${appName}\">App</span></p>"
                + "</body></html>";

        String rendered = templateEngine.process(template, ctx);
        response.setContentType("text/html");
        response.getWriter().write(rendered);
    }
}
