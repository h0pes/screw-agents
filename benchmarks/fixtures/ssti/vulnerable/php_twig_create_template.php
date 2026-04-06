<?php
// Fixture: php-twig-create-template — Twig createTemplate() with user input
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-1336
// Agent: ssti
// Pattern: User input passed as template source to Twig createTemplate() or Environment::createTemplate()

require_once __DIR__ . '/vendor/autoload.php';

use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

$loader = new FilesystemLoader(__DIR__ . '/templates');
$twig = new Environment($loader, [
    'cache' => __DIR__ . '/cache',
    'auto_reload' => true,
]);

$request = Request::createFromGlobals();

// VULNERABLE: User-controlled template source passed to createTemplate()
// Attacker sends: ?bio={{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
// (Twig 1.x) or other Twig-specific gadgets
$route = $request->getPathInfo();

if ($route === '/profile') {
    $username = $request->query->get('username', 'Guest');
    $bio = $request->query->get('bio', '<p>No bio provided</p>');

    // VULNERABLE: bio from query parameter is the template source
    $template = $twig->createTemplate(
        '<div class="profile">' .
        '<h1>' . $username . '</h1>' .
        '<div class="bio">' . $bio . '</div>' .
        '</div>'
    );

    $response = new Response($template->render([
        'username' => $username,
    ]));
    $response->send();

} elseif ($route === '/api/render-block') {
    // VULNERABLE: CMS block content from POST body rendered as Twig template
    // Attacker sends: {"content": "{{app.request.server.all|join(',')}}"}
    $data = json_decode($request->getContent(), true);
    $blockContent = $data['content'] ?? '<p>Empty block</p>';
    $blockTitle = $data['title'] ?? 'Block';

    // VULNERABLE: blockContent is user-controlled and becomes template source
    $template = $twig->createTemplate(
        '<section>' .
        '<h2>{{ title }}</h2>' .
        $blockContent .
        '</section>'
    );

    $rendered = $template->render([
        'title' => $blockTitle,
    ]);

    $response = new Response($rendered, 200, ['Content-Type' => 'text/html']);
    $response->send();
}
