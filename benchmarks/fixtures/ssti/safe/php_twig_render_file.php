<?php
// Fixture: php-twig-render-file — Twig render() with file template, user data as variables
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-1336
// Agent: ssti
// Pattern: Template loaded from file via Twig render(), user input only flows as template variables

require_once __DIR__ . '/vendor/autoload.php';

use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;

$loader = new FilesystemLoader(__DIR__ . '/templates');
$twig = new Environment($loader, [
    'cache' => __DIR__ . '/cache',
    'auto_reload' => true,
    'autoescape' => 'html',
]);

$request = Request::createFromGlobals();
$route = $request->getPathInfo();

// SAFE: Twig render() loads template from file, user input is variable data only
// Twig autoescaping prevents XSS; template structure is developer-controlled
if ($route === '/profile') {
    $username = $request->query->get('username', 'Guest');
    $bio = $request->query->get('bio', 'No bio provided');
    $role = $request->query->get('role', 'member');

    // SAFE: template loaded from templates/profile.html.twig, user input as variables
    $rendered = $twig->render('profile.html.twig', [
        'username' => $username,
        'bio' => $bio,
        'role' => $role,
    ]);

    $response = new Response($rendered);
    $response->send();

} elseif ($route === '/api/render-block') {
    $data = json_decode($request->getContent(), true);
    $blockTitle = $data['title'] ?? 'Block';
    $blockContent = $data['content'] ?? 'Empty block';
    $blockType = $data['type'] ?? 'default';

    // SAFE: template from file, user content is a variable (auto-escaped)
    $rendered = $twig->render('block.html.twig', [
        'title' => $blockTitle,
        'content' => $blockContent,
        'type' => $blockType,
    ]);

    $response = new Response($rendered, 200, ['Content-Type' => 'text/html']);
    $response->send();

} elseif ($route === '/search') {
    $query = $request->query->get('q', '');
    $page = (int) $request->query->get('page', 1);

    // Simulate search results
    $results = [];
    for ($i = 1; $i <= 10; $i++) {
        $results[] = [
            'title' => "Result $i",
            'snippet' => "Match for '$query'...",
            'url' => "/item/$i",
        ];
    }

    // SAFE: file template with user data as variables
    $rendered = $twig->render('search_results.html.twig', [
        'query' => $query,
        'results' => $results,
        'page' => $page,
        'total_pages' => 10,
    ]);

    $response = new Response($rendered);
    $response->send();
}
