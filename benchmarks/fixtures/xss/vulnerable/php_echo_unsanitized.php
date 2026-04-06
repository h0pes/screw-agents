<?php
// Fixture: php-echo-unsanitized — echo $_GET without htmlspecialchars(), Blade {!! !!}
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-79
// Agent: xss
// Pattern: Direct echo/print of $_GET/$_POST/$_REQUEST without HTML encoding

// VULNERABLE: $_GET echoed directly without htmlspecialchars()
// Attacker sends: ?name=<script>alert(document.cookie)</script>
$name = $_GET['name'] ?? 'Guest';
$query = $_GET['q'] ?? '';
?>
<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
    <!-- VULNERABLE: PHP echo with unescaped user input -->
    <h1>Welcome, <?php echo $name; ?></h1>

    <!-- VULNERABLE: shorthand echo tag with unescaped input -->
    <p>Showing results for: <?= $query ?></p>

    <?php
    // VULNERABLE: print() with string concatenation of user input
    // Attacker sends: ?feedback=<img src=x onerror=alert(1)>
    $feedback = $_POST['feedback'] ?? '';
    if ($feedback) {
        print("<div class='feedback'><p>Your feedback: " . $feedback . "</p></div>");
    }
    ?>

    <!-- VULNERABLE: user input in HTML attribute without encoding -->
    <!-- Attacker sends: ?search=" onfocus="alert(1)" autofocus=" -->
    <input type="text" value="<?php echo $_GET['search'] ?? ''; ?>" name="search">
</body>
</html>

<?php
// ============================================================
// Laravel Blade equivalent vulnerability:
// ============================================================
// In a Blade template (.blade.php):
//
// VULNERABLE: {!! !!} outputs raw HTML without escaping
// {!! $userInput !!}
//
// SAFE: {{ }} auto-escapes via htmlspecialchars()
// {{ $userInput }}
//
// Example vulnerable Blade template:
// <div class="bio">{!! $user->bio !!}</div>
// <div class="comment">{!! $comment->body !!}</div>
// <script>var config = {!! json_encode($config) !!};</script>
//
// The {!! !!} syntax is the Blade equivalent of echo without htmlspecialchars().
// Developers use it for "trusted" HTML that is often actually user-controlled.
?>
