<?php
// Fixture: php-htmlspecialchars — htmlspecialchars() with proper flags, Blade {{ $var }}
// Expected: TRUE NEGATIVE (must NOT be flagged)
// CWE: CWE-79
// Agent: xss
// Pattern: htmlspecialchars() with ENT_QUOTES|ENT_SUBSTITUTE, Laravel Blade {{ }} auto-escaping

// SAFE: htmlspecialchars() with ENT_QUOTES encodes <, >, &, ", and '
// The ENT_SUBSTITUTE flag replaces invalid encoding sequences instead of returning empty string
$name = $_GET['name'] ?? 'Guest';
$query = $_GET['q'] ?? '';
$feedback = $_POST['feedback'] ?? '';
?>
<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
    <!-- SAFE: htmlspecialchars() with ENT_QUOTES and explicit charset -->
    <h1>Welcome, <?php echo htmlspecialchars($name, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?></h1>

    <!-- SAFE: htmlspecialchars() on search query -->
    <p>Showing results for: <?php echo htmlspecialchars($query, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?></p>

    <?php if ($feedback): ?>
        <!-- SAFE: htmlspecialchars() on user-submitted feedback -->
        <div class="feedback">
            <p>Your feedback: <?php echo htmlspecialchars($feedback, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?></p>
        </div>
    <?php endif; ?>

    <!-- SAFE: htmlspecialchars() in attribute context with ENT_QUOTES -->
    <input type="text"
           value="<?php echo htmlspecialchars($_GET['search'] ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?>"
           name="search">
</body>
</html>

<?php
// ============================================================
// Laravel Blade safe patterns:
// ============================================================
// SAFE: {{ }} auto-escapes via htmlspecialchars()
// {{ $userInput }}
// {{ $user->name }}
// {{ $comment->body }}
//
// Blade {{ }} calls htmlspecialchars($value, ENT_QUOTES, 'UTF-8', true)
// This is the default and correct Blade output syntax.
//
// Example safe Blade template:
// <div class="bio">{{ $user->bio }}</div>
// <p>Search: {{ $query }}</p>
// <input type="text" value="{{ $searchTerm }}">
//
// For JSON in script contexts:
// <script>var config = @json($config);</script>
// @json() applies json_encode with JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT
?>
