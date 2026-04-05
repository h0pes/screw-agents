<?php
// Fixture: php-wpdb-no-prepare + php-query-interp — WordPress and PDO injection
// Expected: TRUE POSITIVE (high confidence)
// CWE: CWE-89
// Pattern: $wpdb->query without prepare(), mysqli_query with interpolation

// VULNERABLE: WordPress $wpdb without prepare()
function get_user_by_id() {
    global $wpdb;
    $id = $_GET['id'];
    // Missing $wpdb->prepare() — direct variable interpolation
    $results = $wpdb->get_results(
        "SELECT * FROM {$wpdb->prefix}users WHERE id = $id"
    );
    return $results;
}

// VULNERABLE: mysqli_query with variable interpolation
function search_products($conn) {
    $search = $_GET['search'];
    // Direct variable interpolation in double-quoted string
    $result = mysqli_query($conn,
        "SELECT * FROM products WHERE name LIKE '%$search%'"
    );
    return $result;
}

// VULNERABLE: PDO query without prepare
function get_user_pdo($pdo) {
    $email = $_POST['email'];
    // String concatenation in query()
    $stmt = $pdo->query(
        "SELECT * FROM users WHERE email = '" . $email . "'"
    );
    return $stmt->fetchAll();
}

// VULNERABLE: Laravel DB::raw with user input
use Illuminate\Support\Facades\DB;

function sorted_users() {
    $sort = request()->input('sort');
    // DB::raw passes string directly to SQL
    return DB::table('users')
        ->orderByRaw(DB::raw($sort))
        ->get();
}
