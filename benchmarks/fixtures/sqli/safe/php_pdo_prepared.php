<?php
// Fixture: Safe parameterized queries — PHP
// Expected: TRUE NEGATIVE (must NOT be flagged)
// Pattern: PDO prepare/execute, $wpdb->prepare(), Laravel Eloquent

// SAFE: PDO prepared statement with named parameters
function get_user_pdo($pdo) {
    $id = $_GET['id'];
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute(['id' => $id]);
    return $stmt->fetch();
}

// SAFE: PDO prepared statement with positional parameters
function search_users_pdo($pdo) {
    $query = $_GET['q'];
    $stmt = $pdo->prepare("SELECT * FROM users WHERE name LIKE ?");
    $stmt->execute(["%$query%"]);
    return $stmt->fetchAll();
}

// SAFE: WordPress $wpdb->prepare()
function get_user_wp() {
    global $wpdb;
    $id = $_GET['id'];
    $results = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}users WHERE id = %d",
            $id
        )
    );
    return $results;
}

// SAFE: Laravel Eloquent — auto-parameterized query builder
use App\Models\User;
use Illuminate\Http\Request;

function search_laravel(Request $request) {
    $query = $request->input('q');
    return User::where('name', 'like', "%{$query}%")->get();
}

// SAFE: Laravel query builder with bindings
function filter_laravel(Request $request) {
    $status = $request->input('status');
    return DB::table('users')
        ->where('status', '=', $status)
        ->get();
}
