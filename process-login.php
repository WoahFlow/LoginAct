<?php
session_start();
$mysqli = require __DIR__ . "/database.php";

// Validate email and password
if (empty($_POST["email"]) || empty($_POST["password"])) {
    die("Email and Password are required!");
}

$sql = "SELECT id, fullname, email, password_hash, role FROM users WHERE email = ?";
$stmt = $mysqli->stmt_init();

if (!$stmt->prepare($sql)) {
    die("SQL error: " . $mysqli->error);
}

$stmt->bind_param("s", $_POST["email"]);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

if ($user && password_verify($_POST["password"], $user["password_hash"])) {
    // Store user information in the session
    $_SESSION["user_id"] = $user["id"];
    $_SESSION["fullname"] = $user["fullname"];
    $_SESSION["role"] = $user["role"];

    // Redirect based on role
    if ($user["role"] === "admin") {
        header("Location: admin-dashboard.php");
    } else {
        header("Location: user-dashboard.php");
    }
    exit;
} else {
    die("Invalid email or password!");
}
?>
