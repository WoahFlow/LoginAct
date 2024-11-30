<?php
session_start();
$mysqli = require __DIR__ . "/database.php";

if (!isset($_GET['token'])) {
    die("Invalid verification link.");
}

$verification_token = $_GET['token'];

// Check if the token exists in the database
$sql = "SELECT id, fullname, email FROM users WHERE verification_token = ? AND is_verified = 0";
$stmt = $mysqli->prepare($sql);
$stmt->bind_param("s", $verification_token);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

if (!$user) {
    die("Invalid or expired verification link.");
}

// Mark the user as verified
$sql = "UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?";
$stmt = $mysqli->prepare($sql);
$stmt->bind_param("i", $user['id']);

if ($stmt->execute()) {
    // Log the user in by setting session variables
    $_SESSION["user_id"] = $user['id'];
    $_SESSION["role"] = "user";
    
    // Redirect to the user dashboard
    header("Location: user-dashboard.php");
    exit;
} else {
    die("Error verifying email: " . $mysqli->error);
}
?>
