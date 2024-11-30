<?php
session_start();
if (!isset($_SESSION["user_id"]) || $_SESSION["role"] !== "admin") {
    header("Location: login.php");
    exit;
}

$mysqli = require __DIR__ . "/database.php";

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["user_id"])) {
    $user_id = $_POST["user_id"];

    // Delete user query
    $sql = "DELETE FROM users WHERE id = ?";
    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param("i", $user_id);

    if ($stmt->execute()) {
        header("Location: admin-dashboard.php");
        exit;
    } else {
        echo "Error: Could not delete user.";
    }
} else {
    echo "Invalid request.";
}
?>
