<?php
session_start();
if (!isset($_SESSION["user_id"]) || $_SESSION["role"] !== "admin") {
    header("Location: login.php");
    exit;
}

$mysqli = require __DIR__ . "/database.php";

// Fetch current user details
$user_id = $_SESSION["user_id"];
$sql = "SELECT fullname, email FROM users WHERE id = ?";
$stmt = $mysqli->prepare($sql);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

if (!$user) {
    die("User not found.");
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Update Information</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
</head>
<body>
    <h1>Update Your Information</h1>
    <form action="process-admin-update.php" method="post">
        <div>
            <label for="name">Full Name:</label>
            <input type="text" id="name" name="name" placeholder="Enter new Full Name" required>
        </div>
        <div>
            <label for="email">Email:</label>
            <input type="email" id="email" name="email"  placeholder="Enter new email" required>
        </div>
        <div>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" placeholder="Enter new password" require>
        </div>
        <div>
            <label for="password">Password:</label>
            <input type="password" id="confirm-password" name="confirm-password" placeholder="confirm password" require>
        </div>
        <button type="submit">Save Changes</button>
    </form>
</body>
</html>
