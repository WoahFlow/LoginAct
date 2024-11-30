<?php
session_start();
if (!isset($_SESSION["user_id"]) || $_SESSION["role"] !== "user") {
    header("Location: login.php");
    exit;
}

$mysqli = require __DIR__ . "/database.php";

$user_id = $_SESSION["user_id"];
$name = $_POST["name"];
$email = $_POST["email"];
$password = $_POST["password"];
$confirm_password = $_POST["confirm-password"];

// Validate inputs
if (empty($name)) {
    die("Name is required!");
}
if (empty($email)) {
    die("Email is required!");
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    die("Valid Email is required.");
}
if (!empty($password)) {
    if (strlen($password) < 8) {
        die("Password must be at least 8 characters.");
    }
    if (!preg_match("/[a-z]/i", $password)) {
        die("Password must contain at least one letter.");
    }
    if (!preg_match("/[0-9]/", $password)) {
        die("Password must contain at least one number.");
    }
    if ($password !== $confirm_password) {
        die("Passwords must match.");
    }
}

$password_hash = password_hash($_POST["password"], PASSWORD_DEFAULT);

// Check if the email is already taken by an admin or a user
$sql = "SELECT email FROM users WHERE email = ?";
$stmt = $mysqli->prepare($sql);
$stmt->bind_param("s", $_POST["email"]);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    // Email is already taken, show alert and redirect to signup.html
    echo "<script>alert('Email is already taken. Please try again with a different email.'); window.location.href = 'update-user.php';</script>";
    exit; // Make sure to stop the script after displaying the alert
}

try {
    if (!empty($password)) {
        // Hash the new password
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        $sql = "UPDATE users SET fullname = ?, email = ?, password_hash = ? WHERE id = ?";
        $stmt = $mysqli->prepare($sql);
        $stmt->bind_param("sssi", $name, $email, $password_hash, $user_id);
    } else {
        $sql = "UPDATE users SET fullname = ?, email = ? WHERE id = ?";
        $stmt = $mysqli->prepare($sql);
        $stmt->bind_param("ssi", $name, $email, $user_id);
    }

    if ($stmt->execute()) {
        echo "<script>alert('Your account has been successfully updated!'); window.location.href = 'user-dashboard.php';</script>";
    } else {
        throw new Exception("Error updating record: " . $mysqli->error);
    }
} catch (Exception $e) {
    die($e->getMessage());
}
?>
