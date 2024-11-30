<?php
session_start();
if (!isset($_SESSION["user_id"]) || $_SESSION["role"] !== "user") {
    header("Location: login.php");
    exit;
}

$mysqli = require __DIR__ . "/database.php";

// Fetch current user details
$user_id = $_SESSION["user_id"];
$sql = "SELECT fullname FROM users WHERE id = ?";
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
    <title>User Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
</head>
<body>
    <h1>User Dashboard</h1>
            
          
           <p>Hello <?php echo htmlspecialchars($user['fullname']); ?></p>
           

    <!-- Logout Button -->
    <form action="logout.php" method="post">
        <button type="submit">Logout</button>
    </form>
</body>
</html>
