<?php
$mysqli = require __DIR__ . "/database.php";

if (empty($_POST["user_id"])) {
    die("Invalid User ID");
}

$sql = "SELECT fullname, email FROM users WHERE id = ?";
$stmt = $mysqli->stmt_init();

if (!$stmt->prepare($sql)) {
    die("SQL error: " . $mysqli->error);
}

$stmt->bind_param("i", $_POST["user_id"]);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

if (!$user) {
    die("User not found");
}
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Edit User</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
</head>
<body>
    <h1>Edit User</h1>
    <form action="process-admin-update.php" method="post">
        <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($_POST['user_id']); ?>">
        <div>
            <label for="name">Full Name:</label>
            <input type="text" id="name" name="name" value="<?php echo htmlspecialchars($user['fullname']); ?>" required>
        </div>
        <div>
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($user['email']); ?>" required>
        </div>
        <div>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" placeholder="Enter new password">
        </div>
        <div>
            <label for="password">Confirm Password:</label>
            <input type="password" id="confirm-password" name="confirm-password" placeholder="confirm password" require>
        </div>
        <button type="submit">Update</button>
    </form>
</body>
</html>
