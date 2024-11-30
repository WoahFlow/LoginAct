<?php
session_start();
if (!isset($_SESSION["user_id"]) || $_SESSION["role"] !== "admin") {
    header("Location: login.php");
    exit;
}

$mysqli = require __DIR__ . "/database.php";

// Fetch current admin details
$user_id = $_SESSION["user_id"];
$sql = "SELECT fullname, email, password_hash FROM users WHERE id = ?";
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
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
</head>
<body>
    <h1>Admin Dashboard</h1>

    <!-- Current Admin Info -->
    <h2>Admin Information</h2>
    <table>
        <tr>
            <th>Name</th>
            <th>Email</th>
            <th>Password (Hashed)</th>
        </tr>
        <tr>
            <td><?php echo htmlspecialchars($user['fullname']); ?></td>
            <td><?php echo htmlspecialchars($user['email']); ?></td>
            <td><?php echo htmlspecialchars($user['password_hash']); ?></td>
        </tr>
    </table>

    <!-- User Management -->
    <h2>Manage Users</h2>
    <table>
        <thead>
            <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Password (Hashed)</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php
            $mysqli = require __DIR__ . "/database.php";
            $result = $mysqli->query("SELECT id, fullname, email, password_hash FROM users WHERE role ='user'");

            while ($user = $result->fetch_assoc()) {
                echo "<tr>";
                echo "<td>" . htmlspecialchars($user["fullname"]) . "</td>";
                echo "<td>" . htmlspecialchars($user["email"]) . "</td>";
                echo "<td>" . htmlspecialchars($user["password_hash"]) . "</td>";
                echo "<td>
                    <form action='admin-edit-user.php' method='post' style='display:inline;'>
                        <input type='hidden' name='user_id' value='" . $user["id"] . "'>
                        <button type='submit'>Edit</button>
                    </form>

                     <form action='admin-delete-user.php' method='post' style='display:inline;'>
                    <input type='hidden' name='user_id' value='" . $user["id"] . "'>
                    <button type='submit' onclick='return confirm(\"Are you sure you want to delete this user?\");'>Delete</button>
                </form>
                
                </td>";
                echo "</tr>";
            }
            ?>
        </tbody>
    </table>

     <!-- Logout Button -->
     <form action="logout.php" method="post">
        <button type="submit">Logout</button>
    </form>
</body>
</html>
