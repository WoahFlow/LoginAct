<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/water.css">
</head>
<body>
    <h1>Login</h1>
    <form action="process-login.php" method="post">
        <div>
            <input type="email" id="email" name="email" placeholder="Email Address" required>
        </div>
        <div>
            <input type="password" id="password" name="password" placeholder="Password" required>
        </div>
        <button type="submit">Login</button>
    </form>
    <form action="signup.html" method="post">
        <button type="submit">Signup</button>
    </form>
</body>
</html>
