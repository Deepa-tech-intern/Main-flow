<?php
session_start();
include 'includes/db.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Validate inputs
    if (empty($username) || empty($password)) {
        die("All fields are required.");
    }

    // Fetch user from the database
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = :username OR email = :username");
    $stmt->bindParam(':username', $username);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        header("Location: index.html");
        exit();
    } else {
        die("Invalid credentials. <a href='login.html'>Try again</a>");
    }
}
?>