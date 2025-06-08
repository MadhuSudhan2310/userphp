<?php
// Database configuration
$db_host = 'localhost';
$db_username = 'root';
$db_password = '';
$db_name = 'user_registration';

// Connect to database
$conn = new mysqli($db_host, $db_username, $db_password, $db_name);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Initialize variables
$username = $email = $password = $full_name = $phone = '';
$errors = array();

// Process form when submitted
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Validate and sanitize inputs
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);
    $full_name = trim($_POST['full_name']);
    $phone = trim($_POST['phone']);
    
    // Validation checks
    if (empty($username)) {
        $errors['username'] = 'Username is required';
    } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
        $errors['username'] = 'Username can only contain letters, numbers, and underscores';
    } elseif (strlen($username) < 4) {
        $errors['username'] = 'Username must be at least 4 characters';
    }
    
    if (empty($email)) {
        $errors['email'] = 'Email is required';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors['email'] = 'Email is invalid';
    }
    
    if (empty($password)) {
        $errors['password'] = 'Password is required';
    } elseif (strlen($password) < 6) {
        $errors['password'] = 'Password must be at least 6 characters';
    }
    
    if (empty($full_name)) {
        $errors['full_name'] = 'Full name is required';
    }
    
    // If no errors, proceed with registration
    if (empty($errors)) {
        // Check if username or email already exists
        $check_query = "SELECT * FROM user_registration WHERE username=? OR email=? LIMIT 1";
        $stmt = $conn->prepare($check_query);
        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            if ($user['username'] === $username) {
                $errors['username'] = 'Username already exists';
            }
            if ($user['email'] === $email) {
                $errors['email'] = 'Email already exists';
            }
        }
        
        // If still no errors, insert new user
        if (empty($errors)) {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            
            $insert_query = "INSERT INTO user_registration (username, email, password, full_name, phone) 
                            VALUES (?, ?, ?, ?, ?)";
            $stmt = $conn->prepare($insert_query);
            $stmt->bind_param("sssss", $username, $email, $hashed_password, $full_name, $phone);
            
            if ($stmt->execute()) {
                // Registration successful
                header('Location: success.php');
                exit();
            } else {
                $errors['database'] = 'Registration failed: ' . $conn->error;
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Form</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input { width: 100%; padding: 8px; box-sizing: border-box; }
        .error { color: red; font-size: 14px; margin-top: 5px; }
        button { background: #4CAF50; color: white; padding: 10px 15px; border: none; cursor: pointer; }
        button:hover { background: #45a049; }
    </style>
</head>
<body>
    <h2>Registration Form</h2>
    
    <?php if (!empty($errors['database'])): ?>
        <div class="error"><?php echo $errors['database']; ?></div>
    <?php endif; ?>
    
    <form action="sign.php" method="post">
        <div class="form-group">
            <label for="username">Username*</label>
            <input type="text" name="username" id="username" value="<?php echo htmlspecialchars($username); ?>" required>
            <?php if (!empty($errors['username'])): ?>
                <div class="error"><?php echo $errors['username']; ?></div>
            <?php endif; ?>
        </div>
        
        <div class="form-group">
            <label for="email">Email*</label>
            <input type="email" name="email" id="email" value="<?php echo htmlspecialchars($email); ?>" required>
            <?php if (!empty($errors['email'])): ?>
                <div class="error"><?php echo $errors['email']; ?></div>
            <?php endif; ?>
        </div>
        
        <div class="form-group">
            <label for="password">Password*</label>
            <input type="password" name="password" id="password" required>
            <?php if (!empty($errors['password'])): ?>
                <div class="error"><?php echo $errors['password']; ?></div>
            <?php endif; ?>
        </div>
        
        <div class="form-group">
            <label for="full_name">Full Name*</label>
            <input type="text" name="full_name" id="full_name" value="<?php echo htmlspecialchars($full_name); ?>" required>
            <?php if (!empty($errors['full_name'])): ?>
                <div class="error"><?php echo $errors['full_name']; ?></div>
            <?php endif; ?>
        </div>
        
        <div class="form-group">
            <label for="phone">Phone Number</label>
            <input type="tel" name="phone" id="phone" value="<?php echo htmlspecialchars($phone); ?>">
        </div>
        
        <button type="submit">Register</button>
    </form>
</body>
</html>