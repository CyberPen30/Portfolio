<?php
/**
 * Secure vulnerable_script.php
 * Purpose: Remediation for INT310 Lab 2
 * Security improvements:
 * - Input validation & sanitization (CWE-20)
 * - SQL injection protection via prepared statements
 * - Strong password hashing (password_hash, password_verify)
 * - Secure session handling
 * - Secure file upload (whitelist + size limits + storage outside webroot)
 * - Output escaping (XSS prevention)
 * - Removed insecure session_id from GET
 * - Logging hardened (no raw user input)
 */

session_start();

// --------------------------- Database Connection ---------------------------
try {
    $pdo = new PDO("mysql:host=localhost;dbname=enterprise_app;charset=utf8mb4", "admin", "SuperSecurePassword123!", [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false
    ]);
} catch (PDOException $e) {
    die("Database connection error. Please try again later.");
}

// --------------------------- Helper Functions ---------------------------
function sanitize_output($s) {
    return htmlspecialchars($s ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function safe_filename($name) {
    return preg_replace('/[^A-Za-z0-9._-]/', '_', basename($name));
}

// --------------------------- Registration ---------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register'])) {
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $email    = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];

    if (!$username || !$email || strlen($password) < 8) {
        $error = "Invalid input. Ensure username/email are valid and password ≥ 8 characters.";
    } else {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        if ($stmt->execute([$username, $email, $hashed_password])) {
            session_regenerate_id(true);
            $_SESSION['user_id']  = $pdo->lastInsertId();
            $_SESSION['username'] = $username;
            $_SESSION['role']     = 'user';
            $success = "Registration successful.";
        } else {
            $error = "Registration failed.";
        }
    }
}

// --------------------------- Login ---------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $password = $_POST['password'];

    $stmt = $pdo->prepare("SELECT id, username, role, password FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password'])) {
        session_regenerate_id(true);
        $_SESSION['user_id']  = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role']     = $user['role'];
        $success = "Welcome, " . sanitize_output($user['username']);
    } else {
        $error = "Invalid username or password.";
    }
}

// --------------------------- Profile Update ---------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    $user_id = $_SESSION['user_id'] ?? 0;
    $bio     = filter_input(INPUT_POST, 'bio', FILTER_SANITIZE_STRING);
    $website = filter_input(INPUT_POST, 'website', FILTER_SANITIZE_URL);

    if ($user_id) {
        $stmt = $pdo->prepare("UPDATE user_profiles SET bio = ?, website = ? WHERE user_id = ?");
        if ($stmt->execute([$bio, $website, $user_id])) {
            $success = "Profile updated.";
        } else {
            $error = "Profile update failed.";
        }
    } else {
        $error = "Not authenticated.";
    }
}

// --------------------------- File Upload ---------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['user_file'])) {
    $user_id = $_SESSION['user_id'] ?? 0;
    $file    = $_FILES['user_file'];

    if ($user_id && $file['error'] === UPLOAD_ERR_OK) {
        $allowed = ['jpg', 'jpeg', 'png', 'pdf', 'txt'];
        $ext     = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (in_array($ext, $allowed) && $file['size'] <= 5 * 1024 * 1024) {
            $new_name = bin2hex(random_bytes(8)) . "." . $ext;
            $storage  = "/opt/lampp/private_uploads/";
            if (!is_dir($storage)) mkdir($storage, 0750, true);

            if (move_uploaded_file($file['tmp_name'], $storage . $new_name)) {
                $success = "File uploaded successfully.";
                $stmt = $pdo->prepare("INSERT INTO user_files (user_id, original_name, stored_name) VALUES (?, ?, ?)");
                $stmt->execute([$user_id, safe_filename($file['name']), $new_name]);
            } else {
                $error = "File upload failed.";
            }
        } else {
            $error = "Invalid file type or size exceeded.";
        }
    } else {
        $error = "Upload error or not authenticated.";
    }
}

// --------------------------- Search ---------------------------
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['search'])) {
    $search_term = filter_input(INPUT_GET, 'search', FILTER_SANITIZE_STRING);
    $stmt = $pdo->prepare("SELECT name, price FROM products WHERE name LIKE ?");
    $stmt->execute(["%$search_term%"]);
    $search_results = $stmt->fetchAll();
}

// --------------------------- Admin Panel ---------------------------
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['admin_action'])) {
    if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin') {
        $action = filter_input(INPUT_GET, 'admin_action', FILTER_SANITIZE_STRING);

        if ($action === 'list_users') {
            $users = $pdo->query("SELECT id, username, email, role FROM users")->fetchAll();
        }

        if ($action === 'view_logs') {
            $log_file = basename($_GET['log_file'] ?? 'app.log');
            $log_path = "/opt/lampp/logs/app/" . $log_file;
            $log_content = file_exists($log_path) ? file_get_contents($log_path) : "Log not found.";
        }
    }
}

// --------------------------- Password Reset ---------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reset_password'])) {
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    if ($email) {
        $token   = bin2hex(random_bytes(16));
        $expires = date('Y-m-d H:i:s', time() + 3600);
        $stmt = $pdo->prepare("UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?");
        $stmt->execute([$token, $expires, $email]);
        // In real system, email would be sent — here log instead
        error_log("Password reset link: https://example.com/reset?token=$token&email=$email");
        $success = "If the email exists, a reset link was sent.";
    }
}

// --------------------------- XML Processing ---------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['xml_data'])) {
    $xml_data = $_POST['xml_data'];
    $dom = new DOMDocument();
    $ok = @$dom->loadXML($xml_data, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
    $xml_result = $ok ? simplexml_import_dom($dom) : null;
}

// --------------------------- Logout ---------------------------
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header("Location: vulnerable_script.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Enterprise Web App (Patched)</title>
</head>
<body>
    <h1>Enterprise Web App (Patched)</h1>

    <?php if (!isset($_SESSION['user_id'])): ?>
        <h2>Login</h2>
        <?php if (isset($error)) echo "<p style='color:red'>" . sanitize_output($error) . "</p>"; ?>
        <?php if (isset($success)) echo "<p style='color:green'>" . sanitize_output($success) . "</p>"; ?>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit" name="login">Login</button>
        </form>

        <h2>Register</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="email" name="email" placeholder="Email" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit" name="register">Register</button>
        </form>
    <?php else: ?>
        <h2>Welcome, <?php echo sanitize_output($_SESSION['username']); ?></h2>
        <?php if (isset($error)) echo "<p style='color:red'>" . sanitize_output($error) . "</p>"; ?>
        <?php if (isset($success)) echo "<p style='color:green'>" . sanitize_output($success) . "</p>"; ?>

        <h3>Update Profile</h3>
        <form method="POST">
            <textarea name="bio" placeholder="Bio"></textarea><br>
            <input type="text" name="website" placeholder="Website"><br>
            <button type="submit" name="update_profile">Update Profile</button>
        </form>

        <h3>Upload File</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="user_file" required><br>
            <button type="submit">Upload</button>
        </form>

        <h3>Search Products</h3>
        <form method="GET">
            <input type="text" name="search" value="<?php echo sanitize_output($_GET['search'] ?? ''); ?>">
            <button type="submit">Search</button>
        </form>
        <?php if (!empty($search_results)): ?>
            <ul>
            <?php foreach ($search_results as $row): ?>
                <li><?php echo sanitize_output($row['name']); ?> - $<?php echo sanitize_output($row['price']); ?></li>
            <?php endforeach; ?>
            </ul>
        <?php endif; ?>

        <?php if ($_SESSION['role'] === 'admin'): ?>
            <h3>Admin Panel</h3>
            <a href="?admin_action=list_users">List Users</a> | 
            <a href="?admin_action=view_logs&log_file=app.log">View Logs</a>

            <?php if (!empty($users)): ?>
                <ul>
                <?php foreach ($users as $u): ?>
                    <li><?php echo sanitize_output($u['username']); ?> (<?php echo sanitize_output($u['email']); ?>)</li>
                <?php endforeach; ?>
                </ul>
            <?php endif; ?>

            <?php if (!empty($log_content)): ?>
                <pre><?php echo sanitize_output($log_content); ?></pre>
            <?php endif; ?>
        <?php endif; ?>

        <h3>Password Reset</h3>
        <form method="POST">
            <input type="email" name="email" placeholder="Enter your email">
            <button type="submit" name="reset_password">Reset Password</button>
        </form>

        <h3>XML Input</h3>
        <form method="POST">
            <textarea name="xml_data" placeholder="<root>...</root>"></textarea><br>
            <button type="submit">Submit XML</button>
        </form>

        <p><a href="?logout=1">Logout</a></p>
    <?php endif; ?>
</body>
</html>
