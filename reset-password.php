<?php
session_start();
// Database Connection
$host = 'localhost';
$user = 'root';
$pass = 'root';
$dbname = 'cloudbox';
$conn = new mysqli($host, $user, $pass, $dbname);
if ($conn->connect_error) die("Database connection failed: " . $conn->connect_error);

$message = "";
$showOTP = false;

// Redirect if no email in session
if (!isset($_SESSION['reset_email']) && !isset($_SESSION['reset_verified'])) {
    header("Location: forgot-password.php");
    exit;
}

// Get email from session
$email = isset($_SESSION['reset_email']) ? $_SESSION['reset_email'] : '';

// If we have a temporary OTP in session, show it (development only)
if (isset($_SESSION['temp_otp'])) {
    $showOTP = true;
    $tempOTP = $_SESSION['temp_otp'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['verify_otp'])) {
        $otp = $conn->real_escape_string($_POST['otp']);
        
        // Verify OTP
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? AND reset_code = ? AND reset_expires > NOW()");
        $stmt->bind_param("ss", $email, $otp);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
            $_SESSION['reset_user_id'] = $user['id'];
            $_SESSION['reset_verified'] = true;
            $message = "<div class='alert alert-success'>Code vérifié avec succès. Vous pouvez maintenant réinitialiser votre mot de passe.</div>";
            
            // Clear temporary OTP from session
            unset($_SESSION['temp_otp']);
        } else {
            $message = "<div class='alert alert-danger'>Code de vérification invalide ou expiré. Veuillez réessayer.</div>";
        }
    }
    
    if (isset($_POST['reset_password']) && isset($_SESSION['reset_verified']) && $_SESSION['reset_verified']) {
        $password = $conn->real_escape_string($_POST['password']);
        $confirm_password = $conn->real_escape_string($_POST['confirm_password']);
        
        if ($password !== $confirm_password) {
            $message = "<div class='alert alert-danger'>Les mots de passe ne correspondent pas.</div>";
        } elseif (strlen($password) < 6) {
            $message = "<div class='alert alert-danger'>Le mot de passe doit comporter au moins 6 caractères.</div>";
        } else {
            $hashedPassword = sha1($password);
            $userId = $_SESSION['reset_user_id'];
            
            $stmt = $conn->prepare("UPDATE users SET password = ?, reset_code = NULL, reset_expires = NULL WHERE id = ?");
            $stmt->bind_param("si", $hashedPassword, $userId);
            
            if ($stmt->execute()) {
                // Clear reset sessions
                unset($_SESSION['reset_user_id']);
                unset($_SESSION['reset_verified']);
                unset($_SESSION['reset_email']);
                
                $message = "<div class='alert alert-success'>Votre mot de passe a été réinitialisé avec succès. Vous pouvez maintenant <a href='index.php'>vous connecter</a> avec votre nouveau mot de passe.</div>";
            } else {
                $message = "<div class='alert alert-danger'>Erreur lors de la réinitialisation du mot de passe. Veuillez réessayer.</div>";
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
    <title>CloudBOX - Réinitialisation du mot de passe</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .form-container {
            max-width: 450px;
            margin: 100px auto;
            padding: 25px;
            background-color: #fff;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
        }
        
        .form-container h2 {
            text-align: center;
            margin-bottom: 20px;
            color: #4f46e5;
        }
        
        .alert {
            margin-bottom: 20px;
        }
        
        .form-control:focus {
            border-color: #4f46e5;
            box-shadow: 0 0 0 0.25rem rgba(79, 70, 229, 0.25);
        }
        
        .btn-primary {
            background-color: #4f46e5;
            border-color: #4f46e5;
        }
        
        .btn-primary:hover {
            background-color: #4338ca;
            border-color: #4338ca;
        }
        
        a {
            color: #4f46e5;
            text-decoration: none;
        }
        
        a:hover {
            text-decoration: underline;
        }
        
        .otp-reminder {
            background-color: #e8f4fd;
            border-left: 4px solid #4f46e5;
            padding: 10px 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="form-container">
        <?php if ($message): ?>
            <?= $message ?>
        <?php endif; ?>
        
        <h2><i class="fas fa-key me-2"></i>Réinitialisation du mot de passe</h2>
        
        <?php if (!isset($_SESSION['reset_verified']) || !$_SESSION['reset_verified']): ?>
            <!-- OTP Verification Form -->
            <p class="text-center mb-4">Entrez le code de vérification envoyé à votre email.</p>
            
            <?php if ($showOTP): ?>
            <div class="otp-reminder">
                <p class="mb-1"><strong>Pour le développement uniquement:</strong></p>
                <p class="mb-0">Votre code de vérification est: <strong><?= $tempOTP ?></strong></p>
            </div>
            <?php endif; ?>
            
            <form method="POST">
                <div class="mb-3">
                    <label for="otp" class="form-label">Code de vérification</label>
                    <input type="text" class="form-control" id="otp" name="otp" required>
                </div>
                <div class="d-grid">
                    <button type="submit" name="verify_otp" class="btn btn-primary">Vérifier le code</button>
                </div>
            </form>
        <?php else: ?>
            <!-- New Password Form -->
            <p class="text-center mb-4">Entrez votre nouveau mot de passe.</p>
            <form method="POST">
                <div class="mb-3">
                    <label for="password" class="form-label">Nouveau mot de passe</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                    <div class="form-text">Le mot de passe doit comporter au moins 6 caractères.</div>
                </div>
                <div class="mb-3">
                    <label for="confirm_password" class="form-label">Confirmer le nouveau mot de passe</label>
                    <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                </div>
                <div class="d-grid">
                    <button type="submit" name="reset_password" class="btn btn-primary">Réinitialiser le mot de passe</button>
                </div>
            </form>
        <?php endif; ?>
        
        <div class="mt-3 text-center">
            <a href="login.php">Retour à la connexion</a>
        </div>
    </div>
    
    <!-- Bootstrap Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
