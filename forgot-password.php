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

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email'])) {
    $email = $conn->real_escape_string($_POST['email']);
    
    // Check if email exists in database
    $stmt = $conn->prepare("SELECT id, username FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        $userId = $user['id'];
        $username = $user['username'];
        
        // Generate OTP code
        $otp = rand(100000, 999999);
        $expires = date('Y-m-d H:i:s', strtotime('+15 minutes'));
        
        // Save OTP to database
        $stmt = $conn->prepare("UPDATE users SET reset_code = ?, reset_expires = ? WHERE id = ?");
        $stmt->bind_param("ssi", $otp, $expires, $userId);
        $stmt->execute();
        
        // Store email in session for the reset page
        $_SESSION['reset_email'] = $email;
        
        // Option 1: Display OTP for development (uncomment for testing)
        /*
        $_SESSION['temp_otp'] = $otp;
        $message = "<div class='alert alert-success'>
            <p>Normalement, un email serait envoyé, mais pour le développement, voici le code:</p>
            <p><strong>Code OTP: $otp</strong></p>
            <p>Ce code expirera dans 15 minutes.</p>
        </div>";
        
        // Redirect to reset password page after showing the code
        echo "<script>
            setTimeout(function() {
                window.location.href = 'reset-password.php';
            }, 5000); // Redirect after 5 seconds
        </script>";
        */
        
        // Option 2: Use Brevo (formerly Sendinblue) to send the email
        require 'vendor/autoload.php'; // Path to Composer's autoloader
        
        // Configure API key authorization
        $config = SendinBlue\Client\Configuration::getDefaultConfiguration()
            ->setApiKey('api-key', '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');
        
        $apiInstance = new SendinBlue\Client\Api\TransactionalEmailsApi(
            new GuzzleHttp\Client(),
            $config
        );
        
        // Set up the email
        $sendSmtpEmail = new \SendinBlue\Client\Model\SendSmtpEmail();
        $sendSmtpEmail->setSubject('CloudBOX - Réinitialisation de mot de passe');
        $sendSmtpEmail->setSender(new \SendinBlue\Client\Model\SendSmtpEmailSender([
            'name' => 'CloudBOX',
            'email' => 'noreply@cloudbox.com'
        ]));
        $sendSmtpEmail->setTo([
            ['email' => $email, 'name' => $username]
        ]);
        
        $email_content = "Bonjour $username,\n\n";
        $email_content .= "Vous avez demandé à réinitialiser votre mot de passe. Votre code de vérification est: $otp\n\n";
        $email_content .= "Ce code expirera dans 15 minutes.\n\n";
        $email_content .= "Si vous n'avez pas demandé cette réinitialisation, veuillez ignorer cet email.\n\n";
        $email_content .= "Cordialement,\nL'équipe CloudBOX";
        
        $sendSmtpEmail->setTextContent($email_content);
        
        try {
            $result = $apiInstance->sendTransacEmail($sendSmtpEmail);
            $message = "<div class='alert alert-success'>Un code de vérification a été envoyé à votre adresse email. Veuillez vérifier votre boîte de réception.</div>";
            header("Location: reset-password.php");
            exit;
        } catch (Exception $e) {
            $message = "<div class='alert alert-danger'>Erreur d'envoi d'email: " . $e->getMessage() . "</div>";
        }
    } else {
        // Don't reveal that email doesn't exist for security
        $message = "<div class='alert alert-info'>Si votre adresse email existe dans notre base de données, vous recevrez un code de récupération de mot de passe sous peu.</div>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudBOX - Forgot Password</title>
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
    </style>
</head>
<body>
    <div class="form-container">
        <?php if ($message): ?>
            <?= $message ?>
        <?php endif; ?>
        
        <h2><i class="fas fa-lock-open me-2"></i>Mot de passe oublié</h2>
        <p class="text-center mb-4">Entrez votre adresse email et nous vous enverrons un code de vérification pour réinitialiser votre mot de passe.</p>
        
        <form method="POST">
            <div class="mb-3">
                <label for="email" class="form-label">Adresse Email</label>
                <input type="email" class="form-control" id="email" name="email" required>
            </div>
            <div class="d-grid">
                <button type="submit" class="btn btn-primary">Envoyer le code de vérification</button>
            </div>
        </form>
        
        <div class="mt-3 text-center">
            <a href="index.php">Retour à la connexion</a>
        </div>
    </div>
    
    <!-- Bootstrap Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
