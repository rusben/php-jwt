<?php

require_once "../vendor/autoload.php";

$path = explode('/', trim( $_SERVER['REQUEST_URI']));
$views = '/views/';


// SessionController::userSignUp("rusben", "rusben@elpuig.xeill.net", "password");
// die();
// SessionController::userLogin("rusben", "password");
// print_r($_SESSION);


switch ($path[1]) {
    case '':
    case '/':
    case 'login':
        if (SessionController::isLoggedIn()) {
            redirect("/admin");
        } else {
            require __DIR__ . $views . 'login.php';
        }
        
        break;

    case 'admin':
        if (SessionController::isLoggedIn()) {
            require __DIR__ . $views . 'admin.php';
        } else {
            redirect("/");
        }

        break;
    
    case 'auth':
        require __DIR__ . $views . 'auth.php';
        break;

    case 'logout':
        require __DIR__ . $views . 'logout.php';
        redirect("/");
        break;

    case 'not-found':
    default:
        http_response_code(404);
        require __DIR__ . $views . '404.php';
}

function redirect($url)
{
   header('Location: ' . $url);
   die();
}