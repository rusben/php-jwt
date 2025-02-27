<?php

require_once "../../vendor/autoload.php";

session_start();

if (SessionController::isLoggedIn()) {
    echo "OK";
} else {
    header('Location: /login');
    die();
}
