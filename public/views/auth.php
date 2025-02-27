<?php

// Get the JSON
$input = file_get_contents('php://input');
// Decode the JSON data into a PHP associative array
$data = json_decode($input, true);

// Verify JSON is OK
if (json_last_error() !== JSON_ERROR_NONE) {
    echo json_encode(['status' => 'error', 'message' => 'JSON format not valid']);
    return;
}

if (AuthController::auth($data["username"], $data["password"])) {
    echo "OK!";
} else {
    echo "KO!";
}



