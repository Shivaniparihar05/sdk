<?php

$secret = 'your-env-secret';

$requestMethod = $_SERVER['REQUEST_METHOD'] ?? '';
$receivedHmac = $_SERVER['HTTP_X_CS_SIGNATURE'] ?? '';
$timestamp = $_SERVER['HTTP_X_CS_TIMESTAMP'] ?? '';
$url = $_SERVER['REQUEST_URI'];
$body = file_get_contents('php://input');

$data = $requestMethod . $url . $timestamp . $body;
$hmac = hash_hmac('sha256', $data, $secret);

$isValid = hash_equals($hmac, $receivedHmac);

if (!$isValid) {
    // Invalid webhook signature, ignore the request.
    die();
}

$webhook = json_decode($body);

file_put_contents('php://stdout', 'Webhook event received: ' . print_r($webhook, true) . "\r\n");
