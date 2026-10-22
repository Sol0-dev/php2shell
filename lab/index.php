<?php
// lab index.php - session poison + LFI chain target. LAB_MODE guard required.
if (getenv('LAB_MODE') !== 'true') { http_response_code(403); exit('Lab only'); }
session_start();
if (isset($_GET['page'])) {
    include($_GET['page']);
} else {
    echo "PHP " . phpversion() . " | session.upload_progress.enabled=" . ini_get('session.upload_progress.enabled');
}
