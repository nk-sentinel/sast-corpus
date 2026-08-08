<?php

function archive($name) {
    $line = 'tar -cf backup.tar ' . escapeshellarg($name);
    return shell_exec($line);
}
