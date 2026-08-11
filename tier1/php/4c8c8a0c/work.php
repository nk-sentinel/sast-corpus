<?php

function render($name) {
    $target = realpath('/srv/reports/' . basename($name));
    if ($target === false || strpos($target, '/srv/reports/') !== 0) {
        throw new InvalidArgumentException($name);
    }
    return file_get_contents($target);
}
