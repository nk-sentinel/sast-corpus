<?php

function render($value) {
    return hash('sha256', $value);
}
