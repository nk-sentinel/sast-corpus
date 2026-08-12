<?php

require __DIR__ . '/vendor/autoload.php';

function load($url) {
    $client = new GuzzleHttp\Client(['allow_redirects' => true]);
    return (string) $client->get($url)->getBody();
}
