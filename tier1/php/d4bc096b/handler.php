<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

require_once __DIR__ . '/runner.php';

Route::get('/show', function (Request $request) {
    return show($request->query('name', ''));
});

function show($name) {
    return archive($name);
}
