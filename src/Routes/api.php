<?php


use Illuminate\Support\Facades\Route;
use Firauth\Http\Controllers\AuthController;

$prefix  = config('firauth.routes.prefix', 'firauth');
$expose  = config('firauth.routes.expose');

Route::prefix($prefix)->group(function () use ($expose) {
    if (!empty($expose['login'])) {
        Route::post('login',   [AuthController::class, 'login']);
    }
    if (!empty($expose['refresh'])) {
        Route::post('refresh', [AuthController::class, 'refresh'])
            ->middleware(['throttle:60,1', 'firauth.token']);
    }
    if (!empty($expose['logout'])) {
        Route::post('logout',  [AuthController::class, 'logout'])
            ->middleware('firauth');
    }
});
