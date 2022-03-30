<?php

declare(strict_types=1);

namespace Hobbii\CognitoClient\Contracts;

interface AuthSessionContract
{
    public function success(): bool;

    public function getAccessToken(): ?string;

    public function getIdToken(): ?string;

    public function getRefreshToken(): ?string;
}
