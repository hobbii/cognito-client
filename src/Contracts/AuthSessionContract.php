<?php

declare(strict_types=1);

namespace Hobbii\CognitoService\Contracts;

interface AuthSessionContract
{
    public function success(): bool;

    public function getAccessToken(): ?string;

    public function getIdToken(): ?string;

    public function getRefreshToken(): ?string;
}
