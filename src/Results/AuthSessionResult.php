<?php

declare(strict_types=1);

namespace Hobbii\CognitoService\Results;

use Hobbii\CognitoService\Contracts\AuthSessionContract;

class AuthSessionResult extends BaseResult implements AuthSessionContract
{
    public function success(): bool
    {
        return !empty($this->getAccessToken());
    }

    public function getAccessToken(): ?string
    {
        return $this->getToken('AccessToken');
    }

    public function getExpires(): int
    {
        return $this->result->get('AuthenticationResult')['ExpiresIn'] ?? 0;
    }

    public function getIdToken(): ?string
    {
        return $this->getToken('IdToken');
    }

    public function getRefreshToken(): ?string
    {
        return $this->getToken('RefreshToken');
    }

    private function getToken(string $name): ?string
    {
        return $this->result->get('AuthenticationResult')[$name] ?? null;
    }
}
