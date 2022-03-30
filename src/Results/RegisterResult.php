<?php

declare(strict_types=1);

namespace Hobbii\CognitoService\Results;

class RegisterResult extends BaseResult
{
    public function success(): bool
    {
        return (bool) $this->result->get('UserConfirmed');
    }

    public function getUserId(): ?string
    {
        return $this->result->get('UserSub') ?: null;
    }
}
