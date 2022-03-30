<?php

namespace Hobbii\CognitoService\Results;

use Aws\Result;

class BaseResult
{
    /** @var Result */
    protected $result;

    public function __construct(Result $result)
    {
        $this->result = $result;
    }

    public function success(): bool
    {
        return (int) $this->result->get('@metadata')['statusCode'] === 200;
    }
}
