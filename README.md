# Cognito Client
[![Coverage Status](https://coveralls.io/repos/github/hobbii/cognito-client/badge.svg?branch=main)](https://coveralls.io/github/hobbii/cognito-client?branch=main)
[![Total Downloads](https://img.shields.io/packagist/dt/hobbii/cognito-client)](https://packagist.org/packages/hobbii/cognito-client)
[![Latest Version](https://img.shields.io/packagist/v/hobbii/cognito-client)](https://packagist.org/packages/hobbii/cognito-client)
![CI Workflow](https://github.com/hobbii/cognito-client/actions/workflows/ci.yml/badge.svg?branch=main)


A public composer package for interacting with AWS Cognito.

## Installation
```shell
composer require hobbii/cognito-client
```

## Usage
Instantiate the client:

```php
use Hobbii\CognitoClient\CognitoClient

$client = CognitoClient::init(
    'EXAMPLEAKIAIOSFODNN7', // AWS Access Key ID
    'EXAMPLEKEYemi/K7MDENG/bPxRfiCYwJalrXUtnF', // AWS Access Key Secret
    'us-west-1', // AWS Region
    '12a34bcde5fgh7ij8kl90mn12o', // Cognito App Client ID
    '12abc3defghi56789jklmnopqrstu012vwxyzabcd34efg56hi7', // Cognito App Client Secret
    'us-west-1_aB12CD34e', // Cognito User Pool ID
);

$authSession = $client->authenticate($username, $password);

$authSession->getAccessToken();
$authSession->getIdToken();
```

## Test
```shell
php vendor/bin/phpunit
```

## License
All contents of this package are licensed under the [MIT license](LICENSE).
