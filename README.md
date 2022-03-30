# Cognito Service
[![codecov](https://codecov.io/gh/hobbii/cognito-client/branch/main/graph/badge.svg?token=6PFWRSU1CN)](https://codecov.io/gh/hobbii/cognito-client)
![CI Workflow](https://github.com/hobbii/cognito-client/actions/workflows/ci.yml/badge.svg?branch=main)

A PHP Library client for interacting with AWS Cognito.

## Installation
```shell
composer require hobbii/cognito-client
```

## Usage
Instantiate the client:
```php
use Hobbii\CognitoService\CognitoClient

$client = CognitoClient::init(
    'AKIAIOSFODNN7EXAMPLE', // AWS Access Key ID
    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', // AWS Access Key Secret
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
