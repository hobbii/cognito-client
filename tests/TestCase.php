<?php

namespace Tests;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\Result;
use Faker\Factory;
use Faker\Generator;
use Firebase\JWT\JWT;
use Hobbii\CognitoClient\CognitoClient;
use PHPUnit\Framework\TestCase as PHPUnitTestCase;

class TestCase extends PHPUnitTestCase
{
    /** @var Generator */
    protected $faker;
    protected $clientId;
    protected $clientSecret;
    private $poolId;
    private $region;

    /**
     * Throwaway 2048-bit RSA key used only to sign fake tokens in tests
     * (firebase/php-jwt v7 rejects RSA keys shorter than 2048 bits).
     *
     * @var string
     */
    private $privateKey = <<<EOD
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDUvJm34Gg0Qb0v
XU63j887byDSpYsx0lsL+XoXEWW6wfqBDlsg7XkBwHj+WJr+d4f4dQmoOvMjITdg
RZrDyfC9oinz33bCIKkTkXSpNStKf18kLuIFcv7k6LOyeafasObNXPk3K0brXC9v
UtD/ApQ1kxh7vyBaCDdZKlnnlVDCiKaraghO9No+BdAj48UzDbRrxJWNoECuxB5Z
XijzBQTwhc0cRYJxb8JX61ICH0JOLTzL9VgTEq5EwAeQ058AV0TnmT5RLpO4Ckea
yhKhPqSc7eTHmrR42Ia6ErnS7XurorhHloHxSx/qqQzWIwsQ0uB00c6dRS3JSWyR
PJaHh7XZAgMBAAECggEAFn1gbChPe9lzTEg7Tnvn4ZWholiZOt7NJ0VBhfdzNLzV
ucJbGe5g+4bDLnMO4lX1TEE7OyC4RtTNIOKwNis+xcgYp/fOJemuq4CWFQlSQUxD
3PRj3/BEnXiIVBbjtY08E9EqEONaBP8NjgxIR0fuLoJqyoeYaPbeEGbCHbxoTu2n
/TV/drHKgATVsOxVDF5tOgTpXJ2JEeZl4NylNTJXRtnmCUHWR9rJ3Qs1KEORmkP5
8GycnOHKocya5UssQ1FPF5lqSPU/xvFsh55gcxHLVZT5V2B4cNkgKuDi5l5jUst3
RxIrDSFgKnJNcd2wHM02EQNiF6IeX9Is61SbqX3RjQKBgQDynLmPgxp65HTbc8fw
HhrUBsHh4vM3eGfanfs/ysQ++6GK+LmxpK6hwSg1Ryx4fWAqdxfg/8XqKgaoCdj7
j6zly5mm9LYq76gse1uZWfcnvsKs8P62l6Av7Rtnyxc6j7XcXf74qwcY1pANGrwf
X2IiyMF3ki3YDH0uv54+LbwdkwKBgQDgedZ+LxDg4MPlQ6LC8DDbLjWBhM5moTny
TCkhkq9Vf8qekak4VP9vWOfbgkcTWgkbevCdtODdvOy1JL1RetSHQKI/iuV7fAmk
pehIOssmO0Inh9CaQGTZwBS6cOxypuN7wwMkQVXszS+nNONILCnAx6k1nZOiLSdn
8ou/U3JiYwKBgEqzbQM+N+INA9oqTS6m5lXQetQlgAPdZATRTfI3abOG4RecO/jx
nv+ZLNsyvgOffwO0Rbr2pibSp9gHqDLU60SaKwZYJNsVja+cj/io1cv8FY8QaS0p
hJ4dIKoVw2I5q6JdostIRdglAJe4WqJCSUIylDdP4CO8vLKvN3cnt9tXAoGBAKXm
5jPULTFGbQGgf0Z7pmAXQsw6jyEiv2ToDO4XLyaNj/6pwNs1VqPAnXuKSWVwAZMh
xXuJFzhKTNeEE7eIhFKB3mgAC6K8BZR+WbIoYcQbv8Tfh7i5JtAYOjmhA9+ooC/z
7Pp6nzqoWzPEzsWkfidQaSqLD3Wo0Zrtk4MP9VXpAoGAOeri0djkoxPn+irxi4be
gXwOmHxtUwDDvXRAxUDdU0ZbVdp2/2rPVfWeDQKejMg49URbMFUcQ6QJjflChET2
VDioUBCFZXYJ3sjt/sU4Fc21I27vUr4uhZYR/niBuIObaBh4xV1JxN9UYL0QTUAU
JPuWxpaBqZzzDLnf4WTwWsE=
-----END PRIVATE KEY-----
EOD;

    protected function setUp(): void
    {
        parent::setUp();

        $this->faker = Factory::create();
        $this->clientId = $this->faker->password(26);
        $this->clientSecret = $this->faker->password(52);
        $this->region();
        $this->poolId();
    }

    protected function makeAccessToken(array $attributes = []): string
    {
        $region = $this->region();

        $payload = array_merge([
            'sub' => $this->faker->uuid(),
            'event_id' => $this->faker->uuid(),
            'token_use' => 'access',
            'scope' => 'aws.cognito.signin.user.admin',
            'auth_time' => time(),
            'iss' => "https://cognito-idp.$region.amazonaws.com/{$this->poolId($region)}",
            'exp' => time() + 3600,
            'iat' => time(),
            'jti' => $this->faker->uuid(),
            'client_id' => $this->faker->password(25, 25),
            'username' => $this->faker->uuid(),
        ], $attributes);

        return $this->jwtEncode($payload);
    }

    protected function makeIdToken(array $attributes = []): string
    {
        $region = $this->region();

        $payload = array_merge([
            'sub' => $this->faker->uuid(),
            'email_verified' => true,
            'custom:oc_customer_id' => (string) $this->faker->randomNumber(7),
            'iss' => "https://cognito-idp.$region.amazonaws.com/{$this->poolId($region)}",
            'phone_number_verified' => true,
            'cognito:username' => $this->faker->uuid(),
            'locale' => $this->faker->locale(),
            'aud' => $this->faker->password(25, 25),
            'event_id' => $this->faker->uuid(),
            'token_use' => 'id',
            'auth_time' => time(),
            'name' => $this->faker->firstName(),
            'phone_number' => $this->faker->phoneNumber(),
            'exp' => time() + 3600,
            'iat' => time(),
            'family_name' => $this->faker->lastName(),
            'email' => $this->faker->email()
        ], $attributes);

        return $this->jwtEncode($payload);
    }

    /**
     * @return string
     * @throws \Exception
     */
    protected function makeRefreshToken(): string
    {
        return base64_encode('{"cty":"JWT","enc":"A256GCM","alg":"RSA-OAEP"}')
            . '.' . base64_encode(random_bytes(128))
            . '.' . base64_encode(random_bytes(16))
            . '.' . base64_encode(random_bytes(256))
            . '.' . base64_encode(random_bytes(32));
    }

    protected function region(): string
    {
        if (!$this->region) {
            $this->region = $this->faker->randomElement([
                'us-east-2',
                'us-east-1',
                'us-west-1',
                'us-west-2',
                'af-south-1',
                'ap-east-1',
                'ap-southeast-3',
                'ap-south-1',
                'ap-northeast-3',
                'ap-northeast-2',
                'ap-southeast-1',
                'ap-southeast-2',
                'ap-northeast-1',
                'ca-central-1',
                'eu-central-1',
                'eu-west-1',
                'eu-west-2',
                'eu-south-1',
                'eu-west-3',
                'eu-north-1',
                'me-south-1',
                'sa-east-1',
            ]);
        }

        return $this->region;
    }

    /**
     * @param string $method
     * @param array $params
     * @param Result|\Exception|null $result
     * @return CognitoIdentityProviderClient
     */
    protected function providerClient(
        string $method,
        array $params,
        $result = null
    ): CognitoIdentityProviderClient {
        $providerClient = \Mockery::mock(CognitoIdentityProviderClient::class);

        if ($result instanceof \Exception) {
            $providerClient->shouldReceive($method)
                ->with($params)
                ->andThrow($result);
        } else {
            $providerClient->shouldReceive($method)
                ->with($params)
                ->andReturn($result ?: $this->result());
        }

        return $providerClient;
    }

    protected function client(CognitoIdentityProviderClient $providerClient): CognitoClient
    {
        return new CognitoClient(
            $providerClient,
            $this->clientId,
            $this->clientSecret,
            $this->poolId
        );
    }

    protected function makeCognitoHash(string $username): string
    {
        return base64_encode(hash_hmac('sha256', $username . $this->clientId, $this->clientSecret, true));
    }

    protected function poolId(string $region = null): string
    {
        if (!$this->poolId) {
            $this->poolId = ($region ?: $this->region()) . '_' . $this->faker->password(9, 9);
        }
        return $this->poolId;
    }

    protected function result(array $payload = [], bool $success = true): Result
    {
        $metadata = [
            '@metadata' => [
                'statusCode' => 200,
                'effectiveUri' => "https://cognito-idp.{$this->region()}.amazonaws.com",
                'headers' => [
                    'date' => 'Mon, 22 Mar 2021 20:56:49 GMT',
                    'content-type' => 'application/x-amz-json-1.1',
                    'content-length' => '4329',
                    'connection' => 'keep-alive',
                    'x-amzn-requestid' => $this->faker->uuid()
                ],
                'transferStats' => ['http' => [0 => [],],],
            ],
        ];

        if (!$success) {
            $metadata['@metadata']['statusCode'] = 400;
        }

        return new Result(array_merge($payload, $metadata));
    }

    private function jwtEncode(array $payload): string
    {
        return JWT::encode($payload, $this->privateKey, 'RS256');
    }
}
