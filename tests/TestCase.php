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
     * This is a private key found in example with RSA256 (openssl)
     * @see https://firebaseopensource.com/projects/firebase/php-jwt/
     *
     * @var string
     */
    private $privateKey = <<<EOD
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC8kGa1pSjbSYZVebtTRBLxBz5H4i2p/llLCrEeQhta5kaQu/Rn
vuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t0tyazyZ8JXw+KgXTxldMPEL9
5+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4ehde/zUxo6UvS7UrBQIDAQAB
AoGAb/MXV46XxCFRxNuB8LyAtmLDgi/xRnTAlMHjSACddwkyKem8//8eZtw9fzxz
bWZ/1/doQOuHBGYZU8aDzzj59FZ78dyzNFoF91hbvZKkg+6wGyd/LrGVEB+Xre0J
Nil0GReM2AHDNZUYRv+HYJPIOrB0CRczLQsgFJ8K6aAD6F0CQQDzbpjYdx10qgK1
cP59UHiHjPZYC0loEsk7s+hUmT3QHerAQJMZWC11Qrn2N+ybwwNblDKv+s5qgMQ5
5tNoQ9IfAkEAxkyffU6ythpg/H0Ixe1I2rd0GbF05biIzO/i77Det3n4YsJVlDck
ZkcvY3SK2iRIL4c9yY6hlIhs+K9wXTtGWwJBAO9Dskl48mO7woPR9uD22jDpNSwe
k90OMepTjzSvlhjbfuPN1IdhqvSJTDychRwn1kIJ7LQZgQ8fVz9OCFZ/6qMCQGOb
qaGwHmUK6xzpUbbacnYrIM6nLSkXgOAwv7XXCojvY614ILTK3iXiLBOxPu5Eu13k
eUz9sHyD6vkgZzjtxXECQAkp4Xerf5TGfQXGXhxIX52yH+N2LtujCdkQZjXAsGdm
B2zNzvrlgRmgBrklMTrMYgm1NPcW+bRLGcwgW2PTvNM=
-----END RSA PRIVATE KEY-----
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
