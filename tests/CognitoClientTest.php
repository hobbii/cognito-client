<?php

namespace Tests;

use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Command;
use Hobbii\CognitoService\CognitoClient;
use Hobbii\CognitoService\Results\AuthSessionResult;
use Hobbii\CognitoService\Results\BaseResult;
use Hobbii\CognitoService\Results\ChangePasswordResult;
use Hobbii\CognitoService\Results\CodeDeliveryResult;
use Hobbii\CognitoService\Results\ForgotPasswordResult;
use Hobbii\CognitoService\Results\GetUserResult;
use Hobbii\CognitoService\Results\RegisterResult;

class CognitoClientTest extends TestCase
{
    public function testCanInstantiateClient(): void
    {
        $client = CognitoClient::init(
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'us-west-1',
            '12a34bcde5fgh7ij8kl90mn12o',
            '12abc3defghi56789jklmnopqrstu012vwxyzabcd34efg56hi7',
            'us-west-1_aB12CD34e'
        );

        $this->assertInstanceOf(CognitoClient::class, $client);
    }

    public function testCanAuthenticateUser(): void
    {
        $username = $this->faker->userName();
        $password = $this->faker->password();

        $expiresIn = $this->faker->randomNumber();
        $accessToken = $this->makeAccessToken();
        $idToken = $this->makeIdToken();
        $refreshToken = $this->makeRefreshToken();

        $providerClient = $this->providerClient(
            'initiateAuth',
            [
                'AuthFlow' => 'USER_PASSWORD_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $username,
                    'PASSWORD' => $password,
                    'SECRET_HASH' => $this->makeCognitoHash($username),
                ],
                'ClientId' => $this->clientId,
                'UserPoolId' => $this->poolId()
            ],
            $this->result([
                'AuthenticationResult' => [
                    'ExpiresIn' => $expiresIn,
                    'AccessToken' => $accessToken,
                    'IdToken' => $idToken,
                    'RefreshToken' => $refreshToken,
                ]
            ])
        );

        $authSession = $this->client($providerClient)->authenticate(
            $username,
            $password
        );

        $this->assertInstanceOf(AuthSessionResult::class, $authSession);
        $this->assertTrue($authSession->success());
        $this->assertEquals($expiresIn, $authSession->getExpires());
        $this->assertEquals($accessToken, $authSession->getAccessToken());
        $this->assertEquals($idToken, $authSession->getIdToken());
        $this->assertEquals($refreshToken, $authSession->getRefreshToken());
    }

    public function testCanRegisterUser(): void
    {
        $username = $this->faker->userName();
        $password = $this->faker->password();
        $attributes = [
            'email' => $this->faker->email(),
            'phone' => $this->faker->phoneNumber()
        ];
        $userId = $this->faker->uuid();

        $providerClient = $this->providerClient('signUp', [
            'Username'       => $username,
            'Password'       => $password,
            'SecretHash'     => $this->makeCognitoHash($username),
            'UserAttributes' => [
                [
                    'Name' => 'email',
                    'Value' => $attributes['email']
                ],
                [
                    'Name' => 'phone',
                    'Value' => $attributes['phone']
                ],
            ],
            'ClientId' => $this->clientId,
            'UserPoolId' => $this->poolId(),
        ], $this->result([
            'UserConfirmed' => true,
            'UserSub' => $userId
        ]));

        $result = $this->client($providerClient)->register($username, $password, $attributes);

        $this->assertInstanceOf(RegisterResult::class, $result);
        $this->assertTrue($result->success());
        $this->assertEquals($userId, $result->getUserId());
    }

    public function testCanChangePassword(): void
    {
        $accessToken = $this->makeAccessToken();
        $oldPassword = $this->faker->password();
        $newPassword = $this->faker->password();

        $providerClient = $this->providerClient('changePassword', [
            'AccessToken' => $accessToken,
            'PreviousPassword' => $oldPassword,
            'ProposedPassword' => $newPassword,
            'ClientId' => $this->clientId,
            'UserPoolId' => $this->poolId()
        ], $this->result());

        $result = $this->client($providerClient)->changePassword($accessToken, $oldPassword, $newPassword);

        $this->assertInstanceOf(ChangePasswordResult::class, $result);
        $this->assertTrue($result->success());
    }

    public function testCanForgetPassword(): void
    {
        $username = $this->faker->userName();

        $deliveryMedium = $this->faker->randomElement(['SMS', 'EMAIL']);
        if ($deliveryMedium === 'SMS') {
            $destination = $this->faker->phoneNumber();
        } else {
            $destination = $this->faker->email();
        }

        $providerClient = $this->providerClient('forgotPassword', [
            'ClientId' => $this->clientId,
            'SecretHash' => $this->makeCognitoHash($username),
            'Username' => $username,
            'ClientMetadata' => [
                'test' => 'metadata'
            ]
        ], $this->result([
            'CodeDeliveryDetails' => [
                'Destination' => $destination,
                'DeliveryMedium' => $deliveryMedium
            ]
        ]));

        $result = $this->client($providerClient)->forgotPassword($username, ['test' => 'metadata']);

        $this->assertInstanceOf(ForgotPasswordResult::class, $result);
        $this->assertTrue($result->success());
        $this->assertEquals($destination, $result->getDestination());
        $this->assertEquals($deliveryMedium === 'SMS', $result->wasSentBySms());
        $this->assertEquals($deliveryMedium === 'EMAIL', $result->wasSentByEmail());
    }

    public function testCanSetUserAttributes(): void
    {
        $username = $this->faker->userName();
        $attributes = [
            'email' => $this->faker->email(),
            'phone' => $this->faker->phoneNumber(),
        ];

        $providerClient = $this->providerClient('adminUpdateUserAttributes', [
            'UserPoolId' => $this->poolId(),
            'Username'=> $username,
            'UserAttributes' => [
                [
                    'Name' => 'email',
                    'Value' => $attributes['email'],
                ],
                [
                    'Name' => 'phone',
                    'Value' => $attributes['phone'],
                ],
            ],
        ]);

        $this->assertTrue($this->client($providerClient)->setUserAttributes($username, $attributes));
    }

    public function testCanDeleteUser(): void
    {
        $username = $this->faker->userName();

        $providerClient = $this->providerClient('adminDeleteUser', [
            'UserPoolId' => $this->poolId(),
            'Username' => $username,
        ]);

        $this->assertTrue($this->client($providerClient)->deleteUser($username));
    }

    public function testCanRequestEmailVerificationCode(): void
    {
        $username = $this->faker->userName();
        $accessToken = $this->makeAccessToken();

        $email = $this->faker->email();

        $providerClient = $this->providerClient('getUserAttributeVerificationCode', [
            'Username' => $username,
            'AccessToken' => $accessToken,
            'AttributeName' => 'email'
        ], $this->result([
            'CodeDeliveryDetails' => [
                'Destination' => $email,
                'DeliveryMedium' => 'EMAIL'
            ]
        ]));

        $result = $this->client($providerClient)->getEmailVerificationCode($username, $accessToken);

        $this->assertInstanceOf(CodeDeliveryResult::class, $result);
        $this->assertTrue($result->success());
        $this->assertEquals($email, $result->getDestination());
        $this->assertTrue($result->wasSentByEmail());
        $this->assertFalse($result->wasSentBySms());
    }

    public function testCanRequestPhoneVerificationCode(): void
    {
        $username = $this->faker->userName();
        $accessToken = $this->makeAccessToken();

        $phone = $this->faker->phoneNumber();

        $providerClient = $this->providerClient('getUserAttributeVerificationCode', [
            'Username' => $username,
            'AccessToken' => $accessToken,
            'AttributeName' => 'phone_number'
        ], $this->result([
            'CodeDeliveryDetails' => [
                'Destination' => $phone,
                'DeliveryMedium' => 'SMS'
            ],
        ]));

        $result = $this->client($providerClient)->getPhoneVerificationCode($username, $accessToken);

        $this->assertInstanceOf(CodeDeliveryResult::class, $result);
        $this->assertTrue($result->success());
        $this->assertEquals($phone, $result->getDestination());
        $this->assertTrue($result->wasSentBySms());
        $this->assertFalse($result->wasSentByEmail());
    }

    public function testCanRefreshSession(): void
    {
        $username = $this->faker->userName();
        $oldRefreshToken = $this->makeRefreshToken();

        $expiresIn = $this->faker->randomNumber();
        $accessToken = $this->makeAccessToken();
        $idToken = $this->makeIdToken();
        $newRefreshToken = $this->makeRefreshToken();

        $providerClient = $this->providerClient('initiateAuth', [
            'AuthFlow'       => 'REFRESH_TOKEN_AUTH',
            'AuthParameters' => [
                'REFRESH_TOKEN' => $oldRefreshToken,
                'SECRET_HASH'   => $this->makeCognitoHash($username)
            ],
            'ClientId'       => $this->clientId,
            'UserPoolId'     => $this->poolId()
        ], $this->result([
            'AuthenticationResult' => [
                'ExpiresIn' => $expiresIn,
                'AccessToken' => $accessToken,
                'IdToken' => $idToken,
                'RefreshToken' => $newRefreshToken,
            ]
        ]));

        $result = $this->client($providerClient)->refreshSession($username, $oldRefreshToken);

        $this->assertInstanceOf(AuthSessionResult::class, $result);
        $this->assertTrue($result->success());
        $this->assertEquals($accessToken, $result->getAccessToken());
        $this->assertEquals($idToken, $result->getIdToken());
        $this->assertEquals($newRefreshToken, $result->getRefreshToken());
        $this->assertEquals($expiresIn, $result->getExpires());
    }

    public function testCanConfirmForgotPassword(): void
    {
        $username = $this->faker->userName();
        $password = $this->faker->password();
        $token = $this->faker->randomNumber(6);

        $providerClient = $this->providerClient('confirmForgotPassword', [
            'Username'         => $username,
            'Password'         => $password,
            'ConfirmationCode' => $token,
            'SecretHash'       => $this->makeCognitoHash($username),
            'ClientId'         => $this->clientId,
            'UserPoolId'       => $this->poolId()
        ]);

        $result = $this->client($providerClient)->confirmForgotPassword($username, $password, $token);

        $this->assertInstanceOf(BaseResult::class, $result);
        $this->assertTrue($result->success());
    }

    public function testCanGetUser(): void
    {
        $username = $this->faker->userName();

        $firstName = $this->faker->firstName();
        $lastName = $this->faker->lastName();
        $email = $this->faker->email();
        $emailVerified = $this->faker->boolean();
        $phone = $this->faker->phoneNumber();
        $phoneVerified = $this->faker->boolean();
        $locale = $this->faker->locale();
        $openCartId = $this->faker->randomNumber();

        $providerClient = $this->providerClient('adminGetUser', [
            'Username' => $username,
            'UserPoolId' => $this->poolId(),
        ], $this->result([
            'Username' => $username,
            'UserAttributes' => [
                [
                    'Name' => 'name',
                    'Value' => $firstName,
                ],
                [
                    'Name' => 'family_name',
                    'Value' => $lastName,
                ],
                [
                    'Name' => 'email',
                    'Value' => $email,
                ],
                [
                    'Name' => 'email_verified',
                    'Value' => $emailVerified ? 'true' : 'false',
                ],
                [
                    'Name' => 'phone_number',
                    'Value' => $phone,
                ],
                [
                    'Name' => 'phone_number_verified',
                    'Value' => $phoneVerified ? 'true' : 'false',
                ],
                [
                    'Name' => 'locale',
                    'Value' => $locale,
                ],
                [
                    'Name' => 'custom:oc_customer_id',
                    'Value' => $openCartId,
                ],
            ]
        ]));

        $result = $this->client($providerClient)->getUser($username);

        $this->assertInstanceOf(GetUserResult::class, $result);
        $this->assertTrue($result->success());
        $this->assertEquals($username, $result->getUsername());
        $this->assertEquals($firstName, $result->getName());
        $this->assertEquals($lastName, $result->getLastName());
        $this->assertEquals($email, $result->getEmail());
        $this->assertEquals($emailVerified, $result->getEmailVerified());
        $this->assertEquals($phone, $result->getPhoneNumber());
        $this->assertEquals($phoneVerified, $result->getPhoneNumberVerified());
        $this->assertEquals($locale, $result->getLocale());
        $this->assertEquals($openCartId, $result->getOpenCartId());
    }

    public function testGetUserExceptionReturnsNull(): void
    {
        $username = $this->faker->userName();

        $providerClient = $this->providerClient('adminGetUser', [
            'Username' => $username,
            'UserPoolId' => $this->poolId()
        ], new CognitoIdentityProviderException('Error message', new Command('adminGetUser')));

        $this->assertNull($this->client($providerClient)->getUser($username));
    }

    public function testCanGetUserByAccessToken(): void
    {
        $accessToken = $this->makeAccessToken();

        $username = $this->faker->userName();
        $firstName = $this->faker->firstName();
        $lastName = $this->faker->lastName();
        $email = $this->faker->email();
        $emailVerified = $this->faker->boolean();
        $phone = $this->faker->phoneNumber();
        $phoneVerified = $this->faker->boolean();
        $locale = $this->faker->locale();
        $openCartId = $this->faker->randomNumber();

        $providerClient = $this->providerClient('getUser', [
            'AccessToken' => $accessToken,
        ], $this->result([
            'Username' => $username,
            'UserAttributes' => [
                [
                    'Name' => 'name',
                    'Value' => $firstName,
                ],
                [
                    'Name' => 'family_name',
                    'Value' => $lastName,
                ],
                [
                    'Name' => 'email',
                    'Value' => $email,
                ],
                [
                    'Name' => 'email_verified',
                    'Value' => $emailVerified ? 'true' : 'false',
                ],
                [
                    'Name' => 'phone_number',
                    'Value' => $phone,
                ],
                [
                    'Name' => 'phone_number_verified',
                    'Value' => $phoneVerified ? 'true' : 'false',
                ],
                [
                    'Name' => 'locale',
                    'Value' => $locale,
                ],
                [
                    'Name' => 'custom:oc_customer_id',
                    'Value' => $openCartId,
                ],
            ]
        ]));

        $result = $this->client($providerClient)->getUserByAccessToken($accessToken);

        $this->assertInstanceOf(GetUserResult::class, $result);
        $this->assertTrue($result->success());
        $this->assertEquals($username, $result->getUsername());
        $this->assertEquals($firstName, $result->getName());
        $this->assertEquals($lastName, $result->getLastName());
        $this->assertEquals($email, $result->getEmail());
        $this->assertEquals($emailVerified, $result->getEmailVerified());
        $this->assertEquals($phone, $result->getPhoneNumber());
        $this->assertEquals($phoneVerified, $result->getPhoneNumberVerified());
        $this->assertEquals($locale, $result->getLocale());
        $this->assertEquals($openCartId, $result->getOpenCartId());
    }

    public function testGetUserByAccessTokenExceptionReturnsNull(): void
    {
        $accessToken = $this->makeAccessToken();

        $providerClient = $this->providerClient('getUser', [
            'AccessToken' => $accessToken,
        ], new CognitoIdentityProviderException('Error message', new Command('getUser')));

        $this->assertNull($this->client($providerClient)->getUserByAccessToken($accessToken));
    }
}
