<?php

declare(strict_types=1);

namespace Hobbii\CognitoClient;

use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Credentials\Credentials;
use Hobbii\CognitoClient\Contracts\AuthSessionContract;
use Hobbii\CognitoClient\Results\AuthSessionResult;
use Hobbii\CognitoClient\Results\BaseResult;
use Hobbii\CognitoClient\Results\ChangePasswordResult;
use Hobbii\CognitoClient\Results\CodeDeliveryResult;
use Hobbii\CognitoClient\Results\ForgotPasswordResult;
use Hobbii\CognitoClient\Results\GetUserResult;
use Hobbii\CognitoClient\Results\RegisterResult;

class CognitoClient
{
    public const NEW_PASSWORD_CHALLENGE = 'NEW_PASSWORD_REQUIRED';
    public const FORCE_PASSWORD_STATUS = 'FORCE_CHANGE_PASSWORD';
    public const RESET_REQUIRED = 'PasswordResetRequiredException';
    public const LIMIT_EXCEEDED = 'LimitExceededException';
    public const USER_NOT_FOUND = 'UserNotFoundException';
    public const USERNAME_EXISTS = 'UsernameExistsException';
    public const INVALID_PASSWORD = 'InvalidPasswordException';
    public const CODE_MISMATCH = 'CodeMismatchException';
    public const EXPIRED_CODE = 'ExpiredCodeException';

    /** @var CognitoIdentityProviderClient */
    private $client;

    /** @var string */
    private $clientId;

    /** @var string */
    private $clientSecret;

    /** @var string */
    private $poolId;

    public function __construct(CognitoIdentityProviderClient $client, string $clientId, string $clientSecret, string $poolId)
    {
        $this->client = $client;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->poolId = $poolId;
    }

    public static function init(string $awsAccessKeyId, string $awsAccessKeySecret, string $awsRegion, string $clientId, string $clientSecret, string $poolId): self
    {
        return new self(
            new CognitoIdentityProviderClient([
                'credentials' => new Credentials($awsAccessKeyId, $awsAccessKeySecret),
                'region' => $awsRegion,
                'version' => 'latest'
            ]),
            $clientId,
            $clientSecret,
            $poolId
        );
    }

    /**
     * Checks if credentials of a user are valid
     *
     * @see http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
     */
    public function authenticate(string $username, string $password): AuthSessionContract
    {
        $response = $this->client->initiateAuth([
            'AuthFlow'       => 'USER_PASSWORD_AUTH',
            'AuthParameters' => [
                'USERNAME'    => $username,
                'PASSWORD'    => $password,
                'SECRET_HASH' => $this->cognitoSecretHash($username)
            ],
            'ClientId'       => $this->clientId,
            'UserPoolId'     => $this->poolId
        ]);
        return new AuthSessionResult($response);
    }

    /**
     * Registers a user in the given user pool
     *
     * @param string $username with email or sanitized phone
     * @param string $password
     * @param array $attributes key => value array of attributes
     * @return RegisterResult
     */
    public function register(string $username, string $password, array $attributes = []): RegisterResult
    {
        $response = $this->client->signUp([
            'Username'       => $username,
            'Password'       => $password,
            'SecretHash'     => $this->cognitoSecretHash($username),
            'UserAttributes' => $this->formatAttributes($attributes),
            'ClientId'       => $this->clientId,
            'UserPoolId'     => $this->poolId,
        ]);

        return new RegisterResult($response);
    }

    /**
     * Registers a user in the given user pool
     *
     * @param string $accessToken
     * @param string $currentPassword
     * @param string $newPassword
     * @return ChangePasswordResult
     */
    public function changePassword(string $accessToken, string $currentPassword, string $newPassword): ChangePasswordResult
    {
        $response = $this->client->changePassword([
            'AccessToken'      => $accessToken,
            'PreviousPassword' => $currentPassword,
            'ProposedPassword' => $newPassword,
            'ClientId'         => $this->clientId,
            'UserPoolId'       => $this->poolId,
        ]);

        return new ChangePasswordResult($response);
    }

    /**
     * Send a password reset code to a user.
     * @see http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ForgotPassword.html
     *
     * @param string $username
     * @param array $clientMetadata
     * @return ForgotPasswordResult
     */
    public function forgotPassword(string $username, array $clientMetadata = []): ForgotPasswordResult
    {
        $result = $this->client->forgotPassword([
            'ClientId'       => $this->clientId,
            'SecretHash'     => $this->cognitoSecretHash($username),
            'Username'       => $username,
            'ClientMetadata' => $clientMetadata
        ]);
        return new ForgotPasswordResult($result);
    }

    /**
     * Set a users attributes.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserAttributes.html
     *
     * @param string $username
     * @param array $attributes
     * @return bool
     */
    public function setUserAttributes(string $username, array $attributes): bool
    {
        $result = $this->client->adminUpdateUserAttributes([
            'UserPoolId'     => $this->poolId,
            'Username'       => $username,
            'UserAttributes' => $this->formatAttributes($attributes),
        ]);

        return (new BaseResult($result))->success();
    }

    /**
     * @param string $username
     * @return bool
     */
    public function deleteUser(string $username): bool
    {
        $result = $this->client->adminDeleteUser([
            'UserPoolId'     => $this->poolId,
            'Username'       => $username,
        ]);

        return (new BaseResult($result))->success();
    }

    /**
     * @param string $username
     * @param string $accessToken
     * @return CodeDeliveryResult
     */
    public function getEmailVerificationCode(string $username, string $accessToken): CodeDeliveryResult
    {
        $result = $this->client->getUserAttributeVerificationCode([
            'Username'       => $username,
            'AccessToken'    => $accessToken,
            'AttributeName'  => 'email',
        ]);

        return new CodeDeliveryResult($result);
    }

    /**
     * @param string $username
     * @param string $accessToken
     * @return CodeDeliveryResult
     */
    public function getPhoneVerificationCode(string $username, string $accessToken): CodeDeliveryResult
    {
        $result = $this->client->getUserAttributeVerificationCode([
            'Username'       => $username,
            'AccessToken'    => $accessToken,
            'AttributeName'  => 'phone_number',
        ]);

        return new CodeDeliveryResult($result);
    }

    /**
     * @param string $username
     * @param string $refreshToken
     * @return AuthSessionContract
     */
    public function refreshSession(string $username, string $refreshToken): AuthSessionContract
    {
        $response = $this->client->initiateAuth([
            'AuthFlow'       => 'REFRESH_TOKEN_AUTH',
            'AuthParameters' => [
                'REFRESH_TOKEN' => $refreshToken,
                'SECRET_HASH'   => $this->cognitoSecretHash($username)
            ],
            'ClientId'       => $this->clientId,
            'UserPoolId'     => $this->poolId
        ]);
        return new AuthSessionResult($response);
    }

    /**
     * @param string $username
     * @param string $password
     * @param string $token
     * @return ChangePasswordResult
     */
    public function confirmForgotPassword(string $username, string $password, string $token): ChangePasswordResult
    {
        $result = $this->client->confirmForgotPassword([
            'Username'         => $username,
            'Password'         => $password,
            'ConfirmationCode' => $token,
            'SecretHash'       => $this->cognitoSecretHash($username),
            'ClientId'         => $this->clientId,
            'UserPoolId'       => $this->poolId
        ]);
        return new ChangePasswordResult($result);
    }

    /**
     * Get user details.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUser.html
     *
     * @param string $username
     * @return GetUserResult|null
     */
    public function getUser(string $username): ?GetUserResult
    {
        try {
            $user = $this->client->adminGetUser([
                'Username'   => $username,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return null;
        }

        return new GetUserResult($user);
    }

    /**
     * Get user details.
     * http://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_GetUser.html
     *
     * @param string $token
     * @return GetUserResult|null
     */
    public function getUserByAccessToken(string $token): ?GetUserResult
    {
        try {
            $user = $this->client->getUser([
                'AccessToken' => $token,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return null;
        }
        return new GetUserResult($user);
    }

    /**
     * Format attributes in Name/Value array
     *
     * @param array $attributes
     * @return array
     */
    private function formatAttributes(array $attributes): array
    {
        $userAttributes = [];

        foreach ($attributes as $key => $value) {
            $userAttributes[] = [
                'Name'  => $key,
                'Value' => $value,
            ];
        }

        return $userAttributes;
    }

    /**
     * Creates the Cognito secret hash
     *
     * @param string $username
     * @return string
     */
    private function cognitoSecretHash(string $username): string
    {
        return $this->hash($username . $this->clientId);
    }

    /**
     * Creates a HMAC from a string
     *
     * @param string $message
     * @return string
     */
    private function hash(string $message): string
    {
        $hash = hash_hmac(
            'sha256',
            $message,
            $this->clientSecret,
            true
        );

        return base64_encode($hash);
    }
}
