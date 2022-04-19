<?php

namespace Hobbii\CognitoClient\Results;

class GetUserResult extends BaseResult
{
    public function getUsername(): ?string
    {
        return $this->result->get('Username') ?: null;
    }

    public function getEmail(): ?string
    {
        return $this->getAttribute('email');
    }

    public function getEmailVerified(): bool
    {
        return $this->getAttribute('email_verified') === 'true';
    }

    public function getPhoneNumber(): ?string
    {
        return $this->getAttribute('phone_number');
    }

    public function getPhoneNumberVerified(): bool
    {
        return $this->getAttribute('phone_number_verified') === 'true';
    }

    public function getName(): ?string
    {
        return $this->getAttribute('name');
    }

    public function getLastName(): ?string
    {
        return $this->getAttribute('family_name');
    }

    public function getLocale(): ?string
    {
        return $this->getAttribute('locale');
    }

    public function getCustomAttribute(string $attribute): ?string
    {
        return $this->getAttribute("custom:$attribute");
    }

    protected function getAttribute(string $attributeName): ?string
    {
        $filteredAttributes = array_filter(
            $this->result->get('UserAttributes'),
            function (array $attribute) use ($attributeName) {
                return $attribute['Name'] == $attributeName;
            }
        );
        return array_pop($filteredAttributes)['Value'] ?? null;
    }
}
