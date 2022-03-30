<?php

namespace Hobbii\CognitoService\Results;

class CodeDeliveryResult extends BaseResult
{
    public function getDestination(): string
    {
        return $this->result->get('CodeDeliveryDetails')['Destination'];
    }

    public function wasSentBySms(): bool
    {
        return $this->result->get('CodeDeliveryDetails')['DeliveryMedium'] === 'SMS';
    }

    public function wasSentByEmail(): bool
    {
        return $this->result->get('CodeDeliveryDetails')['DeliveryMedium'] === 'EMAIL';
    }
}
