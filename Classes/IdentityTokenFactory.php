<?php

namespace Flownative\OpenIdConnect\Client;

use Neos\Flow\Session\SessionManagerInterface;

final class IdentityTokenFactory
{
    public function __construct(
        private readonly SessionManagerInterface $sessionManager
    ) {
    }

    public function create(): IdentityToken
    {
        return new IdentityToken($this->sessionManager);
    }
}
