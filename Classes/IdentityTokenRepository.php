<?php

namespace Flownative\OpenIdConnect\Client;

use Flownative\OpenIdConnect\Client\Exceptions\NoSuchIdentityTokenException;
use Neos\Flow\Persistence\Exception\ObjectValidationFailedException;
use Neos\Flow\Session\Exception\SessionNotStartedException;
use Neos\Flow\Session\SessionManagerInterface;

final class IdentityTokenRepository
{
    private const SESSION_DATA_IDENTIFIER_KEY = 'identity_token_data';

    public function __construct(
        private readonly SessionManagerInterface $sessionManager,
        private readonly IdentityTokenFactory $identityTokenFactory,
    ) {
    }

    /**
     * @param  string  $serviceName
     * @return IdentityToken
     * @throws NoSuchIdentityTokenException
     */
    public function get(string $serviceName): IdentityToken
    {
        $currentSession = $this->sessionManager->getCurrentSession();

        try {
            $dataFromSession = $currentSession->getData($this->getSessionIdentifierKeyForService($serviceName));
        } catch (SessionNotStartedException) {
            throw new NoSuchIdentityTokenException();
        }

        if ( ! is_string($dataFromSession) || $dataFromSession === '') {
            throw new NoSuchIdentityTokenException();
        }

        $identityToken = $this->identityTokenFactory->create();
        $identityToken->setDataFromJwt($dataFromSession, $serviceName);

        return $identityToken;
    }

    /**
     * @throws ObjectValidationFailedException
     * @throws SessionNotStartedException
     */
    public function save(IdentityToken $identityToken): IdentityToken
    {
        if ( ! $identityToken->hasData()) {
            throw new ObjectValidationFailedException();
        }

        if ($identityToken->getOidcServiceName() === '') {
            throw new ObjectValidationFailedException();
        }

        $currentSession = $this->sessionManager->getCurrentSession();

        $currentSession->putData(
            $this->getSessionIdentifierKeyForService($identityToken->getOidcServiceName()),
            $identityToken->asJwt()
        );

        return $identityToken;
    }

    private function getSessionIdentifierKeyForService(string $serviceName): string
    {
        return md5(self::SESSION_DATA_IDENTIFIER_KEY.'_'.$serviceName);
    }
}
