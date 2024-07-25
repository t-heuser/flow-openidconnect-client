<?php

namespace Flownative\OpenIdConnect\Client;

use InvalidArgumentException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Session\SessionManagerInterface;

/**
 * Value object for an OpenID Connect identity token
 *
 * @see https://openid.net/specs/openid-connect-basic-1_0.html#IDToken
 *
 * @Flow\Scope("singleton")
 */
class IdentityToken extends AbstractToken
{
    private const SESSION_DATA_IDENTIFIER_KEY = 'identity_token_data';

    public function __construct(
        private readonly SessionManagerInterface $sessionManager
    ) {
        $currentSession = $this->sessionManager->getCurrentSession();
        if ( ! $currentSession->isStarted()) {
            return;
        }
        $dataFromSession = $currentSession->getData(self::SESSION_DATA_IDENTIFIER_KEY);
        if ( ! is_array($dataFromSession) ||
            ! array_key_exists('jwt', $dataFromSession) ||
            ! array_key_exists('oidcServiceName', $dataFromSession) ||
            ! is_string($dataFromSession['jwt']) ||
            ! is_string($dataFromSession['oidcServiceName'])) {
            return;
        }

        self::setDataFromJwt($dataFromSession['jwt'], $dataFromSession['oidcServiceName']);
    }

    /**
     * Additionally adds a tag to the session to be able to identify the session later on when using the back channel
     * logout.
     */
    public function setDataFromJwt(string $jwt, string $oidcServiceName): void
    {
        parent::setDataFromJwt($jwt, $oidcServiceName);

        $sessionIdentifier = $this->values['sub'] ?? $this->values['sid'] ?? null;
        if ($sessionIdentifier === null) {
            throw new InvalidArgumentException('The identity token is missing the "sub" and "sid" values.');
        }

        $currentSession = $this->sessionManager->getCurrentSession();
        $tagPrefix = md5("Flownative-OpenIdConnect-Client-$oidcServiceName");
        // Session is already started at this point, this exception can never really occur.
        $currentSession->addTag("$tagPrefix-$sessionIdentifier");

        $currentSession->putData(
            self::SESSION_DATA_IDENTIFIER_KEY,
            ['jwt' => $this->asJwt(), 'oidcServiceName' => $oidcServiceName]
        );
    }

    public function hasData(): bool
    {
        return is_string($this->jwt);
    }
}
