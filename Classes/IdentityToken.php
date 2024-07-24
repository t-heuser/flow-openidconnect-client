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
 * @Flow\Scope("session")
 */
class IdentityToken extends AbstractToken
{
    #[Flow\Inject]
    protected SessionManagerInterface $sessionManager;

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
        // Session is already started at this point, this exception can never really occur.
        $currentSession->addTag('Flownative-OpenIdConnect-Client-'.$sessionIdentifier);
    }

    public function hasData(): bool
    {
        return is_string($this->jwt);
    }
}
