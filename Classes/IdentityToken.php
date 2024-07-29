<?php

namespace Flownative\OpenIdConnect\Client;

use InvalidArgumentException;
use Neos\Flow\Session\SessionManagerInterface;
use Neos\Flow\Annotations as Flow;

/**
 * Value object for an OpenID Connect identity token.
 *
 * @see https://openid.net/specs/openid-connect-basic-1_0.html#IDToken
 */
final class IdentityToken extends AbstractToken
{
    /**
     * @Flow\Inject
     * @var SessionManagerInterface
     */
    protected $sessionManager;

    /**
     * Additionally adds a tag to the session to be able to identify the session later on when using the back channel
     * logout.
     */
    public function setDataFromJwt(string $jwt, string $oidcServiceName): void
    {
        parent::setDataFromJwt($jwt, $oidcServiceName);

        $sessionIdentifier = $this->getValues()['sub'] ?? $this->getValues()['sid'] ?? null;
        if ($sessionIdentifier === null) {
            throw new InvalidArgumentException('The identity token is missing the "sub" and "sid" values.');
        }

        $currentSession = $this->sessionManager->getCurrentSession();
        $tagPrefix = md5("Flownative-OpenIdConnect-Client-$oidcServiceName");
        // Session is already started at this point, this exception can never really occur.
        $currentSession->addTag("$tagPrefix-$sessionIdentifier");
    }

    public function hasData(): bool
    {
        return is_string($this->jwt);
    }
}
