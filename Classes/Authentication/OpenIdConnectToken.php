<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\ConnectionException;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Flownative\OpenIdConnect\Client\OAuthClient;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use Flownative\OpenIdConnect\Client\ServiceException;
use InvalidArgumentException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\AccessDeniedException;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;

final class OpenIdConnectToken extends AbstractToken
{
    /**
     * Name of the parameter used internally by this OpenID Connect client package in GET query parts
     */
    public const OIDC_PARAMETER_NAME = 'flownative_oidc';

    /**
     * @var array
     */
    protected $queryParameters;

    /**
     * @var string
     */
    protected $authorizationHeader;

    #[Flow\Inject]
    protected IdentityToken $identityToken;

    /**
     * @param  ActionRequest  $actionRequest
     * @throws InvalidAuthenticationStatusException
     */
    public function updateCredentials(ActionRequest $actionRequest): void
    {
        $httpRequest = $actionRequest->getHttpRequest();

        $this->queryParameters = $httpRequest->getQueryParams();

        if ($httpRequest->hasHeader('Authorization')) {
            $this->authorizationHeader = $httpRequest->getHeader('Authorization');
        } elseif ($httpRequest->hasHeader('authorization')) {
            $this->authorizationHeader = $httpRequest->getHeader('Authorization');
        }

        if (is_array($this->authorizationHeader)) {
            $this->authorizationHeader = reset($this->authorizationHeader);
        }

        if ( ! $this->identityToken->hasData() && $this->getAuthenticationStatus(
            ) !== self::AUTHENTICATION_SUCCESSFUL) {
            $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
        }
    }

    /**
     * Extract an identity token from either the query parameters of the current request (in case we
     * just return from an authentication redirect) or from the session.
     *
     * @throws AccessDeniedException
     * @throws AuthenticationRequiredException
     * @throws InvalidAuthenticationStatusException
     *
     * NOTE: The token is not verified yet – signature and expiration time must be checked by code using this token
     */
    public function extractIdentityTokenFromRequest(string $serviceName): void
    {
        if ($this->authorizationHeader !== null && str_contains($this->authorizationHeader, 'Bearer ')) {
            $this->extractIdentityTokenFromAuthorizationHeader($serviceName);

            return;
        }

        if ( ! isset($this->queryParameters[self::OIDC_PARAMETER_NAME])) {
            $this->hasInitializedIdentityTokenInSession();

            return;
        }

        $authorizationIdQueryParameterName = OAuthClient::generateAuthorizationIdQueryParameterName(
            OAuthClient::SERVICE_TYPE
        );
        if ( ! isset($this->queryParameters[$authorizationIdQueryParameterName])) {
            throw new AccessDeniedException(
                sprintf(
                    'Missing authorization identifier "%s" from query parameters',
                    $authorizationIdQueryParameterName
                ), 1560350311
            );
        }
        try {
            $tokenArguments = TokenArguments::fromSignedString($this->queryParameters[self::OIDC_PARAMETER_NAME]);
        } catch (InvalidArgumentException $exception) {
            $this->setAuthenticationStatus(self::WRONG_CREDENTIALS);
            throw new AccessDeniedException(
                'Could not extract token arguments from query parameters',
                1560349658,
                $exception
            );
        }

        $authorizationIdentifier = $this->queryParameters[$authorizationIdQueryParameterName];
        $client = new OpenIdConnectClient($tokenArguments[TokenArguments::SERVICE_NAME]);

        try {
            $client->buildIdentityToken($authorizationIdentifier);
            $client->removeAuthorization($authorizationIdentifier);
        } catch (ServiceException|ConnectionException $exception) {
            throw new AccessDeniedException(
                sprintf(
                    'Could not extract identity token for authorization identifier "%s": %s',
                    $authorizationIdentifier,
                    $exception->getMessage()
                ), 1560350413, $exception
            );
        }
    }

    /**
     * @throws AccessDeniedException
     * @throws AuthenticationRequiredException
     * @throws InvalidAuthenticationStatusException
     */
    private function extractIdentityTokenFromAuthorizationHeader(string $serviceName): void
    {
        if ( ! str_starts_with($this->authorizationHeader, 'Bearer ')) {
            $this->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
            throw new AuthenticationRequiredException(
                'Could not extract access token from Authorization header: "Bearer" keyword is missing', 1589283608
            );
        }

        try {
            $jwt = substr($this->authorizationHeader, strlen('Bearer '));
            $this->identityToken->setDataFromJwt($jwt, $serviceName);
        } catch (InvalidArgumentException $exception) {
            $this->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            throw new AccessDeniedException('Could not extract JWT from Authorization header', 1589283968, $exception);
        }
    }

    /**
     * @throws AuthenticationRequiredException
     * @throws InvalidAuthenticationStatusException
     */
    private function hasInitializedIdentityTokenInSession(): void
    {
        if ( ! $this->identityToken->hasData()) {
            $this->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
            throw new AuthenticationRequiredException('Missing/empty IdentityToken for OIDC in session.', 1560349409);
        }
    }
}
