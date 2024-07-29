<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Authentication;

use Flownative\OpenIdConnect\Client\Exceptions\ConnectionException;
use Flownative\OpenIdConnect\Client\Exceptions\NoSuchIdentityTokenException;
use Flownative\OpenIdConnect\Client\Exceptions\ServiceException;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Flownative\OpenIdConnect\Client\IdentityTokenFactory;
use Flownative\OpenIdConnect\Client\IdentityTokenRepository;
use Flownative\OpenIdConnect\Client\OAuthClient;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use InvalidArgumentException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Persistence\Exception\ObjectValidationFailedException;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\AccessDeniedException;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;
use Neos\Flow\Session\Exception\SessionNotStartedException;

final class OpenIdConnectToken extends AbstractToken
{
    /**
     * Name of the parameter used internally by this OpenID Connect client package in GET query parts
     */
    public const OIDC_PARAMETER_NAME = 'flownative_oidc';

    /**
     * @Flow\Inject
     * @var IdentityTokenRepository
     */
    protected $identityTokenRepository;

    /**
     * @Flow\Inject
     * @var IdentityTokenFactory
     */
    protected $identityTokenFactory;

    private array $queryParameters = [];

    /**
     * @var string|array|null
     */
    private $authorizationHeader = '';

    /**
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

        try {
            $this->identityTokenRepository->get($this->entryPoint->getOptions()['serviceName']);
        } catch (NoSuchIdentityTokenException $exception) {
            if ($this->getAuthenticationStatus() !== self::AUTHENTICATION_SUCCESSFUL) {
                $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
            }
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
    public function extractIdentityTokenFromRequest(): IdentityToken
    {
        $serviceName = $this->entryPoint->getOptions()['serviceName'];

        if ($this->authorizationHeader !== null && strpos($this->authorizationHeader, 'Bearer ') !== false) {
            return $this->extractIdentityTokenFromAuthorizationHeader($serviceName);
        }

        if ( ! isset($this->queryParameters[self::OIDC_PARAMETER_NAME])) {
            return $this->getIdentityTokenFromSession($serviceName);
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
            $identityToken = $client->buildIdentityToken($authorizationIdentifier);
            $client->removeAuthorization($authorizationIdentifier);

            return $identityToken;
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
    private function extractIdentityTokenFromAuthorizationHeader(string $serviceName): IdentityToken
    {
        if (strpos($this->authorizationHeader, 'Bearer') !== 0) {
            $this->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
            throw new AuthenticationRequiredException(
                'Could not extract access token from Authorization header: "Bearer" keyword is missing', 1589283608
            );
        }

        try {
            $jwt = substr($this->authorizationHeader, strlen('Bearer '));
            $identityToken = $this->identityTokenFactory->create();
            $identityToken->setDataFromJwt($jwt, $serviceName);

            return $this->identityTokenRepository->save($identityToken);
        } catch (InvalidArgumentException|ObjectValidationFailedException $exception) {
            $this->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            throw new AccessDeniedException('Could not extract JWT from Authorization header', 1589283968, $exception);
        } catch (SessionNotStartedException $exception) {
            $this->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
            throw new AccessDeniedException('An error occurred while trying to log in.', 1589283965, $exception);
        }
    }

    /**
     * @throws AuthenticationRequiredException
     * @throws InvalidAuthenticationStatusException
     */
    private function getIdentityTokenFromSession(string $serviceName): IdentityToken
    {
        try {
            return $this->identityTokenRepository->get($serviceName);
        } catch (NoSuchIdentityTokenException $exception) {
            $this->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
            throw new AuthenticationRequiredException('Missing/empty IdentityToken for OIDC in session.', 1560349409);
        }
    }
}
