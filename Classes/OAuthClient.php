<?php
declare(strict_types=1);
namespace Flownative\OpenIdConnect\Client;

use Neos\Flow\Annotations as Flow;

/**
 * An OAuth Client which is adapted for specific use for Open ID Connect.
 *
 * This OAuth client usually is created in two ways:
 *
 *   1. explicitly through the OpenIdConnectClient
 *   2. automatically through the authorization process by the Flownative.OAuth2.Client package
 *
 * In the first case, the OpenIdConnectClient will inject itself into this
 * OAuthClient so that this client can retrieve the configuration options,
 * such as the authorization endpoint URI.
 *
 * In the second case, this OAuth client will lazily create an instance
 * of OpenIdConnectClient as soon as the configuration options are needed
 * and if no such client has been injected yet.
 */
class OAuthClient extends \Flownative\OAuth2\Client\OAuthClient
{
    public const SERVICE_TYPE= 'oidc';

    /**
     * @Flow\InjectConfiguration(path="http.baseUri", package="Neos.Flow")
     * @var string
     */
    protected $flowBaseUriSetting;

    /**
     * @var array
     */
    private $options = [];

    /**
     * @var OpenIdConnectClient
     */
    private $openIdConnectClient;

    /**
     * @param OpenIdConnectClient $openIdConnectClient
     */
    public function setOpenIdConnectClient(OpenIdConnectClient $openIdConnectClient): void
    {
        $this->openIdConnectClient = $openIdConnectClient;
    }

    /**
     * @return string
     * @throws ConfigurationException
     */
    public function getBaseUri(): string
    {
        $this->initializeOptionsIfNeeded();
        if (!isset($this->options['issuer'])) {
            throw new ConfigurationException(sprintf('Missing configuration issuer for service "%s" (%s). Either configure it explicitly via settings or make sure that auto-discovery returns "issuer".', $this->getServiceName(), $this->getServiceType()), 1559028091);
        }
        return $this->options['issuer'];
    }

    /**
     * Returns the OAuth service endpoint for authorizing a token.
     *
     * @return string
     * @throws ConfigurationException
     */
    public function getAuthorizeTokenUri(): string
    {
        $this->initializeOptionsIfNeeded();
        if (!isset($this->options['authorizationEndpoint']) || !is_string($this->options['authorizationEndpoint'])) {
            throw new ConfigurationException(sprintf('Missing configuration authorizationEndpoint for service "%s" (%s). Either configure it explicitly via settings or make sure that auto-discovery returns "authorization_endpoint".', $this->getServiceName(), $this->getServiceType()), 1558612617);
        }
        return $this->options['authorizationEndpoint'];
    }

    /**
     * @throws ConfigurationException
     */
    public function getEndSessionUri(): string
    {
        $this->initializeOptionsIfNeeded();
        if (!isset($this->options['endSessionEndpoint']) || !is_string($this->options['endSessionEndpoint'])) {
            throw new ConfigurationException(sprintf('Missing configuration endSessionEndpoint for service "%s" (%s). Either configure it explicitly via settings or make sure that auto-discovery returns "end_session_endpoint".', $this->getServiceName(), $this->getServiceType()), 1558612618);
        }
        return $this->options['endSessionEndpoint'];
    }

    /**
     * Returns the OAuth service endpoint for the access token.
     *
     * @return string
     * @throws ConfigurationException
     */
    public function getAccessTokenUri(): string
    {
        $this->initializeOptionsIfNeeded();
        if (!isset($this->options['tokenEndpoint']) || !is_string($this->options['tokenEndpoint'])) {
            throw new ConfigurationException(sprintf('Missing configuration tokenEndpoint for service "%s" (%s). Either configure it explicitly via settings or make sure that auto-discovery returns "token_endpoint".', $this->getServiceName(), $this->getServiceType()), 1558615098);
        }
        return $this->options['tokenEndpoint'];
    }

    /**
     * @return string
     * @throws ConfigurationException
     */
    public function getClientId(): string
    {
        $this->initializeOptionsIfNeeded();
        if (!isset($this->options['clientId'])) {
            throw new ConfigurationException(sprintf('Missing configuration clientId for service "%s" (%s). Either configure it explicitly via settings or make sure that auto-discovery returns "client_id".', $this->getServiceName(), $this->getServiceType()), 1558615099);
        }
        return $this->options['clientId'];
    }

    /**
     * @return string
     */
    public static function getServiceType(): string
    {
        return self::SERVICE_TYPE;
    }

    /**
     * @return void
     */
    private function initializeOptionsIfNeeded(): void
    {
        if ($this->options !== []) {
            return;
        }
        if (!$this->openIdConnectClient) {
            $this->openIdConnectClient = new OpenIdConnectClient($this->getServiceName());
        }
        $this->options = $this->openIdConnectClient->getOptions();
    }
}
