<?php

namespace Flownative\OpenIdConnect\Client\Command;

use Doctrine\ORM\EntityManagerInterface;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Cli\CommandController;

final class OidcCommandController extends CommandController
{
    /**
     * @var EntityManagerInterface
     */
    protected $entityManager;

    /**
     * @Flow\InjectConfiguration
     * @var array
     */
    protected $settings;

    /**
     * @param  EntityManagerInterface  $entityManager
     * @return void
     */
    public function injectEntityManager(EntityManagerInterface $entityManager): void
    {
        $this->entityManager = $entityManager;
    }

    /**
     * Discover OIDC configuration
     *
     * This command connects with the /.well-known/openid-configuration endpoint of an OIDC
     * service configured via Flow settings and retrieves information about endpoints,
     * capabilities and further information. The retrieved data is displayed in a table.
     *
     * @param  string|null  $serviceName  The service name, as it was configured via Flow settings
     * @return void
     */
    public function discoverCommand(string $serviceName = null): void
    {
        if (empty($this->settings['services'])) {
            $this->outputLine('<error>There are no services configured in the Flow settings</error>');
            exit(1);
        }
        if ($serviceName === null) {
            if (count($this->settings['services']) > 1) {
                $this->outputLine(
                    '<error>You must specify a service with --service-name, because multiple services are available</error>'
                );
                $this->outputLine(
                    'Use one of the following service names: '.implode(', ', array_keys($this->settings['services']))
                );
                exit(1);
            }
            $serviceName = array_key_first($this->settings['services']);
        }

        if ( ! isset($this->settings['services'][$serviceName])) {
            $this->outputLine('<error>Unknown service "%s".</error>', [$serviceName]);
            exit(1);
        }
        if (empty($this->settings['services'][$serviceName]['options']['baseUri'])) {
            $this->outputLine('<error>Missing option "baseUri" for service "%s".</error>', [$serviceName]);
            exit(1);
        }

        $openIdConnectClient = new OpenIdConnectClient($serviceName);

        $rows = [];
        foreach ($openIdConnectClient->getDiscoveryOptions(true) as $optionName => $optionValue) {
            $rows[] = [
                $optionName,
                ! is_string($optionValue) ? var_export($optionValue, true) : $optionValue,
            ];
        }

        $this->output->outputTable($rows, ['Option', 'Value']);
    }

    /**
     * @param  string  $serviceName
     */
    public function getAccessTokenCommand(string $serviceName): void
    {
        $openIdConnectClient = new OpenIdConnectClient($serviceName);

        $additionalParameters = $this->settings['services'][$serviceName]['options']['additionalParameters'] ?? [];
        try {
            $accessToken = $openIdConnectClient->getAccessToken(
                $serviceName,
                $this->settings['services'][$serviceName]['options']['clientId'],
                $this->settings['services'][$serviceName]['options']['clientSecret'],
                'profile name',
                $additionalParameters
            );
        } catch (IdentityProviderException $e) {
            $this->outputLine(
                '<error>%s: "%s"</error>',
                [$e->getMessage(), $e->getResponseBody()['error_description'] ?? '']
            );
            exit (1);
        } catch (\Exception $e) {
            $this->outputLine('<error>%s</error>', [$e->getMessage()]);
            exit (1);
        }

        $this->outputLine($accessToken->getToken());
    }
}
