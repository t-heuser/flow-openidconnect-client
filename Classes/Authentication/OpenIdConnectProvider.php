<?php

declare(strict_types=1);

namespace Flownative\OpenIdConnect\Client\Authentication;

use DateTimeImmutable;
use Exception;
use Flownative\OpenIdConnect\Client\AuthenticationException;
use Flownative\OpenIdConnect\Client\IdentityToken;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use Flownative\OpenIdConnect\Client\ServiceException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Configuration\Exception\InvalidConfigurationTypeException;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context;
use Neos\Flow\Security\Exception as SecurityException;
use Neos\Flow\Security\Exception\InvalidAuthenticationStatusException;
use Neos\Flow\Security\Exception\NoSuchRoleException;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;
use Neos\Flow\Security\Policy\Role;
use Psr\Log\LoggerInterface;
use RuntimeException;

final class OpenIdConnectProvider extends AbstractProvider
{
    #[Flow\Inject]
    protected Context $securityContext;

    #[Flow\Inject]
    protected PolicyService $policyService;

    /**
     * @Flow\Inject(name="Neos.Flow:SecurityLogger")
     * @var LoggerInterface
     */
    protected $logger;

    #[Flow\Inject]
    protected AccountRepository $accountRepository;

    #[Flow\Inject]
    protected IdentityToken $identityToken;

    /**
     * @return array
     */
    public function getTokenClassNames(): array
    {
        return [OpenIdConnectToken::class];
    }

    /**
     * @param  TokenInterface  $authenticationToken
     * @throws AuthenticationException
     * @throws InvalidAuthenticationStatusException
     * @throws NoSuchRoleException
     * @throws SecurityException
     * @throws UnsupportedAuthenticationTokenException
     * @throws InvalidConfigurationTypeException
     */
    public function authenticate(TokenInterface $authenticationToken): void
    {
        if ( ! $authenticationToken instanceof OpenIdConnectToken) {
            throw new UnsupportedAuthenticationTokenException(
                sprintf(
                    'The OpenID Connect authentication provider cannot authenticate the given token of type %s.',
                    get_class($authenticationToken)
                ), 1559805996
            );
        }
        if ( ! isset($this->options['roles']) && ! isset($this->options['rolesFromClaims']) && ! isset($this->options['addRolesFromExistingAccount'])) {
            throw new RuntimeException(
                'Either "roles", "rolesFromClaims" or "addRolesFromExistingAccount" must be specified in the configuration of OpenID Connect authentication provider',
                1559806095
            );
        }
        if ( ! isset($this->options['serviceName'])) {
            throw new RuntimeException(
                'Missing "serviceName" option in the configuration of OpenID Connect authentication provider',
                1561480057
            );
        }
        if ( ! isset($this->options['accountIdentifierTokenValueName'])) {
            $this->options['accountIdentifierTokenValueName'] = 'sub';
        }
        try {
            $openIdConnectClient = new OpenIdConnectClient($this->options['serviceName']);
            $jwks = $openIdConnectClient->getJwks();
            $authenticationToken->extractIdentityTokenFromRequest($this->options['serviceName']);

            try {
                $hasValidSignature = $this->identityToken->hasValidSignature($jwks);
            } catch (ServiceException $exception) {
                throw new SecurityException('Open ID Connect: '.$exception->getMessage(), 1671105913, $exception);
            }
            if ( ! $hasValidSignature) {
                throw new SecurityException(
                    'Open ID Connect: The identity token provided by the OIDC provider had an invalid signature',
                    1561479176
                );
            }
            $this->logger->debug(
                sprintf(
                    'OpenID Connect: Successfully verified signature of identity token with %s value "%s"',
                    $this->options['accountIdentifierTokenValueName'],
                    $this->identityToken->values[$this->options['accountIdentifierTokenValueName']] ?? 'unknown'
                ),
                LogEnvironment::fromMethodName(__METHOD__)
            );
        } catch (SecurityException\AuthenticationRequiredException) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);

            return;
        } catch (Exception $exception) {
            if ($authenticationToken->getAuthenticationStatus() === TokenInterface::AUTHENTICATION_SUCCESSFUL) {
                $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
            }
            $this->logger->notice(
                sprintf(
                    'OpenID Connect: The authentication provider caught an exception: %s',
                    $exception->getMessage()
                ),
                LogEnvironment::fromMethodName(__METHOD__)
            );

            return;
        }

        if ($this->identityToken->isExpiredAt(new DateTimeImmutable())) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_NEEDED);
            $this->logger->info(
                sprintf(
                    'OpenID Connect: The JWT token "%s" is expired, need to re-authenticate',
                    $this->identityToken->values[$this->options['accountIdentifierTokenValueName']]
                ),
                LogEnvironment::fromMethodName(__METHOD__)
            );

            return;
        }

        if (isset($this->options['audience']) && ! $this->audienceMatches($this->options['audience'])) {
            throw new AuthenticationException(
                'Open ID Connect: The identity token provided by the OIDC provider was not issued for this audience',
                1616568739
            );
        }

        if ($openIdConnectClient->getBaseUri() !== $this->identityToken->values['iss']) {
            throw new AuthenticationException(
                'The given identity token does not contain a valid "iss" parameter.'
            );
        }

        if ( ! isset($this->identityToken->values[$this->options['accountIdentifierTokenValueName']])) {
            throw new AuthenticationException(
                sprintf(
                    'Open ID Connect: The identity token provided by the OIDC provider contained no "%s" value, which is needed as an account identifier',
                    $this->options['accountIdentifierTokenValueName']
                ), 1560267246
            );
        }

        $roleIdentifiers = $this->getConfiguredRoles();

        $account = $this->createTransientAccount(
            $this->identityToken->values[$this->options['accountIdentifierTokenValueName']],
            $roleIdentifiers
        );

        $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);
        $authenticationToken->setAccount($account);
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);

        $this->logger->debug(
            sprintf(
                'OpenID Connect: Successfully authenticated account "%s" with authentication provider %s. Roles: %s',
                $account->getAccountIdentifier(),
                $account->getAuthenticationProviderName(),
                implode(', ', $this->getConfiguredRoles())
            ),
            LogEnvironment::fromMethodName(__METHOD__)
        );

        $this->emitAuthenticated($authenticationToken, $this->policyService->getRoles());
    }

    /**
     * @return string
     */
    public function getServiceName(): string
    {
        return $this->options['serviceName'] ?? '';
    }

    /**
     * @param  TokenInterface  $authenticationToken
     * @param  Role[]  $roles
     * @return void
     * @Flow\Signal()
     */
    public function emitAuthenticated(
        TokenInterface $authenticationToken,
        array $roles
    ): void {
    }

    /**
     * @param  string  $accountIdentifier
     * @param  array  $roleIdentifiers
     * @return Account
     * @throws InvalidConfigurationTypeException
     * @throws NoSuchRoleException
     * @throws SecurityException
     */
    private function createTransientAccount(string $accountIdentifier, array $roleIdentifiers): Account
    {
        $account = new Account();
        $account->setAccountIdentifier($accountIdentifier);
        foreach ($roleIdentifiers as $roleIdentifier) {
            $account->addRole($this->policyService->getRole($roleIdentifier));
        }
        $account->setAuthenticationProviderName($this->name);
        $account->setCredentialsSource($this->identityToken);

        return $account;
    }

    /**
     * @param  string  $expectedAudience
     * @return bool
     */
    private function audienceMatches(string $expectedAudience): bool
    {
        if (empty($expectedAudience)) {
            $this->logger->warning(
                'OpenID Connect: The authentication provider was configured with an empty "audience" option',
                LogEnvironment::fromMethodName(__METHOD__)
            );

            return false;
        }
        $hasValidAudience = $this->identityToken->hasValidAudience($expectedAudience);

        if ( ! $hasValidAudience) {
            $this->logger->warning(
                sprintf(
                    'OpenID Connect: The identity token (%s) was intended for audience "%s" but this authentication provider is configured as audience "%s"',
                    $this->identityToken->values['sub'],
                    $this->identityToken->values['aud'],
                    $expectedAudience
                ),
                LogEnvironment::fromMethodName(__METHOD__)
            );
        }

        return $hasValidAudience;
    }

    /**
     * @return array
     */
    private function getConfiguredRoles(): array
    {
        $roleIdentifiers = [];

        if (isset($this->options['roles']) && is_array($this->options['roles'])) {
            $roleIdentifiers = $this->options['roles'];
            $this->logger->debug(
                sprintf(
                    'OpenID Connect: Adding the following fixed configured roles for identity token (%s): %s',
                    $this->identityToken->values['sub'] ?? '',
                    implode(', ', $roleIdentifiers)
                ),
                LogEnvironment::fromMethodName(__METHOD__)
            );
        }

        if (isset($this->options['rolesFromClaims']) && is_array($this->options['rolesFromClaims'])) {
            foreach ($this->options['rolesFromClaims'] as $claim) {
                $mapping = null;
                if (is_array($claim)) {
                    if ( ! array_key_exists('mapping', $claim)) {
                        throw new RuntimeException(
                            'If "rolesFromClaims" are specified as array, a "mapping" has to be provided', 1623421601
                        );
                    }
                    $mapping = $claim['mapping'];
                    if ( ! is_array($mapping)) {
                        throw new RuntimeException(
                            sprintf(
                                'If "rolesFromClaims" are specified as array, a "mapping" has to be provided as array, given: %s',
                                gettype($mapping)
                            ), 1623656982
                        );
                    }
                    if ( ! array_key_exists('name', $claim)) {
                        throw new RuntimeException(
                            'If "rolesFromClaims" are specified as array, a "name" has to be provided', 1623421648
                        );
                    }
                    $claim = $claim['name'];
                }
                if ( ! isset($this->identityToken->values[$claim])) {
                    $this->logger->debug(
                        sprintf(
                            'OpenID Connect: Identity token (%s) contained no claim "%s"',
                            $this->identityToken->values['sub'] ?? '',
                            $claim
                        ),
                        LogEnvironment::fromMethodName(__METHOD__)
                    );
                    continue;
                }
                if ( ! is_array($this->identityToken->values[$claim])) {
                    $this->logger->error(
                        sprintf(
                            'OpenID Connect: Failed retrieving roles from identity token (%s) because the claim "%s" was not an array as expected.',
                            $this->identityToken->values['sub'] ?? '',
                            $claim
                        ),
                        LogEnvironment::fromMethodName(__METHOD__)
                    );
                    continue;
                }

                foreach ($this->identityToken->values[$claim] as $roleIdentifier) {
                    if ($mapping !== null) {
                        if ( ! array_key_exists($roleIdentifier, $mapping)) {
                            $this->logger->debug(
                                sprintf(
                                    'OpenID Connect: Ignoring role "%s" from identity token (%s) because there is no corresponding mapping configured.',
                                    $roleIdentifier,
                                    $this->identityToken->values['sub'] ?? ''
                                ),
                                LogEnvironment::fromMethodName(__METHOD__)
                            );
                            continue;
                        }
                        $roleIdentifier = $mapping[$roleIdentifier];
                    }
                    if ($this->policyService->hasRole($roleIdentifier)) {
                        $roleIdentifiers[] = $roleIdentifier;
                    } else {
                        $this->logger->debug(
                            sprintf(
                                'OpenID Connect: Ignoring role "%s" from identity token (%s) because there is no such role configured in Flow.',
                                $roleIdentifier,
                                $this->identityToken->values['sub'] ?? ''
                            ),
                            LogEnvironment::fromMethodName(__METHOD__)
                        );
                    }
                }
            }
        }
        if (isset($this->options['addRolesFromExistingAccount']) && $this->options['addRolesFromExistingAccount'] === true) {
            $accountIdentifier = $this->identityToken->values[$this->options['accountIdentifierTokenValueName']] ?? null;
            if ($accountIdentifier === null) {
                $this->logger->error(
                    sprintf(
                        'OpenID Connect: Failed using account identifier from from identity token (%s) because the configured claim "%s" does not exist.',
                        $this->identityToken->values['sub'] ?? '',
                        $this->options['accountIdentifierTokenValueName']
                    ),
                    LogEnvironment::fromMethodName(__METHOD__)
                );
            } else {
                $existingAccount = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName(
                    $accountIdentifier,
                    $this->name
                );
                if ( ! $existingAccount instanceof Account) {
                    $this->logger->notice(
                        sprintf(
                            'OpenID Connect: Could not add roles from existing account for identity token (%s) because the account "%s" (provider: %s) does not exist.',
                            $this->identityToken->values['sub'] ?? '',
                            $accountIdentifier,
                            $this->name
                        ),
                        LogEnvironment::fromMethodName(__METHOD__)
                    );
                } else {
                    foreach ($existingAccount->getRoles() as $role) {
                        $roleIdentifiers[] = $role->getIdentifier();
                    }
                    $this->logger->debug(
                        sprintf(
                            'OpenID Connect: Added roles (identity token %s) from existing account "%s"',
                            $this->identityToken->values['sub'] ?? '',
                            $existingAccount->getAccountIdentifier()
                        ),
                        LogEnvironment::fromMethodName(__METHOD__)
                    );
                }
            }
        }

        return array_unique($roleIdentifiers);
    }
}
