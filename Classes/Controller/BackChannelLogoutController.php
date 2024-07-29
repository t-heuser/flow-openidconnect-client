<?php

namespace Flownative\OpenIdConnect\Client\Controller;

use Exception;
use Flownative\OpenIdConnect\Client\Exceptions\LogoutTokenClaimValidationException;
use Flownative\OpenIdConnect\Client\LogoutToken;
use Flownative\OpenIdConnect\Client\OpenIdConnectClient;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Flow\Mvc\Exception\NoSuchArgumentException;
use Neos\Flow\Mvc\Exception\StopActionException;
use Neos\Flow\Session\SessionManagerInterface;
use Psr\Log\LoggerInterface;

/**
 * Class BackChannelLogoutController
 *
 * This controller can be configured to be used as endpoint to implement a back channel logout as defined in
 * https://openid.net/specs/openid-connect-backchannel-1_0.html.
 */
final class BackChannelLogoutController extends ActionController
{
    /**
     * @Flow\Inject(name="Neos.Flow:SecurityLogger")
     * @var LoggerInterface
     */
    protected $securityLogger;

    /**
     * @Flow\Inject
     * @var SessionManagerInterface
     */
    protected $sessionManager;

    /**
     * @throws StopActionException
     */
    public function indexAction(string $serviceName): void
    {
        $openIdConnectClient = new OpenIdConnectClient($serviceName);
        try {
            $logoutToken = new LogoutToken();
            $logoutToken->setDataFromJwt($this->request->getArgument('logout_token'), $serviceName);

            $logoutToken->verifyLogoutTokenClaims($openIdConnectClient);
        } catch (NoSuchArgumentException $exception) {
            $this->returnError('No logout_token provided.');
        } catch (LogoutTokenClaimValidationException $exception) {
            $this->securityLogger->info(
                'A given logout token was invalid: '.$exception->getMessage()
            );
            $this->returnError($exception->getMessage());
        } catch (Exception $exception) {
            $this->securityLogger->info(
                'A given logout token was invalid or another error occurred: '.$exception->getMessage()
            );
            $this->returnError('A given logout token was invalid or another error occurred: '.$exception->getMessage());
        }

        // One of these will be present as it was verified before.
        $sessionIdentifier = $logoutToken->getValues()['sub'] ?? $logoutToken->getValues()['sid'];

        $tagPrefix = md5("Flownative-OpenIdConnect-Client-$serviceName");
        $this->sessionManager->destroySessionsByTag(
            "$tagPrefix-$sessionIdentifier",
            'A valid back channel logout request was received for this session.'
        );

        $this->securityLogger->info(
            'A valid back channel logout request was received for the Flownative-OpenIdConnect-Client-'.$sessionIdentifier
        );

        $this->throwStatus(200);
    }

    /**
     * @throws StopActionException
     * @return never
     */
    private function returnError(string $errorMessage)
    {
        $this->response->setContentType('application/json');
        $this->throwStatus(
            400,
            null,
            json_encode(['error' => 'invalid_request', 'error_description' => $errorMessage])
        );
    }
}
