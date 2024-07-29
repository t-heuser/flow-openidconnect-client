<?php

namespace Flownative\OpenIdConnect\Client;

use DateTimeImmutable;
use Exception;
use Flownative\OpenIdConnect\Client\Exceptions\LogoutTokenClaimValidationException;

/**
 * Value object for an OpenID Connect logout token
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken
 */
class LogoutToken extends AbstractToken
{
    /**
     * Verify each claim in the logout token according to the spec for back-channel logout.
     * @see https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation
     * @throws LogoutTokenClaimValidationException
     */
    public function verifyLogoutTokenClaims(OpenIdConnectClient $client): void
    {
        try {
            if ( ! $this->hasValidSignature($client->getJwks())) {
                throw new LogoutTokenClaimValidationException('The given logout token has an invalid signature.');
            }
        } catch (Exception $exception) {
            throw new LogoutTokenClaimValidationException(
                'An error occurred while verifying the logout token: '.$exception->getMessage(),
                $exception->getCode(),
                $exception
            );
        }

        // Verify that the Logout Token doesn't contain a nonce Claim.
        if (array_key_exists('nonce', $this->values)) {
            throw new LogoutTokenClaimValidationException('The given logout token contains the "nonce" parameter.');
        }

        // Verify that the logout token contains a sub or sid, or both.
        if ( ! array_key_exists('sid', $this->values) && ! array_key_exists('sub', $this->values)) {
            throw new LogoutTokenClaimValidationException(
                'The given logout token does not contain the "sid" or "sub" parameter.'
            );
        }

        /*
         * Verify that the Logout Token contains an events Claim whose value is a JSON object containing the member name
         * http://schemas.openid.net/event/backchannel-logout
         */
        if ( ! array_key_exists('events', $this->values)) {
            throw new LogoutTokenClaimValidationException(
                'The given logout token does not contain the "events" parameter.'
            );
        }

        $events = $this->values['events'] ?? '';
        if ( ! array_key_exists('http://schemas.openid.net/event/backchannel-logout', $events)) {
            throw new LogoutTokenClaimValidationException(
                'The given logout token contains an invalid "events" parameter.'
            );
        }

        // Validate the aud
        $expectedAudience = $client->getOptions()['clientId'];
        if ( ! empty($expectedAudience)) {
            if ( ! $this->hasValidAudience($expectedAudience)) {
                throw new LogoutTokenClaimValidationException(
                    'The given logout token does not contain a valid "aud" parameter.'
                );
            }
        }

        if ($client->getRealmUri() !== $this->values['iss']) {
            throw new LogoutTokenClaimValidationException(
                'The given logout token does not contain a valid "iss" parameter.'
            );
        }

        // Validate the iat
        if ($this->isExpiredAt(new DateTimeImmutable())) {
            throw new LogoutTokenClaimValidationException('The given logout token is expired.');
        }
    }
}

// todo write validator class for tokens, is now at two places (here and in OpenIdConnectProvider authenticate)
