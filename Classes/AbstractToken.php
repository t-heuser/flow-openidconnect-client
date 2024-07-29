<?php

namespace Flownative\OpenIdConnect\Client;

use DateTimeInterface;
use Flownative\OpenIdConnect\Client\Exceptions\ServiceException;
use InvalidArgumentException;
use JsonException;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Math\BigInteger;
use Throwable;

/**
 * Class AbstractToken
 */
abstract class AbstractToken
{
    protected ?string $jwt = null;

    private array $header = [];

    private ?Token $parsedJwt = null;

    private string $payload = '';

    private string $signature = '';

    private string $oidcServiceName = '';

    private array $values = [];

    public function getValues(): array
    {
        return $this->values;
    }

    /**
     * @see https://tools.ietf.org/html/rfc7519
     * @throws InvalidArgumentException
     */
    public function setDataFromJwt(string $jwt, string $oidcServiceName): void
    {
        $this->jwt = $jwt;
        $this->oidcServiceName = $oidcServiceName;

        if (preg_match('/^[a-zA-Z0-9=_-]+\.([a-zA-Z0-9=_-]+\.)+[a-zA-Z0-9=_-]+$/', $jwt) !== 1) {
            throw new InvalidArgumentException('The given string was not a valid encoded identity token.', 1559204596);
        }

        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException(
                'The given JWT does not have exactly 3 parts (header, payload, signature), which is currently not supported by this implementation.',
                1559208004
            );
        }

        // The JSON Web Signature (JWS), see https://tools.ietf.org/html/rfc7515
        $this->signature = $this->base64UrlDecode(array_pop($parts));
        if (empty($this->signature)) {
            throw new InvalidArgumentException('Failed decoding signature from JWT.', 1559207444);
        }

        // The JOSE Header (JSON Object Signing and Encryption), see: https://tools.ietf.org/html/rfc7515
        try {
            $this->header = json_decode($this->base64UrlDecode($parts[0]), true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable $e) {
            throw new InvalidArgumentException('Failed decoding JOSE header from JWT.', 1603362934, $e);
        }
        if ( ! isset($this->header['alg'])) {
            throw new InvalidArgumentException('Missing signature algorithm in JOSE header from JWT.', 1559212231);
        }

        // The JWT payload, including header, sans signature
        $this->payload = implode('.', $parts);

        try {
            $identityTokenArray = json_decode($this->base64UrlDecode($parts[1]), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidArgumentException('Failed decoding identity token from JWT.', 1603362918, $e);
        }
        if ( ! is_array($identityTokenArray)) {
            throw new InvalidArgumentException('Failed decoding identity token from JWT.', 1559208043);
        }

        $jwtParser = new Token\Parser(new JoseEncoder());

        $this->values = $identityTokenArray;
        $this->parsedJwt = $jwtParser->parse($jwt);
    }

    public function asJwt(): string
    {
        return $this->jwt ?? '';
    }

    public function __toString(): string
    {
        return $this->asJwt();
    }

    /**
     * Verify the signature (JWS) of this token using a given JWK
     *
     * @param  array  $jwks  The JSON Web Keys to use for verification
     * @return bool
     * @throws ServiceException
     * @see https://tools.ietf.org/html/rfc7517
     */
    public function hasValidSignature(array $jwks): bool
    {
        if (in_array($this->header['alg'], ['RS256', 'RS384', 'RS512'])) {
            return $this->verifyRsaJwtSignature(
                'sha'.substr($this->header['alg'], 2),
                $this->getMatchingKeyForJws($jwks, $this->header['alg'], $this->header['kid'] ?? null),
                $this->payload,
                $this->signature
            );
        }

        throw new ServiceException(
            sprintf('Unsupported JWT signature type %s.', $this->header['alg']),
            1559213623
        );
    }

    public function hasValidAudience(string $expectedAudience): bool
    {
        if ( ! isset($this->getValues()['aud'])) {
            return false;
        }

        if (is_array(($this->getValues()['aud']))) {
            return in_array($expectedAudience, $this->getValues()['aud'], true);
        }

        return $expectedAudience === $this->getValues()['aud'];
    }

    /**
     * @param  DateTimeInterface  $now
     * @return bool
     */
    public function isExpiredAt(DateTimeInterface $now): bool
    {
        if ($this->parsedJwt === null) {
            return true;
        }

        return $this->parsedJwt->isExpired($now);
    }

    /**
     * @return string The configured service name of the oidc provider this token was build with.
     */
    public function getOidcServiceName(): string
    {
        return $this->oidcServiceName;
    }

    /**
     * Verifies a signature for the given payload using the given JSON web key and hash type.
     *
     * @param  string  $hashType  The used hash type, for example SHA256, SHA384 or SHA512
     * @param  array  $jwk  The JSON Web Key as an array, with array keys like "kid", "kty", "use", "alg", "exp" etc.
     * @param  string  $payload  The JWT payload, including header
     * @param  string  $signature  The JWS
     * @return bool
     */
    private function verifyRsaJwtSignature(string $hashType, array $jwk, string $payload, string $signature): bool
    {
        if ( ! isset($jwk['n'], $jwk['e'])) {
            throw new InvalidArgumentException(
                'Failed verifying RSA JWT signature because of an invalid JSON Web Key.',
                1559214667
            );
        }
        $key = PublicKeyLoader::load([
            'e' => new BigInteger($this->base64UrlDecode($jwk['e']), 256),
            'n' => new BigInteger($this->base64UrlDecode($jwk['n']), 256),
        ])
            ->withHash($hashType)
            ->withPadding(RSA::SIGNATURE_PKCS1);

        return $key->verify($payload, $signature);
    }

    /**
     * Returns the matching JWK from the given list of keys, according to the specified algorithm and optional key identifier
     *
     * @param  array  $keys
     * @param  string  $algorithm
     * @param  string|null  $keyIdentifier
     * @return array
     * @throws ServiceException
     */
    private function getMatchingKeyForJws(array $keys, string $algorithm, ?string $keyIdentifier): array
    {
        foreach ($keys as $key) {
            if ($key['kty'] === 'RSA') {
                if ($keyIdentifier === null || ! isset($key['kid']) || $key['kid'] === $keyIdentifier) {
                    return $key;
                }
            } else {
                if (isset($key['alg']) && $key['alg'] === $algorithm && $key['kid'] === $keyIdentifier) {
                    return $key;
                }
            }
        }
        if ( ! empty($keyIdentifier)) {
            throw new ServiceException(
                sprintf(
                    'Failed finding a matching JSON Web Key using algorithm %s for key identifier %s.',
                    $algorithm,
                    $keyIdentifier
                ), 1559213482
            );
        }
        throw new ServiceException(
            sprintf('Failed finding a matching JSON Web Key using RSA for key identifier %s.', $keyIdentifier),
            1559213507
        );
    }

    /**
     * Decode Base64URL-encoded data
     *
     * @param  string  $base64UrlEncodedString
     * @return string
     */
    private function base64UrlDecode(string $base64UrlEncodedString): string
    {
        $padding = strlen($base64UrlEncodedString) % 4;
        if ($padding > 0) {
            $base64UrlEncodedString .= str_repeat('=', 4 - $padding);
        }

        return base64_decode(strtr($base64UrlEncodedString, '-_', '+/'));
    }
}
