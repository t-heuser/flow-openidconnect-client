<?php

namespace Tests\Unit;

/*
 * This file is part of the Flownative.OpenIdConnect.Client package.
 *
 * (c) Robert Lemke, Flownative GmbH - www.flownative.com
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Flownative\OpenIdConnect\Client\IdentityToken;
use InvalidArgumentException;
use Neos\Flow\Session\SessionInterface;
use Neos\Flow\Session\SessionManagerInterface;
use PHPUnit\Framework\MockObject\MockObject;

class IdentityTokenTest extends TestCase
{
    private MockObject&SessionManagerInterface $sessionManagerMock;

    protected function setUp(): void
    {
        parent::setUp();

        $this->sessionManagerMock = $this->createMock(SessionManagerInterface::class);
        $sessionMock = $this->createMock(SessionInterface::class);

        $this->sessionManagerMock->method('getCurrentSession')->willReturn($sessionMock);
    }

    public function invalidJsonStrings(): array
    {
        return [
            ['xy', 1559204596],
            ['abc.def.ghi.foo..', 1559204596],
            ['header.payload.signature.something', 1559208004],
            ['header.payload.signature.=', 1559208004],
            [
                'ImludmFsaWRfaGVhZGVyIg==.eyJpc3MiOiJodHRwczovL2lkLmV4YW1wbGUuY29tIiwiYXVkIjoiQCFEREQ1LjM3MEQuODU0Ny5GRkQ5ITAwMDEhQTFDOS45MkMxITAwMDghMTNEQi41NEQ4LjY1REUuMjc2MSIsImV4cCI6MTU1OTIwNTU2MCwiaWF0IjoxNTU5MjAxOTYwLCJhdXRoX3RpbWUiOjE1NTkyMDE5NTksImF0X2hhc2giOiJfU1BHdHM1OUlTbFdNSHhzMmEwM3N3Iiwib3hPcGVuSURDb25uZWN0VmVyc2lvbiI6Im9wZW5pZGNvbm5lY3QtMS4wIiwic3ViIjoiVVdBWWZ6em1jYU5BWnlfQzhhOFVvVXhNbWhUMUlsY0tsWEc4VG5Xa3lJTSJ9.VsOdosHuRWVaoacWG1CNJl0IZrHH-HbFTCZDcQDtFPSma13sHO-C69tm_HTjHX5DnMX6B_lDCgu3A8AsSZIQEG71z_Mnd2uxHoUrKUtHr8iM9bhpPKMnaXx9jr0O1EtKAJDLkz4qdzNunyOU7Ud94Lc8YxIjf7FZH_-jJc0UqFyFKY2rdEiZQVATNG94F-SIWA4CK5FZtW47TCL8EPBUzP8gGG8g6eMBEIfv80uWQxpJ59_UB91D8U6zSOiA4JrFDBRLkIX2kGnUZ7eu1G-4O6TglL_Id0oMeJdNEsMARYKHGmYZjvHGFVoLyoxca1KDK5dlcnLsYyxfKsZWNrTaqA',
                1603362934,
            ],
            [
                'eyJraWQiOiJkZmViZTVlNy00MjMyLTQ0NjQtOGYyZS0xNTE2ODFhMGQxNzMiLCJ0eXAiOiJKV1QifQ==.eyJpc3MiOiJodHRwczovL2lkLmV4YW1wbGUuY29tIiwiYXVkIjoiQCFEREQ1LjM3MEQuODU0Ny5GRkQ5ITAwMDEhQTFDOS45MkMxITAwMDghMTNEQi41NEQ4LjY1REUuMjc2MSIsImV4cCI6MTU1OTIwNTU2MCwiaWF0IjoxNTU5MjAxOTYwLCJhdXRoX3RpbWUiOjE1NTkyMDE5NTksImF0X2hhc2giOiJfU1BHdHM1OUlTbFdNSHhzMmEwM3N3Iiwib3hPcGVuSURDb25uZWN0VmVyc2lvbiI6Im9wZW5pZGNvbm5lY3QtMS4wIiwic3ViIjoiVVdBWWZ6em1jYU5BWnlfQzhhOFVvVXhNbWhUMUlsY0tsWEc4VG5Xa3lJTSJ9.VsOdosHuRWVaoacWG1CNJl0IZrHH-HbFTCZDcQDtFPSma13sHO-C69tm_HTjHX5DnMX6B_lDCgu3A8AsSZIQEG71z_Mnd2uxHoUrKUtHr8iM9bhpPKMnaXx9jr0O1EtKAJDLkz4qdzNunyOU7Ud94Lc8YxIjf7FZH_-jJc0UqFyFKY2rdEiZQVATNG94F-SIWA4CK5FZtW47TCL8EPBUzP8gGG8g6eMBEIfv80uWQxpJ59_UB91D8U6zSOiA4JrFDBRLkIX2kGnUZ7eu1G-4O6TglL_Id0oMeJdNEsMARYKHGmYZjvHGFVoLyoxca1KDK5dlcnLsYyxfKsZWNrTaqA',
                1559212231,
            ],
            [
                'eyJraWQiOiJkZmViZTVlNy00MjMyLTQ0NjQtOGYyZS0xNTE2ODFhMGQxNzMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.InNvbWV0aGluZyI=.VsOdosHuRWVaoacWG1CNJl0IZrHH-HbFTCZDcQDtFPSma13sHO-C69tm_HTjHX5DnMX6B_lDCgu3A8AsSZIQEG71z_Mnd2uxHoUrKUtHr8iM9bhpPKMnaXx9jr0O1EtKAJDLkz4qdzNunyOU7Ud94Lc8YxIjf7FZH_-jJc0UqFyFKY2rdEiZQVATNG94F-SIWA4CK5FZtW47TCL8EPBUzP8gGG8g6eMBEIfv80uWQxpJ59_UB91D8U6zSOiA4JrFDBRLkIX2kGnUZ7eu1G-4O6TglL_Id0oMeJdNEsMARYKHGmYZjvHGFVoLyoxca1KDK5dlcnLsYyxfKsZWNrTaqA',
                1559208043,
            ],
        ];
    }

    /**
     * @test
     * @dataProvider invalidJsonStrings
     * @throws
     */
    public function fromJsonRejectsInvalidJsonStrings(string $json, int $expectedExceptionCode): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionCode($expectedExceptionCode);
        $identityToken = new IdentityToken();
        $this->inject($identityToken, 'sessionManager', $this->sessionManagerMock);
        $identityToken->setDataFromJwt($json, 'foo');
    }

    /**
     * {"kid":"dfebe5e7-4232-4464-8f2e-151681a0d173","typ":"JWT","alg":"RS256"}
     * {"iss":"https://id.example.com","aud":"@!DDD5.370D.8547.FFD9!0001!A1C9.92C1!0008!13DB.54D8.65DE.2761","exp":1559205560,"iat":1559201960,"auth_time":1559201959,"at_hash":"_SPGts59ISlWMHxs2a03sw","oxOpenIDConnectVersion":"openidconnect-1.0","sub":"UWAYfzzmcaNAZy_C8a8UoUxMmhT1IlcKlXG8TnWkyIM"}
     * … (binary data of signature) …
     *
     * @test
     * @throws
     */
    public function fromJsonSetsValuesCorrectly(): void
    {
        $json = 'eyJraWQiOiJkZmViZTVlNy00MjMyLTQ0NjQtOGYyZS0xNTE2ODFhMGQxNzMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkLmV4YW1wbGUuY29tIiwiYXVkIjoiQCFEREQ1LjM3MEQuODU0Ny5GRkQ5ITAwMDEhQTFDOS45MkMxITAwMDghMTNEQi41NEQ4LjY1REUuMjc2MSIsImV4cCI6MTU1OTIwNTU2MCwiaWF0IjoxNTU5MjAxOTYwLCJhdXRoX3RpbWUiOjE1NTkyMDE5NTksImF0X2hhc2giOiJfU1BHdHM1OUlTbFdNSHhzMmEwM3N3Iiwib3hPcGVuSURDb25uZWN0VmVyc2lvbiI6Im9wZW5pZGNvbm5lY3QtMS4wIiwic3ViIjoiVVdBWWZ6em1jYU5BWnlfQzhhOFVvVXhNbWhUMUlsY0tsWEc4VG5Xa3lJTSJ9.VsOdosHuRWVaoacWG1CNJl0IZrHH-HbFTCZDcQDtFPSma13sHO-C69tm_HTjHX5DnMX6B_lDCgu3A8AsSZIQEG71z_Mnd2uxHoUrKUtHr8iM9bhpPKMnaXx9jr0O1EtKAJDLkz4qdzNunyOU7Ud94Lc8YxIjf7FZH_-jJc0UqFyFKY2rdEiZQVATNG94F-SIWA4CK5FZtW47TCL8EPBUzP8gGG8g6eMBEIfv80uWQxpJ59_UB91D8U6zSOiA4JrFDBRLkIX2kGnUZ7eu1G-4O6TglL_Id0oMeJdNEsMARYKHGmYZjvHGFVoLyoxca1KDK5dlcnLsYyxfKsZWNrTaqA';
        $identityToken = new IdentityToken();
        $this->inject($identityToken, 'sessionManager', $this->sessionManagerMock);
        $identityToken->setDataFromJwt($json, 'foo');

        $this->assertSame('https://id.example.com', $identityToken->values['iss']);
        $this->assertSame('UWAYfzzmcaNAZy_C8a8UoUxMmhT1IlcKlXG8TnWkyIM', $identityToken->values['sub']);
        $this->assertSame(
            '@!DDD5.370D.8547.FFD9!0001!A1C9.92C1!0008!13DB.54D8.65DE.2761',
            $identityToken->values['aud']
        );
    }

    /**
     * @test
     * @throws
     */
    public function asJwtReturnsTokenAsString(): void
    {
        $json = 'eyJraWQiOiJkZmViZTVlNy00MjMyLTQ0NjQtOGYyZS0xNTE2ODFhMGQxNzMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkLmV4YW1wbGUuY29tIiwiYXVkIjoiQCFEREQ1LjM3MEQuODU0Ny5GRkQ5ITAwMDEhQTFDOS45MkMxITAwMDghMTNEQi41NEQ4LjY1REUuMjc2MSIsImV4cCI6MTU1OTIwNTU2MCwiaWF0IjoxNTU5MjAxOTYwLCJhdXRoX3RpbWUiOjE1NTkyMDE5NTksImF0X2hhc2giOiJfU1BHdHM1OUlTbFdNSHhzMmEwM3N3Iiwib3hPcGVuSURDb25uZWN0VmVyc2lvbiI6Im9wZW5pZGNvbm5lY3QtMS4wIiwic3ViIjoiVVdBWWZ6em1jYU5BWnlfQzhhOFVvVXhNbWhUMUlsY0tsWEc4VG5Xa3lJTSJ9.VsOdosHuRWVaoacWG1CNJl0IZrHH-HbFTCZDcQDtFPSma13sHO-C69tm_HTjHX5DnMX6B_lDCgu3A8AsSZIQEG71z_Mnd2uxHoUrKUtHr8iM9bhpPKMnaXx9jr0O1EtKAJDLkz4qdzNunyOU7Ud94Lc8YxIjf7FZH_-jJc0UqFyFKY2rdEiZQVATNG94F-SIWA4CK5FZtW47TCL8EPBUzP8gGG8g6eMBEIfv80uWQxpJ59_UB91D8U6zSOiA4JrFDBRLkIX2kGnUZ7eu1G-4O6TglL_Id0oMeJdNEsMARYKHGmYZjvHGFVoLyoxca1KDK5dlcnLsYyxfKsZWNrTaqA';
        $identityToken = new IdentityToken();
        $this->inject($identityToken, 'sessionManager', $this->sessionManagerMock);
        $identityToken->setDataFromJwt($json, 'foo');
        $this->assertSame($identityToken->asJwt(), $json);
        $this->assertSame((string)$identityToken, $json);
    }

    /**
     * @test
     */
    public function isExpiredAtReturnsCorrectResult(): void
    {
        $json = 'eyJraWQiOiJkZmViZTVlNy00MjMyLTQ0NjQtOGYyZS0xNTE2ODFhMGQxNzMiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkLmV4YW1wbGUuY29tIiwiYXVkIjoiQCFEREQ1LjM3MEQuODU0Ny5GRkQ5ITAwMDEhQTFDOS45MkMxITAwMDghMTNEQi41NEQ4LjY1REUuMjc2MSIsImV4cCI6MTU1OTIwNTU2MCwiaWF0IjoxNTU5MjAxOTYwLCJhdXRoX3RpbWUiOjE1NTkyMDE5NTksImF0X2hhc2giOiJfU1BHdHM1OUlTbFdNSHhzMmEwM3N3Iiwib3hPcGVuSURDb25uZWN0VmVyc2lvbiI6Im9wZW5pZGNvbm5lY3QtMS4wIiwic3ViIjoiVVdBWWZ6em1jYU5BWnlfQzhhOFVvVXhNbWhUMUlsY0tsWEc4VG5Xa3lJTSJ9.VsOdosHuRWVaoacWG1CNJl0IZrHH-HbFTCZDcQDtFPSma13sHO-C69tm_HTjHX5DnMX6B_lDCgu3A8AsSZIQEG71z_Mnd2uxHoUrKUtHr8iM9bhpPKMnaXx9jr0O1EtKAJDLkz4qdzNunyOU7Ud94Lc8YxIjf7FZH_-jJc0UqFyFKY2rdEiZQVATNG94F-SIWA4CK5FZtW47TCL8EPBUzP8gGG8g6eMBEIfv80uWQxpJ59_UB91D8U6zSOiA4JrFDBRLkIX2kGnUZ7eu1G-4O6TglL_Id0oMeJdNEsMARYKHGmYZjvHGFVoLyoxca1KDK5dlcnLsYyxfKsZWNrTaqA';
        $identityToken = new IdentityToken();
        $this->inject($identityToken, 'sessionManager', $this->sessionManagerMock);
        $identityToken->setDataFromJwt($json, 'foo');

        # Token expired at 2019-05-30 08:39:20.000000
        $this->assertFalse(
            $identityToken->isExpiredAt(\DateTimeImmutable::createFromFormat('d.m.Y H:i:s', '29.05.2019 09:00:00'))
        );
        $this->assertTrue(
            $identityToken->isExpiredAt(\DateTimeImmutable::createFromFormat('d.m.Y H:i:s', '31.05.2019 09:00:00'))
        );
    }
}
