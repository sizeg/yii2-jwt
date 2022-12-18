<?php

declare(strict_types=1);

namespace sizeg\jwt\tests;

use DateTimeImmutable;
use Lcobucci\JWT\Builder as BuilderInterface;
use Lcobucci\JWT\Token as TokenInterface;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use sizeg\jwt\Jwt;
use sizeg\jwt\JwtKey;
use sizeg\jwt\JwtSigner;
use Yii;
use yii\base\InvalidConfigException;

class JwtTest extends TestCase
{

    /**
     *
     */
    private const TOKEN_ISSUED_BY = 'http://example.com';

    /**
     *
     */
    private const TOKEN_PERMITTED_FOR = 'http://example.org';

    /**
     *
     */
    private const TOKEN_IDENTIFIED_BY = '4f1g23a12aa';

    /**
     * @var Jwt
     */
    private Jwt $jwt;

    /**
     * @var Jwt
     */
    private Jwt $jwtSecured;

    protected function setUp(): void
    {
        parent::setUp();

        $this->jwt = Yii::createObject(Jwt::class);

        $this->jwtSecured = Yii::createObject([
            'class' => Jwt::class,
            'signer' => JwtSigner::HS256,
            'signerKey' => JwtKey::PLAIN_TEXT,
            'signerKeyContents' => random_bytes(32),
            'signerKeyPassphrase' => 'secret',
            'constraints' => [
                function () {
                    return new LooseValidAt(
                        \Lcobucci\Clock\SystemClock::fromSystemTimezone(),
                    );
                },
                function () {
                    return new SignedWith(
                        $this->jwtSecured->getSigner(),
                        $this->jwtSecured->getSignerKey(),
                    );
                },
            ],
        ]);
    }

    /**
     * @return BuilderInterface
     */
    private function getBuilder(): BuilderInterface
    {
        $now = new DateTimeImmutable();

        return $this->jwt->getBuilder()
            // Configures the issuer (iss claim)
            ->issuedBy('http://example.com')
            // Configures the audience (aud claim)
            ->permittedFor('http://example.org')
            // Configures the id (jti claim)
            ->identifiedBy('4f1g23a12aa')
            // Configures the time that the token was issue (iat claim)
            ->issuedAt($now)
            // Configures the time that the token can be used (nbf claim)
            ->canOnlyBeUsedAfter($now->modify('+1 minute'))
            // Configures the expiration time of the token (exp claim)
            ->expiresAt($now->modify('+1 hour'))
            // Configures a new claim, called "uid"
            ->withClaim('uid', 1)
            // Configures a new header, called "foo"
            ->withHeader('foo', 'bar');
    }

    private function buildUnsecuredToken(): TokenInterface
    {
        $now = new DateTimeImmutable();

        return $this->jwt->getBuilder()
            // Configures the issuer (iss claim)
            ->issuedBy(self::TOKEN_ISSUED_BY)
            // Configures the audience (aud claim)
            ->permittedFor(self::TOKEN_PERMITTED_FOR)
            // Configures the id (jti claim)
            ->identifiedBy(self::TOKEN_IDENTIFIED_BY)
            // Configures the time that the token was issue (iat claim)
            ->issuedAt($now)
            // Configures the time that the token can be used (nbf claim)
            ->canOnlyBeUsedAfter($now->modify('+2 second'))
            // Configures the expiration time of the token (exp claim)
            ->expiresAt($now->modify('+10 second'))
            // Configures a new claim, called "uid"
            ->withClaim('uid', 1)
            // Configures a new header, called "foo"
            ->withHeader('foo', 'bar')
            ->getToken(
                $this->jwt->getSigner(),
                $this->jwt->getSignerKey()
            );
    }

    private function buildSecuredHS256Token(): TokenInterface
    {
//        $now = new DateTimeImmutable();
        $clock = \Lcobucci\Clock\SystemClock::fromSystemTimezone();

        return $this->jwtSecured->getBuilder()
            // Configures the issuer (iss claim)
            ->issuedBy(self::TOKEN_ISSUED_BY)
            // Configures the audience (aud claim)
            ->permittedFor(self::TOKEN_PERMITTED_FOR)
            // Configures the id (jti claim)
            ->identifiedBy(self::TOKEN_IDENTIFIED_BY)
            // Configures the time that the token was issue (iat claim)
            ->issuedAt($clock->now())
            // Configures the time that the token can be used (nbf claim)
            ->canOnlyBeUsedAfter($clock->now()->modify('+2 second'))
            // Configures the expiration time of the token (exp claim)
//            ->expiresAt($clock->now()->modify('+10 second'))
            // Configures a new claim, called "uid"
            ->withClaim('uid', 1)
            // Configures a new header, called "foo"
            ->withHeader('foo', 'bar')
            ->getToken(
                $this->jwtSecured->getSigner(JwtSigner::HS256),
                $this->jwtSecured->getSignerKey(JwtKey::PLAIN_TEXT, $this->jwtSecured->signerKeyContents, $this->jwtSecured->signerKeyPassphrase)
            );
    }

    public function testIssuingToken()
    {
        $token = $this->buildUnsecuredToken();

        $this->assertTrue($token instanceof TokenInterface, 'Token should implements \Lcobucci\JWT\Token.');
    }

    public function testParsingToken()
    {
        $jwt = $this->buildUnsecuredToken()->toString();

        $token = $this->jwt->parse($jwt);

        $this->assertTrue($token instanceof TokenInterface, 'Token should implements \Lcobucci\JWT\Token.');
    }

    public function testValidatingToken()
    {
        $jwt = $this->buildUnsecuredToken()->toString();

        $token = $this->jwt->parse($jwt);

        self::assertTrue($this->jwt->validate($token, new IdentifiedBy(self::TOKEN_IDENTIFIED_BY)), 'IdentifiedBy');

        self::assertTrue($this->jwt->validate($token, new IssuedBy(self::TOKEN_ISSUED_BY)), 'IssuedBy');

        self::assertTrue($this->jwt->validate($token, new PermittedFor(self::TOKEN_PERMITTED_FOR)), 'PermittedFor');

        self::assertTrue($this->jwt->validate($token, new SignedWith($this->jwt->getSigner(), $this->jwt->getSignerKey())), 'SignedWith');
    }

    public function testIssuingHS256Token()
    {
        $token = $this->buildSecuredHS256Token();

        $this->assertTrue($token instanceof TokenInterface, 'Token should implements \Lcobucci\JWT\Token.');
    }

    public function testParsingHS256Token()
    {
        $jwt = $this->buildSecuredHS256Token()->toString();

        $token = $this->jwtSecured->parse($jwt);

        $this->assertTrue($token instanceof TokenInterface, 'Token should implements \Lcobucci\JWT\Token.');
    }

    public function testValidatingHS256Token()
    {
        $jwt = $this->buildSecuredHS256Token()->toString();

        $token = $this->jwtSecured->parse($jwt);

        self::assertTrue($this->jwtSecured->validate($token, new IdentifiedBy(self::TOKEN_IDENTIFIED_BY)), 'IdentifiedBy');

        self::assertTrue($this->jwtSecured->validate($token, new IssuedBy(self::TOKEN_ISSUED_BY)), 'IssuedBy');

        self::assertTrue($this->jwtSecured->validate($token, new PermittedFor(self::TOKEN_PERMITTED_FOR)), 'PermittedFor');

        self::assertTrue($this->jwtSecured->validate($token, new SignedWith(
            $this->jwtSecured->getSigner(JwtSigner::HS256),
            $this->jwtSecured->getSignerKey(JwtKey::PLAIN_TEXT)
        )), 'SignedWith');
    }

    public function testLoadHS256Token()
    {
        $jwt = $this->buildSecuredHS256Token()->toString();

        sleep(2);

        $token = $this->jwtSecured->loadToken($jwt, true, true);

        $this->assertTrue($token instanceof TokenInterface, 'Token should implements \Lcobucci\JWT\Token.');
    }
}
