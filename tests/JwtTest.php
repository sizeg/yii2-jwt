<?php

namespace sizeg\jwt\tests;

use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use sizeg\jwt\Jwt;

class JwtTest extends TestCase
{

    /**
     * Secret key
     */
    const SECRET = 'secret';

    /**
     * Issuer
     */
    const ISSUER = 'http://example.com';

    /**
     * Audience
     */
    const AUDIENCE = 'http://example.org';

    /**
     * Id
     */
    const ID = '4f1g23a12aa';

    /**
     * @var Jwt
     */
    public $jwt;

    /**
     * @ineritdoc
     */
    public function setUp()
    {
        $this->jwt = \Yii::createObject(Jwt::class, [
            ['key' => self::SECRET]
        ]);
    }

    /**
     * @return Signer
     */
    private function getSigner()
    {
        return $this->jwt->getSigner('HS256');
    }

    /**
     * @return Key
     */
    private function getSigningKey()
    {
        return $this->jwt->getKey();
    }

    /**
     * @return Token created token
     */
    private function createTokenWithSignature()
    {
        // creates a signature using "testing" as key
        $signer = $this->getSigner();
        $key = $this->getSigningKey();

        $now = new \DateTimeImmutable();

        return $this->getConfiguration()->builder()
            ->issuedBy(self::ISSUER) // Configures the issuer (iss claim)
            ->permittedFor(self::AUDIENCE) // Configures the audience (aud claim)
            ->identifiedBy(self::ID) // Configures the id (jti claim), replicating as a header item
            //->canOnlyBeUsedAfter($now->modify('+1 minute')) // Configures the time that the token can be used (nbf claim)
            ->issuedAt($now) // Configures the time that the token was issue (iat claim)
            ->expiresAt($now->modify('+1 hour')) // Configures the expiration time of the token (nbf claim)
            ->withClaim('uid', 1) // Configures a new claim, called "uid"
            ->withHeader('foo', 'bar') // Configures a new header, called "foo"
            ->getToken($signer, $key); // Retrieves the generated token
    }

    /**
     * @return Configuration
     */
    private function getConfiguration()
    {
        return $this->jwt->getConfiguratuionforSymmetricSigner($this->getSigner(), $this->getSigningKey());
    }

    /**
     * Validate token with signature
     */
    public function testValidateTokenWithSignature()
    {
        $token = $this->createTokenWithSignature();
        self::assertInstanceOf(Token\Plain::class, $token);

        $configuration = $this->getConfiguration();
        $configuration->setValidationConstraints(
            new IdentifiedBy(self::ID),
            new IssuedBy(self::ISSUER),
            new PermittedFor(self::AUDIENCE)
        );

        $constraints = $configuration->validationConstraints();
        self::assertTrue($configuration->validator()->validate($token, ...$constraints), 'Token validation failed');
    }

    /**
     * Validate token timeout with signature
     */
    public function testValidateTokenTimeWithSignature()
    {
        $token = $this->createTokenWithSignature();
        self::assertInstanceOf(Token\Plain::class, $token);

        $token_exp = $token->claims()->get(RegisteredClaims::EXPIRATION_TIME);
        self::assertNotNull($token_exp);

        // Changing the token exp time to future
        $failed_clock = new FrozenClock($token_exp->modify('+1 minute'));

        $configuration = $this->getConfiguration();
        $configuration->setValidationConstraints(
            new ValidAt($failed_clock)
        );

        $constraints = $configuration->validationConstraints();
        self::assertFalse($configuration->validator()->validate($token, ...$constraints), 'Token time validation failed');
    }
}
