<?php

namespace jwttests;

class JwtTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Secret key
     */
    const SECRET = 'secret';
    
    /**
     * @var Jwt
     */
    public $jwt;
    
    public function setUp()
    {
        $this->jwt = \yii\di\Instance::ensure($this->jwt, \sizeg\jwt\Jwt::className());
    }
    
    /**
     * @return strin created token
     */
    public function createTokenWithSignature()
    {
        $signer = new \Lcobucci\JWT\Signer\Hmac\Sha256();
        
        return $this->jwt->getBuilder()->setIssuer('http://example.com') // Configures the issuer (iss claim)
                        ->setAudience('http://example.org') // Configures the audience (aud claim)
                        ->setId('4f1g23a12aa', true) // Configures the id (jti claim), replicating as a header item
                        ->setIssuedAt(time()) // Configures the time that the token was issue (iat claim)
                        ->setNotBefore(time() + 60) // Configures the time that the token can be used (nbf claim)
                        ->setExpiration(time() + 3600) // Configures the expiration time of the token (nbf claim)
                        ->set('uid', 1) // Configures a new claim, called "uid"
                        ->sign($signer, 'testing') // creates a signature using "testing" as key
                        ->getToken(); // Retrieves the generated token
    }
}