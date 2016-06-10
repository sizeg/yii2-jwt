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
        $this->jwt = \Yii::createObject(\sizeg\jwt\Jwt::className(), [
            'key' => self::SECRET
        ]);
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
                ->sign($signer, self::SECRET) // creates a signature using "testing" as key
                ->getToken(); // Retrieves the generated token
    }
    
    public function getValidationData()
    {
        $data = $this->jwt->getValidationData(); // It will use the current time to validate (iat, nbf and exp)
        $data->setIssuer('http://example.com');
        $data->setAudience('http://example.org');
        $data->setId('4f1g23a12aa');
        return $data;
    }

    public function testValidateTokenWithSignature()
    {
        $token = $this->createTokenWithSignature();
        $data = $this->getValidationData();
        $is_valid = $token->validate($data); // true, because validation information is equals to data contained on the token
        $this->assertTrue($is_valid);
    }
    
//    public function testValidateTokenTimeoutWithSignature()
//    {
//        $token = $this->createTokenWithSignature();
//        $data = $this->getValidationData();
//        $data->setCurrentTime(time() + 4000); // changing the validation time to future
//        $is_valid = $token->validate($data); // false, because token is expired since current time is greater than exp
//        $this->assertFalse($is_valid);
//    }
}
