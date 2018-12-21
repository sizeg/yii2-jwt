<?php

namespace sizeg\jwt;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Claim\Factory as ClaimFactory;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Parsing\Decoder;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Yii;
use yii\base\Component;
use yii\base\InvalidArgumentException;

/**
 * JSON Web Token implementation, based on this library:
 * https://github.com/lcobucci/jwt
 *
 * @author Dmitriy Demin <sizemail@gmail.com>
 * @since 1.0.0-a
 */
class Jwt extends Component
{

    /**
     * @var array Supported algorithms
     */
    public $supportedAlgs = [
        'HS256' => 'Lcobucci\JWT\Signer\Hmac\Sha256',
        'HS384' => 'Lcobucci\JWT\Signer\Hmac\Sha384',
        'HS512' => 'Lcobucci\JWT\Signer\Hmac\Sha512',
        'ES256' => 'Lcobucci\JWT\Signer\Ecdsa\Sha256',
        'ES384' => 'Lcobucci\JWT\Signer\Ecdsa\Sha384',
        'ES512' => 'Lcobucci\JWT\Signer\Ecdsa\Sha512',
        'RS256' => 'Lcobucci\JWT\Signer\Rsa\Sha256',
        'RS384' => 'Lcobucci\JWT\Signer\Rsa\Sha384',
        'RS512' => 'Lcobucci\JWT\Signer\Rsa\Sha512',
    ];

    /**
     * @var Key|string $key The key
     */
    public $key;

    /**
     * @see [[Lcobucci\JWT\Builder::__construct()]]
     * @return Builder
     */
    public function getBuilder(Encoder $encoder = null, ClaimFactory $claimFactory = null)
    {
        return new Builder($encoder, $claimFactory);
    }

    /**
     * @see [[Lcobucci\JWT\Parser::__construct()]]
     * @return Parser
     */
    public function getParser(Decoder $decoder = null, ClaimFactory $claimFactory = null)
    {
        return new Parser($decoder, $claimFactory);
    }

    /**
     * @see [[Lcobucci\JWT\ValidationData::__construct()]]
     * @return ValidationData
     */
    public function getValidationData($currentTime = null)
    {
        return new ValidationData($currentTime);
    }

    /**
     * Parses the JWT and returns a token class
     * @param string $token JWT
     * @return Token|null
     * @throws \Throwable
     */
    public function loadToken($token, $validate = true, $verify = true)
    {
        try {
            $token = $this->getParser()->parse((string) $token);
        } catch (\RuntimeException $e) {
            Yii::warning("Invalid JWT provided: " . $e->getMessage(), 'jwt');
            return null;
        } catch (\InvalidArgumentException $e) {
            Yii::warning("Invalid JWT provided: " . $e->getMessage(), 'jwt');
            return null;
        }

        if ($validate && !$this->validateToken($token)) {
            return null;
        }

        if ($verify && !$this->verifyToken($token)) {
            return null;
        }

        return $token;
    }

    /**
     * Validate token
     * @param Token $token token object
     * @return bool
     */
    public function validateToken(Token $token, $currentTime = null)
    {
        $data = $this->getValidationData($currentTime);
        // @todo Add claims for validation

        return $token->validate($data);
    }

    /**
     * Validate token
     * @param Token $token token object
     * @return bool
     * @throws \Throwable
     */
    public function verifyToken(Token $token)
    {
        $alg = $token->getHeader('alg');

        if (empty($this->supportedAlgs[$alg])) {
            throw new InvalidArgumentException('Algorithm not supported');
        }

        /** @var Signer $signer */
        $signer = Yii::createObject($this->supportedAlgs[$alg]);

        return $token->verify($signer, $this->key);
    }
}
