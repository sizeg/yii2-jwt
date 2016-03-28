<?php

namespace sizeg\jwt;

/**
 * Description of JwtToken
 *
 * @author ddemin
 */
class JwtToken extends \yii\base\DynamicModel
{

    /**
     * @var \Lcobucci\JWT\Token
     */
    public $token;

    public function __construct(\Lcobucci\JWT\Token $token, $config = [])
    {
        $this->headers = $token->headers;
        $this->claims = $token->claims;
        $this->signature = $token->signature;
        $this->payload = $token->payload;
    }
}
