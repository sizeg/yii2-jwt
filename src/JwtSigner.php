<?php

declare(strict_types=1);

namespace sizeg\jwt;

interface JwtSigner
{

    /**
     * None
     */
    public const NONE = \Lcobucci\JWT\Signer\None::class;

    /**
     * sha256
     */
    public const HS256 = \Lcobucci\JWT\Signer\Hmac\Sha256::class;

    /**
     * sha384
     */
    public const HS384 = \Lcobucci\JWT\Signer\Hmac\Sha384::class;

    /**
     * sha512
     */
    public const HS512 = \Lcobucci\JWT\Signer\Hmac\Sha512::class;

    /**
     * OPENSSL_ALGO_SHA256
     */
    public const ES256 = \Lcobucci\JWT\Signer\Ecdsa\Sha256::class;

    /**
     * OPENSSL_ALGO_SHA384
     */
    public const ES384 = \Lcobucci\JWT\Signer\Ecdsa\Sha384::class;

    /**
     * OPENSSL_ALGO_SHA512
     */
    public const ES512 = \Lcobucci\JWT\Signer\Ecdsa\Sha512::class;

    /**
     * OPENSSL_ALGO_SHA256
     */
    public const RS256 = \Lcobucci\JWT\Signer\Rsa\Sha256::class;

    /**
     * OPENSSL_ALGO_SHA384
     */
    public const RS384 = \Lcobucci\JWT\Signer\Rsa\Sha384::class;

    /**
     * OPENSSL_ALGO_SHA512
     */
    public const RS512 = \Lcobucci\JWT\Signer\Rsa\Sha512::class;
}