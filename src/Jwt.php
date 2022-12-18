<?php

declare(strict_types=1);

namespace sizeg\jwt;

use BadMethodCallException;
use Closure;
use Lcobucci\JWT\Builder as BuilderInterface;
use Lcobucci\JWT\ClaimsFormatter as ClaimsFormatterInterface;
use Lcobucci\JWT\Decoder as DecoderInterface;
use Lcobucci\JWT\Encoder as EncoderInterface;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Encoding\MicrosecondBasedDateConversion;
use Lcobucci\JWT\Encoding\UnifyAudience;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Signer as SignerInterface;
use Lcobucci\JWT\Signer\Key as KeyInterface;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token as TokenInterface;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\Validation\Constraint as ConstraintInterface;
use Lcobucci\JWT\Validation\Validator;
use Lcobucci\JWT\Validator as ValidatorInterface;
use sizeg\jwt\Encoding\ChainedFormatter;
use yii\base\Component;
use yii\di\Instance;

/**
 * @property-read ParserInterface $parser
 * @property-read ValidatorInterface $validator
 */
final class Jwt extends Component implements JwtSigner, JwtKey
{

    /**
     * @var BuilderInterface|string
     */
    public $builder = Builder::class;

    /**
     * @var EncoderInterface|array|string
     */
    public $encoder = JoseEncoder::class;

    /**
     * @var DecoderInterface|array|string
     */
    public $decoder = JoseEncoder::class;

    /**
     * @var ClaimsFormatterInterface|array|string
     */
    public $claimsFormatter = [
        'class' => ChainedFormatter::class,
        'formatters' => [
            UnifyAudience::class,
            MicrosecondBasedDateConversion::class,
        ],
    ];

    /**
     * @var string
     */
    public string $signer = JwtSigner::NONE;

    /**
     * @var int
     * You should specify \sizeg\jwt\Jwt::$signerKeyContents if value deffer from JwtKey::EMPTY
     */
    public int $signerKey = JwtKey::EMPTY;

    /**
     * @var Closure|string
     * Should not be empty string if \sizeg\jwt\Jwt::$signerKey has other value than JwtKey::EMPTY
     */
    public $signerKeyContents = '';

    /**
     * @var string
     */
    public string $signerKeyPassphrase = '';

    /**
     * @var \Lcobucci\JWT\Validation\Constraint[]
     */
    public array $constraints;

    /**
     * @return BuilderInterface
     */
    public function getBuilder(): BuilderInterface
    {
        if (!$this->builder instanceof BuilderInterface) {
            $this->builder = new Builder(
                Instance::ensure($this->encoder, EncoderInterface::class),
                Instance::ensure($this->claimsFormatter, ClaimsFormatterInterface::class)
            );
        }

        return $this->builder;
    }

    /**
     * @param string|null $signer
     * @return SignerInterface
     */
    public function getSigner(?string $signer = null): SignerInterface
    {
        return Instance::ensure($signer ?: $this->signer, SignerInterface::class);
    }

    /**
     * @param int|null $signerKey
     * @param string|null $contents
     * @param string|null $passphrase
     * @return KeyInterface
     */
    public function getSignerKey(
        ?int $signerKey = null,
        ?string $contents = null,
        ?string $passphrase = null
    ): KeyInterface {
        $signerKey = $signerKey !== null ? $signerKey : $this->signerKey;
        $contents = $contents !== null ? $contents : $this->signerKeyContents;
        $passphrase = $passphrase !== null ? $passphrase : $this->signerKeyPassphrase;

        switch ($signerKey) {
            case JwtKey::EMPTY:
                $key = InMemory::empty();
                break;

            case JwtKey::PLAIN_TEXT:
                $key = InMemory::plainText($contents, $passphrase);
                break;

            case JwtKey::BASE64_ENCODED:
                $key = InMemory::base64Encoded($contents, $passphrase);
                break;

            case JwtKey::FILE:
                $key = InMemory::file($contents, $passphrase);
                break;

            default:
                throw new BadMethodCallException(
                    'This \sizeg\jwt\Jwt::$signerKey value "' . $signerKey . '" is not supported.'
                );
        }

        return $key;
    }

    /**
     * @return ParserInterface
     */
    public function getParser(): ParserInterface
    {
        static $parser = null;

        if ($parser === null) {
            $parser = new Parser(Instance::ensure($this->decoder, DecoderInterface::class));
        }

        return $parser;
    }

    /**
     * @param string $jwt
     * @return TokenInterface
     */
    public function parse(string $jwt): TokenInterface
    {
        return $this->getParser()->parse($jwt);
    }

    /**
     * @return ValidatorInterface
     */
    public function getValidator(): ValidatorInterface
    {
        static $validator = null;

        if ($validator === null) {
            $validator = new Validator();
        }

        return $validator;
    }

    /**
     * @param TokenInterface $token
     * @param ConstraintInterface ...$constraints
     * @return bool
     */
    public function validate(TokenInterface $token, ConstraintInterface ...$constraints): bool
    {
        return $this->getValidator()->validate($token, ...$constraints);
    }

    /**
     * @param TokenInterface $token
     * @param ConstraintInterface ...$constraints
     * @return void
     */
    public function assert(TokenInterface $token, ConstraintInterface ...$constraints): void
    {
        $this->getValidator()->assert($token, ...$constraints);
    }

    /**
     * @param string $jwt
     * @param bool $validate
     * @param bool $throwException
     * @return ?TokenInterface
     */
    public function loadToken(string $jwt, bool $validate = true, bool $throwException = true)
    {
        try {
            $token = $this->parse($jwt);
        } catch (CannotDecodeContent|InvalidTokenStructure|UnsupportedHeaderFound $e) {
            if ($throwException) {
                throw $e;
            }

            \Yii::warning('Invalid JWT provided: ' . $e->getMessage(), 'jwt');
            return null;
        }

        if ($validate && $this->constraints) {
            $constraints = [];
            foreach ($this->constraints as $constraint) {
                if ($constraint instanceof Closure) {
                    $constraints[] = call_user_func($constraint);
                } elseif ($constraint instanceof ConstraintInterface) {
                    $constraints[] = $constraint;
                } else {
                    $constraints[] = Instance::ensure($constraint, ConstraintInterface::class);
                }
            }

            if ($throwException) {
                $this->assert($token, ...$constraints);
            } else {
                $this->validate($token, ...$constraints);
            }
        }

        return $token;
    }
}