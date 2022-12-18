# Yii2 JWT

![](https://travis-ci.org/sizeg/yii2-jwt.svg)

This extension provides the [JWT](https://github.com/lcobucci/jwt) integration for the [Yii framework 2.0](http://www.yiiframework.com) (requires PHP 5.6+).
It includes basic HTTP authentication support.

## Table of contents

1. [Installation](#installation)
2. [Dependencies](#dependencies)
3. [Basic usage](#basicusage)
   1. [Creating](#basicusage-creating)
   2. [Parsing from strings](#basicusage-parsing)
   3. [Validating](#basicusage-validating)
4. [Token signature](#tokensign)
   1. [Hmac](#tokensign-hmac)
   2. [RSA and ECDSA](#tokensign-rsa-ecdsa)
5. [Yii2 basic template example](#yii2basic-example)

<a name="#installation"></a>
## Installation

Package is available on [Packagist](https://packagist.org/packages/sizeg/yii2-jwt),
you can install it using [Composer](http://getcomposer.org).

```shell
composer require sizeg/yii2-jwt
```

<a name="dependencies"></a>
## Dependencies

- PHP 5.6+
- OpenSSL Extension
- [lcobucci/jwt 3.3](https://github.com/lcobucci/jwt/tree/3.3)

<a href="#basicusage"></a>
## Basic usage

Add `jwt` component to your configuration file,

```php
'components' => [
    'jwt' => [
        'class' => \sizeg\jwt\Jwt::class,
        'constraints' => [
            function () {
                return new \Lcobucci\JWT\Validation\Constraint\LooseValidAt(
                    \Lcobucci\Clock\SystemClock::fromSystemTimezone()
                );
            },
        ],
    ],
],
```

Configure the `authenticator` behavior as follows.

```php
namespace app\controllers;

class ExampleController extends \yii\rest\Controller
{

    /**
     * @inheritdoc
     */
    public function behaviors()
    {
        $behaviors = parent::behaviors();
        $behaviors['authenticator'] = [
            'class' => \sizeg\jwt\JwtHttpBearerAuth::class,
        ];

        return $behaviors;
    }
}
```

Also, you can use it with `CompositeAuth` refer to a [doc](http://www.yiiframework.com/doc-2.0/guide-rest-authentication.html).

<a name="basicusage-creating"></a>
### Creating

Just use the builder to create a new JWT/JWS tokens:

```php
$now = new DateTimeImmutable();
$algorithm = $this->jwt->getSigner();
$key = $this->jwt->getSignerKey();

$token = Yii::$app->jwt->getBuilder()
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
   // Builds a new token
   ->getToken($algorithm, $key);
   
$token->headers(); // Retrieves the token headers
$token->claims(); // Retrieves the token claims
   
echo $token->headers()->get('foo'); // will print "bar"
echo $token->claims()->get('jti'); // will print "4f1g23a12aa"
echo $token->claims()->get('iss'); // will print "http://example.com"
echo $token->claims()->get('uid'); // will print "1"
echo $token->toString(); // The string representation of the object is a JWT string (pretty easy, right?)
```

<a name="basicusage-parsing"></a>
### Parsing from strings

Use the parser to create a new token from a JWT string (using the previous token as example):

```php
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\UnencryptedToken;

try {
    /** @var string $jwt JWT token string */
    $token = Yii::$app->jwt->parse($jwt); // Parses from a string
} catch (CannotDecodeContent | InvalidTokenStructure | UnsupportedHeaderFound $e) {
    echo 'Oh no, an error: ' . $e->getMessage();
}

assert($token instanceof UnencryptedToken);
```

<a name="basicusage-validating"></a>
### Validating

We can easily validate if the token is valid (using the previous token as example):

```php
use \Lcobucci\JWT\Validation\Constraint\IssuedBy;

if (!Yii::$app->jwt->validate($token, new IssuedBy('http://example.com'))) {
    echo 'Invalid token (1)!', PHP_EOL; // will not print this
}

if (!Yii::$app->jwt->validate($token, new IssuedBy('http://example.org'))) {
    echo 'Invalid token (1)!', PHP_EOL; // will print this
}
```

#### Available constraints

* `\Lcobucci\JWT\Validation\Constraint\IdentifiedBy`: verifies if the claim jti matches the expected value
* `\Lcobucci\JWT\Validation\Constraint\IssuedBy`: verifies if the claim iss is listed as expected values
* `\Lcobucci\JWT\Validation\Constraint\PermittedFor`: verifies if the claim aud contains the expected value
* `\Lcobucci\JWT\Validation\Constraint\RelatedTo`: verifies if the claim sub matches the expected value
* `\Lcobucci\JWT\Validation\Constraint\SignedWith`: verifies if the token was signed with the expected signer and key
* `\Lcobucci\JWT\Validation\Constraint\StrictValidAt`: verifies presence and validity of the claims iat, nbf, and exp (supports leeway configuration)
* `\Lcobucci\JWT\Validation\Constraint\LooseValidAt`: verifies the claims iat, nbf, and exp, when present (supports leeway configuration)
* `\Lcobucci\JWT\Validation\Constraint\HasClaimWithValue`: verifies that a custom claim has the expected value (not recommended when comparing cryptographic hashes)

#### Important

* You have to configure `\sizeg\jwt\Jwt::$constraints` informing all claims you want to validate the token by `Yii::$app->jwt->loadToken()`, this method also called inside `\sizeg\jwt\JwtHttpBearerAuth`.

<a name="tokensign"></a>
## Token signature

We can use signatures to be able to verify if the token was not modified after its generation.
This extension implements Hmac, RSA and ECDSA signatures (using 256, 384 and 512).

### Important

Do not allow the string sent to the Parser to dictate which signature algorithm to use,
or else your application will be vulnerable to a [critical JWT security vulnerability](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries).

The examples below are safe because the choice in `Signer` is hard-coded and cannot be influenced by malicious users.

<a name="tokensign-hmac"></a>
### Hmac

Hmac signatures are really simple to be used.

You may configure component:

```php
'components' => [
    'jwt' => [
        'class' => \sizeg\jwt\Jwt::class,
        'signer' => \sizeg\jwt\JwtSigner::HS256,
        'signerKey' => \sizeg\jwt\JwtKey::PLAIN_TEXT,
        'signerKeyContents' => random_bytes(32),
        'signerKeyPassphrase' => 'secret',
        'constraints' => [
            function () {
                // Verifies the claims iat, nbf, and exp, when present (supports leeway configuration)
                return new \Lcobucci\JWT\Validation\Constraint\LooseValidAt(
                    \Lcobucci\Clock\SystemClock::fromSystemTimezone()
                );
            },
            function () {
                // Verifies if the token was signed with the expected signer and key
                return new \Lcobucci\JWT\Validation\Constraint\SignedWith(
                    Yii::$app->jwt->getSigner(),
                    Yii::$app->jwt->getSignerKey()
                );
            },
         ],
    ],
],
```

```php
use \Lcobucci\JWT\Validation\Constraint\SignedWith;

$now = new DateTimeImmutable();

$algorithm = $this->jwt->getSigner(\sizeg\jwt\JwtSigner::HS256);
// ... and key
$contents = random_bytes(32);
$passphrase = 'secret';
$key = $this->jwt->getSignerKey(\sizeg\jwt\JwtKey::PLAIN_TEXT, $contents, $passphrase);

$token = Yii::$app->jwt->getBuilder()
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
    ->withHeader('foo', 'bar')
    // Builds a new token
    ->getToken($algorithm, $key);
    
if (!Yii::$app->jwt->validate($token, new SignedWith(
    Yii::$app->jwt->getSigner(\sizeg\jwt\JwtSigner::HS256),
    Yii::$app->jwt->getSignerKey(JwtKey::PLAIN_TEXT, $contents, $passphrase)
))) {
    echo 'Invalid token (1)!', PHP_EOL; // will not print this
}

if (!Yii::$app->jwt->validate($token, new SignedWith(
    Yii::$app->jwt->getSigner(\sizeg\jwt\JwtSigner::HS256),
    Yii::$app->jwt->getSignerKey(JwtKey::PLAIN_TEXT, random_bytes(32), 'other-secret')
))) {
    echo 'Invalid token (1)!', PHP_EOL; // will print this
}
```

<a name="tokensign-rsa-ecdsa"></a>
### RSA and ECDSA

RSA and ECDSA signatures are based on public and private keys so you have to generate using the private key and verify using the public key:

```php
use \Lcobucci\JWT\Validation\Constraint\SignedWith;

$now = new DateTimeImmutable();

// you can use 'ES256' if you're using ECDSA keys
$algorithm = Yii::$app->jwt->getSigner(\sizeg\jwt\JwtSigner::RS256);
$privateKey = Yii::$app->jwt->getSignerKey(\sizeg\jwt\JwtKey::FILE, 'file://{path to your private key}');

$token = Yii::$app->jwt->getBuilder()
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
    ->withHeader('foo', 'bar')
    // Builds a new token
    ->getToken($algorithm, $privateKey);

$publicKey = Yii::$app->jwt->getSignerKey(\sizeg\jwt\JwtKey::FILE, 'file://{path to your public key}');

var_dump(Yii::$app->jwt->validate($token, new SignedWith(
    Yii::$app->jwt->getSigner(\sizeg\jwt\JwtSigner::RS256),
    Yii::$app->jwt->getSignerKey(JwtKey::FILE, $publicKey)
))); // true when the public key was generated by the private one =)
```

**It's important to say that if you're using RSA keys you shouldn't invoke ECDSA signers (and vice-versa), otherwise ```sign()``` and ```verify()``` will raise an exception!**

<a name="yii2basic-example"></a>
## Yii2 basic template example

### Basic scheme

1. Client send credentials. For example, login + password
2. Backend validate them
3. If credentials is valid client receive token
4. Client store token for the future requests

### Step-by-step usage example

1. Create Yii2 application

    In this example we will use [basic template](https://github.com/yiisoft/yii2-app-basic), but you can use [advanced template](https://github.com/yiisoft/yii2-app-advanced) in the same way.

    ```shell
    composer create-project --prefer-dist --stability=dev yiisoft/yii2-app-basic yii2-jwt-test
    ```

2. Install component

    ```shell
    composer require sizeg/yii2-jwt
    ```

3. Add to config/web.php into `components` section

    ```php
    $config = [
        'components' => [
            // other default components here..
            'jwt' => [
                'class' => \sizeg\jwt\Jwt::class,
                'constraints' => [
                    function () {
                        return new \Lcobucci\JWT\Validation\Constraint\LooseValidAt(
                            \Lcobucci\Clock\SystemClock::fromSystemTimezone()
                        );
                    },
                ],
            ],
        ],
    ];
    ```
4. Change method `app\models\User::findIdentityByAccessToken()`

    ```php
        /**
         * {@inheritdoc}
         * @param \Lcobucci\JWT\Token $token
         */
        public static function findIdentityByAccessToken($token, $type = null)
        {
            foreach (self::$users as $user) {
                if ($user['id'] === (string) $token->claims()->get('uid')) {
                    return new static($user);
                }
            }
    
            return null;
        }
    ```

5. Create controller

    ```php
       <?php
    
       namespace app\controllers;
    
       use sizeg\jwt\Jwt;
       use sizeg\jwt\JwtHttpBearerAuth;
       use Yii;
       use yii\rest\Controller;
    
       class RestController extends Controller
       {
           /**
            * @inheritdoc
            */
           public function behaviors()
           {
               $behaviors = parent::behaviors();
               $behaviors['authenticator'] = [
                   'class' => JwtHttpBearerAuth::class,
                   'optional' => [
                       'login',
                   ],
               ];
    
               return $behaviors;
           }
    
           /**
            * @return \yii\web\Response
            */
           public function actionLogin()
           {
               $now = new DateTimeImmutable();
               $algorithm = $this->jwt->getSigner();
               $key = $this->jwt->getSignerKey();

               /** @var Jwt $jwt */
               $jwt = Yii::$app->jwt;
            
               $token = Yii::$app->jwt->getBuilder()
                   // Configures the issuer (iss claim)
                   ->issuedBy('http://example.com')
                   // Configures the audience (aud claim)
                   ->permittedFor('http://example.org')
                   // Configures the id (jti claim)
                   ->identifiedBy('4f1g23a12aa')
                   // Configures the time that the token was issue (iat claim)
                   ->issuedAt($now)
                   // Configures the expiration time of the token (exp claim)
                   ->expiresAt($now->modify('+1 hour'))
                   // Configures a new claim, called "uid"
                   ->withClaim('uid', 100)
                   // Builds a new token
                   ->getToken($algorithm, $key);

            return $this->asJson([
                'token' => $token->toString(),
            ]);
        }
    
        /**
         * @return \yii\web\Response
         */
        public function actionData()
        {
            return $this->asJson([
                'success' => true,
            ]);
        }
    }
    ```

6. Send simple login request to get token. Here we does not send any credentials to simplify example. As we specify in `authenticator` behavior action `login` as optional the `authenticator` skip auth check for that action.
![image](https://user-images.githubusercontent.com/4047591/54614758-c4d2e100-4a7e-11e9-9175-0f1742bf4047.png)

7. First of all we try to send request to rest/data without token and getting error `Unauthorized`
![image](https://user-images.githubusercontent.com/4047591/54615287-a3262980-4a7f-11e9-81a9-609f5cb443c7.png)

8. Then we retry request but already adding `Authorization` header with our token
![image](https://user-images.githubusercontent.com/4047591/54615245-8ee22c80-4a7f-11e9-9948-e3f801596c43.png)
