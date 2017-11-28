<?php
namespace OAuth2Password;

use \OAuth2Password\Interfaces\AuthRepositoryInterface;
use \OAuth2Password\Exceptions\OAuth2Exception;
use \Psr\Http\Message\ServerRequestInterface;
use \Psr\Http\Message\ResponseInterface;
use \Lcobucci\JWT\Builder;
use \Lcobucci\JWT\Signer\Key;
use \Lcobucci\JWT\Signer\Rsa\Sha256;
use \Lcobucci\JWT\Parser;
use \Lcobucci\JWT\ValidationData;
use DateTime;
use DateInterval;

class OAuth2
{
    protected $request;
    protected $authRepo;
    protected $config;
    protected $info = [];

    /**
     * @param AuthRepositoryInterface $authRepo AuthRepo to handle authentication for username and password
     * @param array                   $config   Must include expiration (ISO_8601 duration), private_key, and public_key
     */
    public function __construct(AuthRepositoryInterface $authRepo, array $config)
    {
        $this->authRepo = $authRepo;
        $this->config = $config;
    }

    public function authenticate(ServerRequestInterface $request, ResponseInterface $response)
    {
        if (empty($username = $request->getParam('username')) || empty($password = $request->getParam('password')) ||
            empty($grant = $request->getParam('grant_type')) || $grant !== 'password') {
            throw (new OAuth2Exception('Invalid parameters supplied for authentication'))
                ->displayMessage(OAuth2Exception::BAD_CREDENTIALS)
                ->response($response->withStatus(401));
        }

        $result = $this->authRepo->validateCredentials($username, $password);

        if (empty($result)) {
            throw (new OAuth2Exception('Wrong username or password'))
                ->displayMessage(OAuth2Exception::BAD_CREDENTIALS)
                ->response($response->withStatus(401));
        }

        $address = $this->getAddress();

        $expiration = $this->getExpiration($this->config['expiration']);

        $builder = (new Builder())
            ->setIssuer($address) // Configures the issuer (iss claim)
            ->setAudience($address) // Configures the audience (aud claim)
            ->setId(md5(uniqid(mt_rand(), true)), true) // Configures the id (jti claim), replicating as a header item
            ->setIssuedAt(time()) // Configures the time that the token was issue (iat claim)
            ->setNotBefore(time() + 60) // Configures the time that the token can be used (nbf claim)
            ->setExpiration($expiration) // Configures the expiration time of the token (exp claim)
            ->setSubject($result['id']);

        $customClaims = [];

        foreach($result as $claim => $value) {
            if ($claim !== 'id') {
                $customClaims[] = $claim;
                $builder->set($claim, $value);
            }
        }

        $token = $builder
            ->set('cc', implode(',', $customClaims))
            ->sign(new Sha256(), new Key($this->config['private-key']))
            ->getToken(); // Retrieves the generated token

        return $response
            ->withHeader(
                \HTTP\Header\CacheControl::name(),
                \HTTP\Header\CacheControl::values([
                    \HTTP\Header\CacheControl::NO_CACHE,
                    \HTTP\Header\CacheControl::REVALIDATE
                ])
            )
            ->withType('application/json;charset=utf-8')
            ->write(json_encode([
                'token'   => sprintf('%s', $token),
                'type'    => 'Bearer',
                'expires' => $expiration
            ]));
    }

    public function validateToken(ServerRequestInterface $request, ResponseInterface $response)
    {
        $authHeader = $request->getHeader('HTTP_AUTHORIZATION');

        if (empty($authHeader)) {
            $authHeader = getHeaders();

            if (empty($authHeader['authorization'])) {
                throw (new OAuth2Exception('Authorization header is missing'))
                    ->displayMessage(OAuth2Exception::FORBIDDEN)
                    ->response($response->withStatus(403));
            }

            $authHeader = $authHeader['authorization'];
        } else {
            $authHeader = $authHeader[0];
        }

        list($token) = sscanf($authHeader, 'Bearer %s');

        if (!$token) {
            throw (new OAuth2Exception('Token is missing in the request'))
                ->displayMessage(OAuth2Exception::FORBIDDEN)
                ->response($response->withStatus(403));
        }

        try {
            $token = (new Parser())->parse($token);
        } catch (\Exception $e) {
            throw (new OAuth2Exception('Token was tampered'))
                ->displayMessage(OAuth2Exception::FORBIDDEN)
                ->response($response->withStatus(403));
        }

        if ($token->getClaim('exp') <= time()) {
            throw (new OAuth2Exception('Token expired'))
                ->displayMessage(OAuth2Exception::FORBIDDEN)
                ->response($response->withStatus(403));
        }

        $this->info['id'] = $token->getClaim('sub');

        foreach (explode(',', $token->getClaim('cc')) as $customClaim) {
            $this->info[$customClaim] = $token->getClaim($customClaim);
        }

        if (!$token->verify(new Sha256(), $this->config['public-key'])) {
            throw (new OAuth2Exception('Token was tampered'))
                ->displayMessage(OAuth2Exception::FORBIDDEN)
                ->response($response->withStatus(403));
        }

        return $response;
    }

    public function getInfo()
    {
        return $this->info;
    }

    protected function getAddress()
    {
        $protocol = (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] == "off") ? 'http': 'https';

        return "{$protocol}://{$_SERVER['HTTP_HOST']}/";
    }

    protected function getExpiration($format)
    {
        $date = new DateTime;

        $date->add(new DateInterval($format));

        return $date->getTimestamp();
    }

    protected function getHeaders()
    {
        $headers = [];

        foreach ($this->getHeaders() as $k => $v) {
            $header = strtolower($k);
            $headers[$header] = $v;
        }

        return $headers;
    }
}
