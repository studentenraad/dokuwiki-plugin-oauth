<?php

namespace OAuth\OAuth2\Service;

use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\OAuth2\Token\StdOAuth2Token;

class Authserver extends AbstractService
{
    const USERNAME = 'profile:username';
    const REALNAME = 'profile:realname';
    const EMAIL = 'profile:email';
    const GROUPS = 'profile:groups';

    public function __construct(CredentialsInterface $credentials, ClientInterface $httpClient, TokenStorageInterface $storage, array $scopes = [], $baseApiUri = null, $stateParameterInAutUrl = false)
    {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri, $stateParameterInAutUrl);
        $hlp = plugin_load('helper', 'oauth');
        $this->baseApiUri = new Uri($hlp->getConf('authserver-domain'));
    }

    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    /**
     * Returns the authorization API endpoint.
     *
     * @return UriInterface
     */
    public function getAuthorizationEndpoint()
    {
        return $this->determineRequestUriFromPath('oauth/v2/auth', $this->baseApiUri);
    }

    /**
     * Returns the access token API endpoint.
     *
     * @return UriInterface
     */
    public function getAccessTokenEndpoint()
    {
        return $this->determineRequestUriFromPath('oauth/v2/token', $this->baseApiUri);
    }
    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);

        if (isset($data['expires'])) {
            $token->setLifeTime($data['expires']);
        }

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token']);
        unset($data['expires']);

        $token->setExtraParams($data);

        return $token;
    }
}

