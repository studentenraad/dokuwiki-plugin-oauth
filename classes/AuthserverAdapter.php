<?php

namespace OAuth\Plugin;

use OAuth\OAuth2\Service\Authserver;

class AuthserverAdapter extends AbstractAdapter
{
    /**
     * Retrieve the user's data
     *
     * The array needs to contain at least 'email', 'name', 'user', 'grps'
     *
     * @return array
     */
    public function getUser()
    {
        $response = $this->oAuth->request('api/user.json');
        $result = json_decode($response, true);
        $groupPrefix = $this->hlp->getConf('authserver-group-prefix');
        $oauthDomain = $this->oAuth->getAccessTokenEndpoint()->getHost();
        return [
            'name' => $result['name'],
            'user' => $result['username'],
            'mail' => $result['guid'].'@'.$oauthDomain,
            'grps' => array_map(function($groupName) use ($groupPrefix) {
                return substr($groupName, strlen($groupPrefix));
            }, array_filter($result['groups'], function($groupName) use ($groupPrefix) {
                return strpos($groupName, $groupPrefix) == 0;
            })),
        ];
    }

    public function getScope()
    {
        return [
            Authserver::REALNAME,
            Authserver::USERNAME,
            Authserver::GROUPS,
        ];
    }

}
