<?php

/*********************************
 This is an example implementation of OAuth provider. IT WOULD NOT RUN AS-IS! 
 Some functions are not implemented (see TODO marks)
********************************/
/**
 *
 * OAuth provider implementation
 */
class ExampleOAuthServer
{
    /**
     * OAuth token
     * @var OAuthToken
     */
    protected $token;

    /**
     * Check if everything is OK
     * @throws OAuthException
     */
    protected function check()
    {
        if(!function_exists('mhash') && !function_exists('hash_hmac')) {
            // define exception class
            throw new OAuthException("MHash extension required for OAuth support");
        }
    }

    /**
     * Is this functionality enabled?
     */
    public static function enabled()
    {
        return function_exists('mhash') || function_exists('hash_hmac');
    }

    /**
     * Find consumer by key
     * @param $provider
     */
    public function lookupConsumer($provider)
    {
        // check $provider->consumer_key
        // on unknown: Zend_Oauth_Provider::CONSUMER_KEY_UNKNOWN
        // on bad key: Zend_Oauth_Provider::CONSUMER_KEY_REFUSED
		// TODO: OAuthKey::fetchKey gets consumer object having 
		// secret and key properties 
        $consumer = OAuthKey::fetchKey($provider->consumer_key);
        if(!$consumer) {
            return Zend_Oauth_Provider::CONSUMER_KEY_UNKNOWN;
        }
        $provider->consumer_secret = $consumer->secret;
        $this->consumer = $consumer;
        return Zend_Oauth_Provider::OK;
    }

    /**
     * Check timestamps & nonces
     * @param OAuthProvider $provider
     */
    public function timestampNonceChecker($provider)
    {
        if(empty($provider->nonce)) {
            return Zend_Oauth_Provider::BAD_NONCE;
        }
        if(empty($provider->timestamp)) {
            return Zend_Oauth_Provider::BAD_TIMESTAMP;
        }
        // TODO: checkNonce verisifes that:
		// 1. No nonce with time after given nonce exists
		// 2. Current nonce is not listed in the database
		// 3. If it's ok, returns Zend_Oauth_Provider::OK
        return OAuthToken::checkNonce($provider->consumer_key, $provider->nonce, $provider->timestamp);
    }

    /**
     * Vefiry incoming token
     * @param OAuthProvider $provider
     */
    public function tokenHandler($provider)
    {
		// TODO: returns token object by token ID, with properties:
		// consumer, id, secret, verify, tstate
		// tstate is one of REQUEST, ACCESS, INVALID
        $token = OAuthToken::load($provider->token);
        if(empty($token)) {
            return Zend_Oauth_Provider::TOKEN_REJECTED;
        }
        if($token->consumer != $this->consumer->id) {
            return Zend_Oauth_Provider::TOKEN_REJECTED;
        }
        if($token->tstate == OAuthToken::REQUEST) {
            if(!empty($token->verify) && $provider->verifier == $token->verify) {
                $provider->token_secret = $token->secret;
                $this->token = $token;
                return Zend_Oauth_Provider::OK;
            } else {
                return Zend_Oauth_Provider::TOKEN_USED;
            }
        }
        if($token->tstate == OAuthToken::ACCESS) {
            $provider->token_secret = $token->secret;
            $this->token = $token;
            return Zend_Oauth_Provider::OK;
        }
        return Zend_Oauth_Provider::TOKEN_REJECTED;
    }

	/**
	* Assemble parameters from POST and GET 
	*/
    protected function decodePostGet()
    {
        $data = $_GET;
        $data = array_merge($data, $_POST);
        foreach($data as $k => $v) {
            $data[$k] = from_html($v);
        }
        return $data;
    }

    /**
     * Create OAuth provider
     *
     * Checks current request for OAuth valitidy
     * @param bool $add_rest add REST endpoint as request path
     */
    public function __construct($req_path = '')
    {
        $this->check();
        $this->provider = new Zend_Oauth_Provider();
	    $this->provider->setConsumerHandler(array($this,'lookupConsumer'));
	    $this->provider->setTimestampNonceHandler(array($this,'timestampNonceChecker'));
	    $this->provider->setTokenHandler(array($this,'tokenHandler'));
        if(!empty($req_path)) {
	        $this->provider->setRequestTokenPath($req_path);  // No token needed for this end point
        }
    	$this->provider->checkOAuthRequest(null, $this->decodePostGet());
    	if(mt_rand() % 10 == 0) {
    	    // TODO: cleanup old tokens and nonces
    	    OAuthToken::cleanup();
    	}
    }

    /**
     * Generate request token string
     * @return string
     */
    public function requestToken()
    {
		// TODO: generate a new token string with token/secret pair
        $token = OAuthToken::generate();
		// TODO: set consumer key
        $token->setConsumer($this->consumer);
		// TODO: save token
        $token->save();
        return "oauth_token={$token->token}&oauth_token_secret={$token->secret}";
    }

    /**
     * Generate access token string - must have validated request token
     * @return string
     */
    public function accessToken()
    {
        if(empty($this->token) || $this->token->tstate != OAuthToken::REQUEST) {
            return null;
        }
		// TODO: invalidate request token
        $this->token->invalidate();
		// TODO: generate a new token string with token/secret pair
        $token = OAuthToken::generate();
		// TODO: set token state
        $token->setState(OAuthToken::ACCESS);
		// TODO: set consumer key
        $token->setConsumer($this->consumer);
        // TODO: transfer authorization data from request token
        $token->copyAuthData($this->token);
		// TODO: save token
        $token->save();
        return "oauth_token={$token->token}&oauth_token_secret={$token->secret}";
    }

    /**
     * Return authorization URL
     * @return string
     */
    public function authUrl()
    {
        return "http://mysite.com/OAuthAuthorize";
    }

    /**
     * Fetch current token if it is authorized
     * @return OAuthToken|null
     */
    public function authorizedToken()
    {
        if($this->token->tstate == OAuthToken::ACCESS) {
            return $this->token;
        }
        return null;
    }

    /**
     * Fetch authorization data from current token
     * @return mixed Authorization data or null if none
     */
    public function authorization()
    {
        if($this->token->tstate == OAuthToken::ACCESS) {
            return $this->token->authdata;
        }
        return null;
    }

    /**
     * Report OAuth problem as string
     */
    public function reportProblem(Exception $e)
    {
        return $this->provider->reportProblem($e);
    }

    /**
	 * Authorize token for access
	 * Note that this request is not OAuth-authenticated - this should be called
	 * from regularly authenticated session
	 * @param string $token_str Token string
	 * @param mixed $authdata Authorization data to be attached to the token, such as user ID and permissions
	 * @return string|false verifier value on success (should be sent to the client), false on failure
	 */
	static public function authorizeToken($token_str, $authdata)
	{
		// TODO: load token object
        $token = OAuthToken::load($token_str);
        if(empty($token) || empty($token->consumer) || $token->tstate != OAuthToken::REQUEST) {
        	return false;
        }
		$token->authdata = $authdata;
		// TODO: generate a random string
		$token->verify = OAuthToken::generateRandom();
		$token->save();
		return $token->verify;
	}
}
