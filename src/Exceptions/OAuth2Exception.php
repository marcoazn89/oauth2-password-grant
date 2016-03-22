<?php
namespace OAuth2Password\Exceptions;

class OAuth2Exception extends \Exception\BooBoo {
    const BAD_CREDENTIALS = 'Unable to verify credentials';
    const FORBIDDEN = 'Access denied';

    protected function getTag()
    {
        return 'OAuth2Exception';
    }
}
