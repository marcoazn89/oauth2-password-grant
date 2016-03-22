<?php
namespace OAuth2Password\Interfaces;

interface AuthRepositoryInterface
{
    public function validateCredentials($username, $password);
}
