<?php

    /** @noinspection PhpIllegalPsrClassPathInspection */
    /** @noinspection PhpIllegalPsrClassPathInspection */
    /** @noinspection PhpMultipleClassesDeclarationsInOneFile */

    /**
     * This script is for handling HTTP-Basic authentication
     */

    use Handler\Handler;
    use IntellivoidAccounts\Abstracts\AccountStatus;
    use IntellivoidAccounts\Abstracts\ApplicationStatus;
    use IntellivoidAccounts\Abstracts\AuthenticationAccessStatus;
    use IntellivoidAccounts\Abstracts\SearchMethods\AccountSearchMethod;
    use IntellivoidAccounts\Abstracts\SearchMethods\ApplicationSearchMethod;
    use IntellivoidAccounts\Abstracts\SearchMethods\AuthenticationAccessSearchMethod;
    use IntellivoidAccounts\Exceptions\AccountNotFoundException;
    use IntellivoidAccounts\Exceptions\ApplicationNotFoundException;
    use IntellivoidAccounts\Exceptions\AuthenticationAccessNotFoundException;
    use IntellivoidAccounts\IntellivoidAccounts;
    use IntellivoidAccounts\Objects\Account;
    use IntellivoidAccounts\Objects\COA\Application;
    use IntellivoidAccounts\Objects\COA\AuthenticationAccess;

    /**
     * Class apiAuthenticationFailure
     */
    class HttpAuthenticationFailure extends Exception
    {
        /**
         * @var int
         */
        private int $coa_error_code;

        /**
         * @var int
         */
        private int $status_code;

        /**
         * HttpAuthenticationFailure constructor.
         * @param int $coa_error_code
         * @param $status_code
         */
        public function __construct(int $coa_error_code, int $status_code)
        {
            parent::__construct(resolve_error_code($coa_error_code), $coa_error_code);
            $this->coa_error_code = $coa_error_code;
            $this->status_code = $status_code;
        }

        /**
         * @return int
         */
        public function getCoaErrorCode(): int
        {
            return $this->coa_error_code;
        }

        /**
         * @return int
         */
        public function getStatusCode(): int
        {
            return $this->status_code;
        }
    }

    /**
     * Class UserAuthenticationFailure
     */
    class UserAuthenticationFailure extends Exception
    {
        /**
         * @var int
         */
        private int $coa_error_code;

        /**
         * @var int
         */
        private int $status_code;

        /**
         * UserAuthenticationFailure constructor.
         * @param int $coa_error_code
         * @param int $status_code
         */
        public function __construct(int $coa_error_code, int $status_code)
        {
            parent::__construct(resolve_error_code($coa_error_code), $coa_error_code);
            $this->coa_error_code = $coa_error_code;
            $this->status_code = $status_code;
        }

        /**
         * @return int
         */
        public function getCoaErrorCode(): int
        {
            return $this->coa_error_code;
        }

        /**
         * @return int
         */
        public function getStatusCode(): int
        {
            return $this->status_code;
        }
    }

    /**
     * @param bool $require_secret
     * @return null
     * @throws HttpAuthenticationFailure
     */
    function fetchApplicationAuthentication(bool $require_secret=true): ?array
    {
        $Parameters = Handler::getParameters(true, true);

        $Results = [
            "application_id" => null,
            "secret_key" => null
        ];

        // Process the HTTP Authentication if available
        if (isset($_SERVER['PHP_AUTH_USER']))
        {
            $Results["application_id"] = $_SERVER["PHP_AUTH_USER"];

            if($_SERVER['PHP_AUTH_PW'] !== null)
            {
                if(strlen($_SERVER['PHP_AUTH_PW']) > 0)
                {
                    $Results["secret_key"] = $_SERVER['PHP_AUTH_PW'];
                }
            }
        }

        if($Results["application_id"] == null)
        {
            if(isset($Parameters["application_id"]))
            {
                $Results["application_id"] = $Parameters["application_id"];
            }
            else
            {
                if($require_secret)
                {
                    // Missing both ID and Secret Key
                    header('WWW-Authenticate: Basic realm="Intellivoid Accounts Application ID & Secret Key"');
                    throw new HttpAuthenticationFailure(22, 401);

                }
                else
                {
                    // Missing ID
                    header('WWW-Authenticate: Basic realm="Intellivoid Accounts Application ID"');
                    throw new HttpAuthenticationFailure(1, 401);
                }
            }
        }

        if($require_secret)
        {
            if($Results["secret_key"] == null)
            {
                if(isset($Parameters["secret_key"]) == false)
                {
                    // Missing Secret Key
                    header('WWW-Authenticate: Basic realm="Intellivoid Accounts Application ID & Secret Key"');
                    throw new HttpAuthenticationFailure(22, 401);
                }
                else
                {
                    $Results["secret_key"] = $Parameters["secret_key"];
                }
            }
        }

        return $Results;
    }

    /**
     * Fetches the user authentication access token
     *
     * @param IntellivoidAccounts $intellvoidAccounts
     * @return AuthenticationAccess
     * @throws UserAuthenticationFailure
     */
    function fetchUserAuthentication(IntellivoidAccounts $intellvoidAccounts): AuthenticationAccess
    {
        $Parameters = Handler::getParameters(true, true);

        if(isset($Parameters["access_token"]) == false)
        {
            throw new UserAuthenticationFailure(24, 401);
        }

        try
        {
            $access_token = $intellvoidAccounts->getCrossOverAuthenticationManager()->getAuthenticationAccessManager()->getAuthenticationAccess(
                AuthenticationAccessSearchMethod::byAccessToken, $Parameters["access_token"]
            );
        }
        catch (AuthenticationAccessNotFoundException $e)
        {
            throw new UserAuthenticationFailure(25, 401);
        }
        catch (Exception $e)
        {
            throw new UserAuthenticationFailure(-1, 500);
        }

        // Check if the user revoked access
        if($access_token->Status == AuthenticationAccessStatus::Revoked)
        {
            throw new UserAuthenticationFailure(29, 403);
        }

        // Check if the access token expired
        if((int)time() > $access_token->ExpiresTimestamp)
        {
            throw new UserAuthenticationFailure(27, 403);
        }
        else
        {
            // Update the expiry timestamp
            $access_token->ExpiresTimestamp = (int)time() + 172800;

            try
            {
                $intellvoidAccounts->getCrossOverAuthenticationManager()->getAuthenticationAccessManager()->updateAuthenticationAccess($access_token);
            }
            catch (Exception $e)
            {
                throw new UserAuthenticationFailure(-1, 500);
            }
        }

        return $access_token;
    }

    /**
     * Returns the authenticated user
     *
     * @param IntellivoidAccounts $intellivoidAccounts
     * @param AuthenticationAccess $authenticationAccess
     * @return Account
     * @throws UserAuthenticationFailure
     */
    function getUser(IntellivoidAccounts $intellivoidAccounts, AuthenticationAccess $authenticationAccess): Account
    {
        try
        {
            $Account = $intellivoidAccounts->getAccountManager()->getAccount(
                AccountSearchMethod::byId, $authenticationAccess->AccountId
            );
        }
        catch(AccountNotFoundException $e)
        {
            throw new UserAuthenticationFailure(26, 403);
        }
        catch(Exception $e)
        {
            throw new UserAuthenticationFailure(-1, 500);
        }


        // Check the status of the account
        switch($Account->Status)
        {
            case AccountStatus::Suspended:
                throw new UserAuthenticationFailure(28, 403);

            case AccountStatus::Limited:
            case AccountStatus::VerificationRequired:
            case AccountStatus::PasswordRecoveryMode:
            case AccountStatus::BlockedDueToGovernmentBackedAttack:
                throw new UserAuthenticationFailure(51, 403);

            case AccountStatus::Active:
            default:
                break;
        }

        return $Account;
    }

    /**
     * Returns the authenticated application
     *
     * @param IntellivoidAccounts $intellivoidAccounts
     * @param AuthenticationAccess $authenticationAccess
     * @return Application
     * @throws UserAuthenticationFailure
     */
    function getApplication(IntellivoidAccounts $intellivoidAccounts, AuthenticationAccess $authenticationAccess): Application
    {
        try
        {
            $Application = $intellivoidAccounts->getApplicationManager()->getApplication(
                ApplicationSearchMethod::byId, $authenticationAccess->ApplicationId
            );
        }
        catch (ApplicationNotFoundException $e)
        {
            throw new UserAuthenticationFailure(7, 403);
        }
        catch(Exception $e)
        {
            throw new UserAuthenticationFailure(-1, 500);
        }

        switch($Application->Status)
        {
            case ApplicationStatus::Suspended:
                throw new UserAuthenticationFailure(3, 403);

            case ApplicationStatus::Disabled:
                throw new UserAuthenticationFailure(4, 403);

            case ApplicationStatus::Active:
            default:
                break;
        }

        return $Application;
    }

    /**
     * Verifies the access between the Authentication Access Token and Application
     *
     * @param AuthenticationAccess $authenticationAccess
     * @param Application $application
     * @throws UserAuthenticationFailure
     */
        function verifyAccess(AuthenticationAccess $authenticationAccess, Application $application)
        {
            if($authenticationAccess->ApplicationId !== $application->ID)
            {
                throw new UserAuthenticationFailure(25, 401);
            }
        }