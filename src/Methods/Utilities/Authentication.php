<?php

    namespace Methods\Utilities;

    use Exception;
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
    use KimchiAPI\Classes\Request;

    class Authentication
    {
        /**
         * @param bool $require_secret
         * @return null
         * @throws HttpAuthenticationFailure
         * @noinspection DuplicatedCode
         */
        public static function fetchApplicationAuthentication(bool $require_secret=true): ?array
        {
            $Parameters = Request::getParameters();

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
         * @noinspection DuplicatedCode
         * @noinspection PhpCastIsUnnecessaryInspection
         */
        public static function fetchUserAuthentication(IntellivoidAccounts $intellvoidAccounts): AuthenticationAccess
        {
            $Parameters = Request::getParameters();

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
         * @noinspection DuplicatedCode
         */
        public static function getUser(IntellivoidAccounts $intellivoidAccounts, AuthenticationAccess $authenticationAccess): Account
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
         * @noinspection DuplicatedCode
         */
        public static function getApplication(IntellivoidAccounts $intellivoidAccounts, AuthenticationAccess $authenticationAccess): Application
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
        public static function verifyAccess(AuthenticationAccess $authenticationAccess, Application $application)
        {
            if($authenticationAccess->ApplicationId !== $application->ID)
            {
                throw new UserAuthenticationFailure(25, 401);
            }
        }

        /**
         * Resolves the error code into a human-readable message
         *
         * @param int $error_code
         * @return string
         */
        public static function resolveErrorCode(int $error_code): string
        {
            switch($error_code)
            {
                case -1:
                    return("INTERNAL SERVER ERROR");

                case 1:
                    return("MISSING PARAMETER 'application_id'");

                case 2:
                    return("INVALID APPLICATION ID");

                case 3:
                    return("APPLICATION SUSPENDED");

                case 4:
                    return("APPLICATION UNAVAILABLE");

                case 5:
                    return("CANNOT VERIFY CLIENT HOST");

                case 6:
                    return("MISSING PARAMETER 'redirect'");

                case 7:
                    return("MISSING PARAMETER 'auth' IN AUTH PROMPT");

                case 8:
                    return("MISSING PARAMETER 'application_id' IN AUTH PROMPT");

                case 9:
                    return("MISSING PARAMETER 'request_token' IN AUTH PROMPT");

                case 10:
                    return("INVALID APPLICATION ID IN AUTH PROMPT");

                case 11:
                    return("INTERNAL SERVER ERROR IN AUTH PROMPT (TYPE PROMPT-01)");

                case 12:
                    return("INVALID REQUEST TOKEN IN AUTH PROMPT");

                case 13:
                    return("INTERNAL SERVER ERROR IN AUTH PROMPT (TYPE PROMPT-02)");

                case 14:
                    return("MISSING PARAMETER 'redirect' IN AUTH PROMPT");

                case 15:
                    return("UNSUPPORTED AUTHENTICATION TYPE");

                case 16:
                    return("INVALID REDIRECT URL");

                case 17:
                    return("MISSING PARAMETER 'verification_token' IN AUTH PROMPT->ACTION");

                case 18:
                    return("CANNOT VERIFY REQUEST, INVALID VERIFICATION TOKEN");

                case 19:
                    return("AUTHENTICATION ACCESS DOES NOT EXIST");

                case 20:
                    return("ALREADY AUTHENTICATED");

                case 21:
                    return("INTERNAL SERVER ERROR WHILE TRYING TO AUTHENTICATE USER");

                case 22:
                    return("MISSING PARAMETER 'secret_key'");

                case 23:
                    return("ACCESS DENIED, INCORRECT SECRET KEY");

                case 24:
                    return("MISSING PARAMETER 'access_token'");

                case 25:
                    return("ACCESS DENIED, INCORRECT ACCESS TOKEN");

                case 26:
                    return("ACCESS DENIED, ACCOUNT NOT FOUND");

                case 27:
                    return("ACCESS TOKEN EXPIRED");

                case 28:
                    return("ACCOUNT SUSPENDED");

                case 29:
                    return("ACCESS DENIED, USER DISABLED ACCESS");

                case 30:
                    return("ACCESS DENIED, INSUFFICIENT PERMISSIONS");

                case 31:
                    return("MISSING PARAMETER 'field'");

                case 32:
                    return("MISSING PARAMETER 'value'");

                case 33:
                    return("INVALID VALUE FOR 'first_name'");

                case 34:
                    return("REQUEST TOKEN EXPIRED");

                case 35:
                    return("UNSUPPORTED APPLICATION AUTHENTICATION TYPE");

                case 36:
                    return("CRYPTO ERROR, APPLICATION CERTIFICATE MISHAP");

                case 37:
                    return("CRYPTO ERROR, AUTHENTICATION REQUEST MISHAP");

                case 38:
                    return("ACCESS DENIED");

                case 39:
                    return("MISSING PARAMETER 'request_token'");

                case 40:
                    return("INVALID REQUEST TOKEN");

                case 41:
                    return("AWAITING AUTHENTICATION");

                case 42:
                    return("MISSING PARAMETER 'plan_name'");

                case 43:
                    return("SUBSCRIPTION PLAN NOT FOUND");

                case 44:
                    return("SUBSCRIPTION PROMOTION NOT FOUND");

                case 45:
                    return("SUBSCRIPTION PLAN NOT AVAILABLE");

                case 46:
                    return("SUBSCRIPTION PROMOTION NOT AVAILABLE");

                case 47:
                    return("SUBSCRIPTION PROMOTION EXPIRED");

                case 48:
                    return("SUBSCRIPTION PROMOTION NOT APPLICABLE TO PLAN");

                case 49:
                    return("INSUFFICIENT FUNDS");

                case 50:
                    return("MISSING PARAMETERS 'subscription_id'");

                case 51:
                    return("ACCESS DENIED DUE TO SECURITY ISSUES");

                case 52:
                    return("MISSING PARAMETER 'application'");

                case 53:
                    return("DIRECT AUTHENTICATION IS ONLY APPLICABLE TO BUILTIN APPLICATIONS");

                case 54:
                    return("DIRECT AUTHENTICATION FAILED, APPLICATION NOT FOUND");

                default:
                    return("UNKNOWN ERROR");
            }
        }
    }