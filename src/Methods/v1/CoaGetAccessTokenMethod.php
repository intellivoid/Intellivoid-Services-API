<?php

    /**
     * @noinspection PhpMissingFieldTypeInspection
     * @noinspection DuplicatedCode
     * @noinspection PhpUnused
     * @noinspection PhpIllegalPsrClassPathInspection
     */

    namespace Methods\v1;

    use Exception;
    use IntellivoidAccounts\Abstracts\ApplicationStatus;
    use IntellivoidAccounts\Abstracts\SearchMethods\ApplicationSearchMethod;
    use IntellivoidAccounts\Abstracts\SearchMethods\AuthenticationAccessSearchMethod;
    use IntellivoidAccounts\Exceptions\ApplicationNotFoundException;
    use IntellivoidAccounts\Exceptions\AuthenticationAccessNotFoundException;
    use IntellivoidAccounts\IntellivoidAccounts;
    use KimchiAPI\Abstracts\Method;
    use KimchiAPI\Abstracts\ResponseStandard;
    use KimchiAPI\Classes\Request;
    use KimchiAPI\Objects\Response;
    use Methods\Utilities\Authentication;
    use Methods\Utilities\HttpAuthenticationFailure;

    /**
     * Class coa_get_access_token
     */
    class CoaGetAccessToken extends Method
    {
        /**
         * @return Response
         * @noinspection PhpIfWithCommonPartsInspection
         */
        public function execute(): Response
        {
            $Parameters = Request::getParameters();

            try
            {
                // Process the authentication requirements
                $Authentication = Authentication::fetchApplicationAuthentication(true);
            }
            catch (HttpAuthenticationFailure $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = $e->getStatusCode();
                $Response->ErrorCode = $e->getCode();
                $Response->ErrorMessage = $e->getMessage();
                $Response->Exception = $e;
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }
            catch(Exception $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 500;
                $Response->ErrorCode = -1;
                $Response->ErrorMessage = "An unexpected internal server occurred while trying to process the client's authentication";
                $Response->Exception = $e;
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            if(isset($Parameters["access_token"]) == false)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 403;
                $Response->ErrorCode = 24;
                $Response->ErrorMessage = Authentication::resolveErrorCode(24);
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            // Define IntellivoidAccounts
            $IntellivoidAccounts = new IntellivoidAccounts();

            // Check if the Application Exists
            try
            {
                $Application = $IntellivoidAccounts->getApplicationManager()->getApplication(
                    ApplicationSearchMethod::byApplicationId, $Authentication["application_id"]
                );
            }
            catch (ApplicationNotFoundException $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 404;
                $Response->ErrorCode = 2;
                $Response->ErrorMessage = Authentication::resolveErrorCode(2);
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;
                $Response->Exception = $e;

                return $Response;
            }
            catch(Exception $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 500;
                $Response->ErrorCode = -1;
                $Response->ErrorMessage = Authentication::resolveErrorCode(-1);
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;
                $Response->Exception = $e;

                return $Response;
            }

            // Validate the secret key
            if(hash("sha256", $Authentication["secret_key"]) !== hash("sha256", $Application->SecretKey))
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 401;
                $Response->ErrorCode = 23;
                $Response->ErrorMessage = Authentication::resolveErrorCode(23);
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            // Check if the Application is suspended
            if($Application->Status == ApplicationStatus::Suspended)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 403;
                $Response->ErrorCode = 3;
                $Response->ErrorMessage = Authentication::resolveErrorCode(3);
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            // Check if the Application is disabled
            if($Application->Status == ApplicationStatus::Disabled)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 403;
                $Response->ErrorCode = 4;
                $Response->ErrorMessage = Authentication::resolveErrorCode(4);
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            try
            {
                $AuthenticationAccess = $IntellivoidAccounts->getCrossOverAuthenticationManager()->getAuthenticationAccessManager()->getAuthenticationAccess(
                    AuthenticationAccessSearchMethod::byAccessToken, $Parameters["access_token"]
                );
            }
            catch (AuthenticationAccessNotFoundException $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 401;
                $Response->ErrorCode = 25;
                $Response->ErrorMessage = Authentication::resolveErrorCode(25);
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }
            catch(Exception $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 500;
                $Response->ErrorCode = -1;
                $Response->ErrorMessage = Authentication::resolveErrorCode(-1);
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            if($AuthenticationAccess->ApplicationId !== $Application->ID)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 401;
                $Response->ErrorCode = 25;
                $Response->ErrorMessage = Authentication::resolveErrorCode(25);
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            $Response = new Response();
            $Response->Success = true;
            $Response->ResponseCode = 200;
            $Response->ResultData = [
                "granted_permissions" => $AuthenticationAccess->Permissions,
                "expires_timestamp" => $AuthenticationAccess->ExpiresTimestamp
            ];

            return $Response;
        }
    }