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
    use IntellivoidAccounts\Abstracts\AuthenticationMode;
    use IntellivoidAccounts\Abstracts\AuthenticationRequestStatus;
    use IntellivoidAccounts\Abstracts\SearchMethods\ApplicationSearchMethod;
    use IntellivoidAccounts\Exceptions\ApplicationNotFoundException;
    use IntellivoidAccounts\IntellivoidAccounts;
    use KimchiAPI\Abstracts\Method;
    use KimchiAPI\Abstracts\ResponseStandard;
    use KimchiAPI\Classes\Request;
    use KimchiAPI\Objects\Response;
    use Methods\Utilities\Authentication;
    use Methods\Utilities\HttpAuthenticationFailure;

    /**
     * Class coa_request_authentication
     */
    class CoaRequestAuthenticationMethod extends Method
    {
        /**
         * @return Response
         * @noinspection PhpIfWithCommonPartsInspection
         * @noinspection PhpCastIsUnnecessaryInspection
         */
        public function execute(): Response
        {
            $Parameters = Request::getParameters();

            try
            {
                // Process the authentication requirements
                $Authentication = Authentication::fetchApplicationAuthentication(false);
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

            // Check if the required redirect parameter is present
            if($Application->AuthenticationMode == AuthenticationMode::Redirect)
            {
                if(isset($Parameters["redirect"]) == false)
                {
                    $Response = new Response();
                    $Response->Success = false;
                    $Response->ResponseCode = 400;
                    $Response->ErrorCode = 6;
                    $Response->ErrorMessage = Authentication::resolveErrorCode(6);
                    $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                    return $Response;
                }
            }

            // Check the client
            try
            {
                $ClientIP = KIMCHI_CLIENT_IP_ADDRESS;

                if($ClientIP == "::1")
                {
                    $ClientIP = "127.0.0.1";
                }

                if(isset($_SERVER['HTTP_USER_AGENT']) == false)
                {
                    $Response = new Response();
                    $Response->Success = false;
                    $Response->ResponseCode = 400;
                    $Response->ErrorCode = -1;
                    $Response->ErrorMessage = "You must provide a user-agent to complete these request";
                    $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                    return $Response;
                }

                $KnownHost = $IntellivoidAccounts->getKnownHostsManager()->syncHost($ClientIP, $_SERVER['HTTP_USER_AGENT']);
            }
            catch(Exception $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 400;
                $Response->ErrorCode = 5;
                $Response->ErrorMessage = Authentication::resolveErrorCode(5);
                $Response->Exception = $e;
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            // Generate an authentication request token
            try
            {
                $AuthRequestToken = $IntellivoidAccounts->getCrossOverAuthenticationManager()->getAuthenticationRequestManager()->createAuthenticationRequest(
                    $Application, $KnownHost->ID
                );
            }
            catch (Exception $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 500;
                $Response->ErrorCode = -1;
                $Response->ErrorMessage = Authentication::resolveErrorCode(-1);
                $Response->Exception = $e;
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            if($AuthRequestToken->ApplicationId !== $Application->ID)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 400;
                $Response->ErrorCode = 40;
                $Response->ErrorMessage = Authentication::resolveErrorCode(40);
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            // Check the protocol
            $protocol = "https";

            if(isset($Parameters["secured"]))
            {
                if($Parameters["secured"] == "false" || $Parameters["secured"] == "0")
                {
                    $protocol = "http";
                }
            }

            switch($AuthRequestToken->Status)
            {
                case AuthenticationRequestStatus::Active:
                    $AuthenticationRequestStatus = "ACTIVE";
                    break;

                case AuthenticationRequestStatus::Blocked:
                    $AuthenticationRequestStatus = "BLOCKED";
                    break;

                default:
                    $AuthenticationRequestStatus = "UNKNOWN";
                    break;
            }

            if((int)time() > $AuthRequestToken->ExpiresTimestamp)
            {
                $AuthenticationRequestStatus = "EXPIRED";
            }

            // Return the results applicable to the Application's authentication mode
            if($Application->AuthenticationMode == AuthenticationMode::Redirect)
            {
                $AuthenticationParameters =  array(
                    "auth" => "application",
                    "redirect" => $Parameters["redirect"],
                    "application_id" => $Application->PublicAppId,
                    "request_token" => $AuthRequestToken->RequestToken
                );

                if(isset($Parameters["expand_ui"]))
                {
                    if($Parameters["expand_ui"] == "true" || $Parameters["expand_ui"] == "1")
                    {
                        $AuthenticationParameters["expanded"] = "1";
                    }
                }

                if(isset($Parameters["require_close"]))
                {
                    if($Parameters["require_close"] == "true" || $Parameters["require_close"] == "1")
                    {
                        $AuthenticationParameters["require_close"] = "1";
                    }
                }

                $AuthenticationUrl = $protocol . "://accounts.intellivoid.net/auth/login?" . http_build_query($AuthenticationParameters);

                $Response = new Response();
                $Response->Success = true;
                $Response->ResponseCode = 200;
                $Response->ResultData = [
                    "request_token" => $AuthRequestToken->RequestToken,
                    "requested_permissions" => $AuthRequestToken->RequestedPermissions,
                    "status" => $AuthenticationRequestStatus,
                    "authentication_url" => $AuthenticationUrl,
                    "expires_timestamp" => $AuthRequestToken->ExpiresTimestamp
                ];

                return $Response;
            }
            else
            {
                $AuthenticationParameters =  array(
                    "auth" => "application",
                    "application_id" => $Application->PublicAppId,
                    "request_token" => $AuthRequestToken->RequestToken
                );

                if(isset($Parameters["expand_ui"]))
                {
                    if($Parameters["expand_ui"] == "true" || $Parameters["expand_ui"] == "1")
                    {
                        $AuthenticationParameters["expanded"] = "1";
                    }
                }

                if(isset($Parameters["require_close"]))
                {
                    if($Parameters["require_close"] == "true" || $Parameters["require_close"] == "1")
                    {
                        $AuthenticationParameters["require_close"] = "1";
                    }
                }

                $AuthenticationUrl = $protocol . "://accounts.intellivoid.net/auth/login?" . http_build_query($AuthenticationParameters);

                $Response = new Response();
                $Response->Success = true;
                $Response->ResponseCode = 200;
                $Response->ResultData = [
                    "request_token" => $AuthRequestToken->RequestToken,
                    "requested_permissions" => $AuthRequestToken->RequestedPermissions,
                    "status" => $AuthenticationRequestStatus,
                    "authentication_url" => $AuthenticationUrl,
                    "expires_timestamp" => $AuthRequestToken->ExpiresTimestamp
                ];

                return $Response;
            }
        }
    }