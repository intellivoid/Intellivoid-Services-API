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
    use IntellivoidAccounts\Abstracts\SearchMethods\ApplicationSearchMethod;
    use IntellivoidAccounts\Exceptions\ApplicationNotFoundException;
    use IntellivoidAccounts\IntellivoidAccounts;
    use KimchiAPI\Abstracts\Method;
    use KimchiAPI\Abstracts\ResponseStandard;
    use KimchiAPI\Objects\Response;
    use Methods\Utilities\Authentication;
    use Methods\Utilities\HttpAuthenticationFailure;

    /**
     * Class coa_get_application
     */
    class CoaGetApplicationMethod extends Method
    {
        /**
         * @return Response
         * @noinspection PhpArrayIndexImmediatelyRewrittenInspection
         * @noinspection PhpCastIsUnnecessaryInspection
         */
        public function execute(): Response
        {
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

            $IntellivoidAccounts = new IntellivoidAccounts();

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
                $Response->ErrorMessage = Authentication::resolveErrorCode(-1);
                $Response->Exception = $e;
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            $EndpointURL = "https://accounts.intellivoid.net/user/contents/public/application?";

            $Response = new Response();
            $Response->Success = true;
            $Response->ResponseCode = 200;
            $Response->ResultData = [
                "name" => $Application->Name,
                "name_safe" => $Application->NameSafe,
                "logo" => [
                    "original" => $EndpointURL . http_build_query(["app_id" => $Application->PublicAppId, "resource" => "original"]),
                    "normal" => $EndpointURL . http_build_query(["app_id" => $Application->PublicAppId, "resource" => "normal"]),
                    "preview" => $EndpointURL . http_build_query(["app_id" => $Application->PublicAppId, "resource" => "preview"]),
                    "small" => $EndpointURL . http_build_query(["app_id" => $Application->PublicAppId, "resource" => "small"]),
                    "tiny" => $EndpointURL . http_build_query(["app_id" => $Application->PublicAppId, "resource" => "tiny"]),
                ],
                "status" => "UNKNOWN",
                "authentication_mode" => "UNKNOWN",
                "permissions" => $Application->Permissions
            ];

            switch($Application->AuthenticationMode)
            {
                case AuthenticationMode::Redirect:
                    $Response->ResultData["authentication_mode"] = "REDIRECT";
                    break;

                case AuthenticationMode::ApplicationPlaceholder:
                    $Response->ResultData["authentication_mode"] = "PLACEHOLDER";
                    break;

                case AuthenticationMode::Code:
                    $Response->ResultData["authentication_mode"] = "RETURN_ACCESS_CODE";
                    break;

                default:
                    $Response->ResultData["authentication_mode"] = "UNKNOWN";
                    break;
            }

            switch((int)$Application->Status)
            {
                case ApplicationStatus::Active:
                    $Response->ResultData["status"] = "ACTIVE";
                    break;

                case ApplicationStatus::Disabled:
                    $Response->ResultData["status"] = "DISABLED";
                    break;

                case ApplicationStatus::Suspended:
                    $Response->ResultData["status"] = "SUSPENDED";
                    break;

                default:
                    $Response->ResultData["status"] = "UNKNOWN";
                    break;
            }

            return $Response;
        }
    }