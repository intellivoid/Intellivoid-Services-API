<?php

    /**
     * @noinspection PhpMissingFieldTypeInspection
     * @noinspection DuplicatedCode
     * @noinspection PhpUnused
     * @noinspection PhpIllegalPsrClassPathInspection
     */

    namespace Methods\v1;

    use Exception;
    use IntellivoidAccounts\Abstracts\AccountRequestPermissions;
    use IntellivoidAccounts\IntellivoidAccounts;
    use KimchiAPI\Abstracts\Method;
    use KimchiAPI\Abstracts\ResponseStandard;
    use KimchiAPI\Objects\Response;
    use Methods\Utilities\Authentication;
    use Methods\Utilities\HttpAuthenticationFailure;
    use Methods\Utilities\UserAuthenticationFailure;

    /**
     * Class accounts_get_user
     */
    class AccountsGetUserMethod extends Method
    {
        /**
         * @return Response
         */
        public function execute(): Response
        {
            $IntellivoidAccounts = new IntellivoidAccounts();

            try
            {
                // Process the authentication requirements
                Authentication::fetchApplicationAuthentication(true);
                $AccessToken = Authentication::fetchUserAuthentication($IntellivoidAccounts);
                $UserAccount = Authentication::getUser($IntellivoidAccounts, $AccessToken);
                $Application = Authentication::getApplication($IntellivoidAccounts, $AccessToken);
                Authentication::verifyAccess($AccessToken, $Application);
            }
            catch (HttpAuthenticationFailure | UserAuthenticationFailure $e)
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

            if($AccessToken->has_permission(AccountRequestPermissions::GetUserDisplay) == false || $AccessToken->has_permission(AccountRequestPermissions::ViewUsername) == false)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 403;
                $Response->ErrorCode = 30;
                $Response->ErrorMessage = Authentication::resolveErrorCode(30);
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            $EndpointURL = "https://accounts.intellivoid.net/user/contents/public/avatar?";
            $Response = new Response();
            $Response->Success = true;
            $Response->ResponseCode = 200;
            $Response->ResultData = [
                "id" => $UserAccount->PublicID,
                "username" => $UserAccount->Username,
                "avatar" => [
                    "original" => $EndpointURL . http_build_query(["user_id" => $UserAccount->PublicID, "resource" => "original"]),
                    "normal" => $EndpointURL . http_build_query(["user_id" => $UserAccount->PublicID, "resource" => "normal"]),
                    "preview" => $EndpointURL . http_build_query(["user_id" => $UserAccount->PublicID, "resource" => "preview"]),
                    "small" => $EndpointURL . http_build_query(["user_id" => $UserAccount->PublicID, "resource" => "small"]),
                    "tiny" => $EndpointURL . http_build_query(["user_id" => $UserAccount->PublicID, "resource" => "tiny"]),
                ]
            ];
            $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

            return $Response;
        }
    }