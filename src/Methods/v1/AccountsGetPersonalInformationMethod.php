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

    class AccountsGetPersonalInformationMethod extends Method
    {
        /**
         * Checks if the string is null/empty, if it isn't null then it will return the string. If it's null/empty then
         * it will return a proper null
         *
         * @param $input
         * @return null|string
         */
        private function checkString($input): ?string
        {
            if(is_null($input) == false)
            {
                if(strlen($input) > 0 )
                {
                    return $input;
                }
            }

            return null;
        }

        /**
         * Checks if the integer is null and or zero, if it doesn't meet any of the conditions then it will return a
         * strict integer. If it's null and or zero then it will return a proper null
         *
         * @param $input
         * @param bool $greater_than_zero
         * @return null|integer
         * @noinspection PhpSameParameterValueInspection
         */
        private function checkInteger($input, bool $greater_than_zero=true): ?int
        {
            if(is_null($input) == false)
            {
                if($greater_than_zero)
                {
                    if((int)$input > 0)
                    {
                        return (int)$input;
                    }

                    return null;
                }

                return (int)$input;
            }

            return null;
        }

        /**
         * @return Response
         * @noinspection PhpIfWithCommonPartsInspection
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

            if($AccessToken->has_permission(AccountRequestPermissions::ReadPersonalInformation) == false)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 403;
                $Response->ErrorCode = 30;
                $Response->ErrorMessage = Authentication::resolveErrorCode(30);
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            $Response = new Response();
            $Response->Success = true;
            $Response->ResponseCode = 200;
            $Response->ResultData = [
                "first_name" => $this->checkString($UserAccount->PersonalInformation->FirstName),
                "last_name" => $this->checkString($UserAccount->PersonalInformation->LastName),
                "birthday" => [
                    "day" => $this->checkInteger($UserAccount->PersonalInformation->BirthDate->Day),
                    "month" => $this->checkInteger($UserAccount->PersonalInformation->BirthDate->Month),
                    "year" => $this->checkInteger($UserAccount->PersonalInformation->BirthDate->Year)
                ]
            ];
            $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

            return $Response;
        }
    }