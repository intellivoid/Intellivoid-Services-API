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
    use IntellivoidAccounts\Abstracts\ApplicationSettingsDatumType;
    use IntellivoidAccounts\Exceptions\ApplicationSettingsSizeExceededException;
    use IntellivoidAccounts\Exceptions\InvalidDataTypeForDatumException;
    use IntellivoidAccounts\Exceptions\InvalidDatumTypeException;
    use IntellivoidAccounts\Exceptions\MalformedJsonDataException;
    use IntellivoidAccounts\Exceptions\VariableNameAlreadyExistsException;
    use IntellivoidAccounts\IntellivoidAccounts;
    use KimchiAPI\Abstracts\Method;
    use KimchiAPI\Abstracts\ResponseStandard;
    use KimchiAPI\Classes\Request;
    use KimchiAPI\Objects\Response;
    use Methods\Utilities\Authentication;
    use Methods\Utilities\HttpAuthenticationFailure;
    use Methods\Utilities\UserAuthenticationFailure;

    /**
     * Class application_settings_add
     */
    class ApplicationSettingsAddMethod extends Method
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

            if($AccessToken->has_permission(AccountRequestPermissions::SyncApplicationSettings) == false)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 403;
                $Response->ErrorCode = 30;
                $Response->ErrorMessage = Authentication::resolveErrorCode(30);
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            $Parameters = Request::getParameters();

            // Validate the variable type
            if(isset($Parameters["type"]) == false)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 400;
                $Response->ErrorCode = 1;
                $Response->ErrorMessage = "Missing parameter 'type'";
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            if(isset($Parameters["name"]) == false)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 400;
                $Response->ErrorCode = 3;
                $Response->ErrorMessage = "Missing parameter 'name'";
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            if(strlen($Parameters["name"]) == 0)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 400;
                $Response->ErrorCode = 5;
                $Response->ErrorMessage = "Variable name cannot be empty";
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            $CreateOptions = [
                "value_type" => null,
                "overwrite" => true,
                "name" => $Parameters["name"],
                "value_raw" => null
            ];

            if(isset($Parameters["value"]))
            {
                $CreateOptions["value_raw"] = $Parameters["value"];
            }

            if(isset($Parameters["overwrite"]))
            {
                if(strtolower($Parameters["overwrite"]) == "false" || (int)$Parameters["overwrite"] == 0)
                {
                    $CreateOptions["overwrite"] = false;
                }
            }

            switch(strtolower($Parameters["type"]))
            {
                case (string)ApplicationSettingsDatumType::string:
                case "string":
                case "str":
                    $CreateOptions["value_type"] = ApplicationSettingsDatumType::string;
                    break;

                case (string)ApplicationSettingsDatumType::boolean:
                case "boolean":
                case "bool":
                    $CreateOptions["value_type"] = ApplicationSettingsDatumType::boolean;
                    break;

                case (string)ApplicationSettingsDatumType::integer:
                case "integer":
                case "int":
                    $CreateOptions["value_type"] = ApplicationSettingsDatumType::integer;
                    break;

                case ApplicationSettingsDatumType::list:
                case "list":
                    $CreateOptions["value_type"] = ApplicationSettingsDatumType::list;
                    break;

                case ApplicationSettingsDatumType::array:
                case "array":
                    $CreateOptions["value_type"] = ApplicationSettingsDatumType::array;
                    break;

                default:
                    $Response = new Response();
                    $Response->Success = false;
                    $Response->ResponseCode = 400;
                    $Response->ErrorCode = 2;
                    $Response->ErrorMessage = "Invalid variable type";
                    $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                    return $Response;
            }

            try
            {
                $ApplicationSettings = $IntellivoidAccounts->getApplicationSettingsManager()->smartGetRecord(
                    $Application->ID, $UserAccount->ID
                );
            }
            catch(Exception $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 500;
                $Response->ErrorCode = -1;
                $Response->ErrorMessage = "An unexpected internal server occurred while trying to retrieve the Application's settings";
                $Response->Exception = $e;
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            try
            {
                $ApplicationSettings->add(
                    $CreateOptions["value_type"],
                    $CreateOptions["name"],
                    $CreateOptions["value_raw"],
                    $CreateOptions["overwrite"]
                );
            }
            catch (InvalidDataTypeForDatumException $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 400;
                $Response->ErrorCode = 8;
                $Response->ErrorMessage = $e->getMessage();
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;
                $Response->Exception = $e;

                return $Response;
            }
            catch (InvalidDatumTypeException $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 400;
                $Response->ErrorCode = 2;
                $Response->ErrorMessage = "Invalid variable type";
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;
                $Response->Exception = $e;

                return $Response;
            }
            catch (VariableNameAlreadyExistsException $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 400;
                $Response->ErrorCode = 6;
                $Response->ErrorMessage = "Variable already exists and cannot be overwritten";
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;
                $Response->Exception = $e;

                return $Response;
            }
            catch (MalformedJsonDataException $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 400;
                $Response->ErrorCode = 7;
                $Response->ErrorMessage = "The value cannot be parsed, expected JSON data";
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;
                $Response->Exception = $e;

                return $Response;
            }

            try
            {
                $IntellivoidAccounts->getApplicationSettingsManager()->updateRecord($ApplicationSettings);
            }
            catch (ApplicationSettingsSizeExceededException $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 400;
                $Response->ErrorCode = 9;
                $Response->ErrorMessage = "Maximum Application size exceeded";
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;
                $Response->Exception = $e;

                return $Response;
            }
            catch (Exception $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 500;
                $Response->ErrorCode = -1;
                $Response->ErrorMessage = "An unexpected internal server occurred while trying to push changes";
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;
                $Response->Exception = $e;

                return $Response;
            }

            $Response = new Response();
            $Response->Success = true;
            $Response->ResponseCode = 200;
            $Response->ResultData = $ApplicationSettings->getSummary();

            return $Response;
        }
    }