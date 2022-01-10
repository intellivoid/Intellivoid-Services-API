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
    use IntellivoidAccounts\Exceptions\VariableNotFoundException;
    use IntellivoidAccounts\IntellivoidAccounts;
    use IntellivoidAccounts\Objects\ApplicationSettings\DatumArray;
    use IntellivoidAccounts\Objects\ApplicationSettings\DatumList;
    use IntellivoidAccounts\Utilities\Converter;
    use KimchiAPI\Abstracts\Method;
    use KimchiAPI\Abstracts\ResponseStandard;
    use KimchiAPI\Classes\Request;
    use KimchiAPI\Objects\Response;
    use Methods\Utilities\Authentication;
    use Methods\Utilities\HttpAuthenticationFailure;
    use Methods\Utilities\UserAuthenticationFailure;
    use ZiProto\ZiProto;

    /**
     * Class application_settings_get
     */
    class ApplicationSettingsAppendMethod extends Method
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
                $Results = $ApplicationSettings->get($Parameters["name"]);
            }
            catch (VariableNotFoundException $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 404;
                $Response->ErrorCode = 10;
                $Response->ErrorMessage = "Variable not found";
                $Response->Exception = $e;
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }
            catch (Exception $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 500;
                $Response->ErrorCode = -1;
                $Response->ErrorMessage = "An unexpected internal server occurred while trying to get data";
                $Response->Exception = $e;
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            switch($Results->getCurrentType()) {
                case ApplicationSettingsDatumType::list:
                    if (isset($Parameters["value"]) == false) {
                        $Response = new Response();
                        $Response->Success = false;
                        $Response->ResponseCode = 400;
                        $Response->ErrorCode = 4;
                        $Response->ErrorMessage = "Missing parameter 'value'";
                        $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                        return $Response;
                    }

                    try
                    {
                        /** @var DatumList $Results */
                        $Results->appendValue($Parameters["value"]);
                    }
                    catch (InvalidDataTypeForDatumException $e)
                    {
                        $Response = new Response();
                        $Response->Success = false;
                        $Response->ResponseCode = 400;
                        $Response->ErrorCode = 8;
                        $Response->ErrorMessage = "Missing parameter 'value'";
                        $Response->Exception = $e;
                        $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                        return $Response;
                    }
                    break;

                case ApplicationSettingsDatumType::array:
                    if(isset($Parameters["value"]) == false)
                    {
                        $Response = new Response();
                        $Response->Success = false;
                        $Response->ResponseCode = 400;
                        $Response->ErrorCode = 4;
                        $Response->ErrorMessage = "Missing parameter 'value'";
                        $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                        return $Response;
                    }

                    if(isset($Parameters["key"]) == false)
                    {
                        $Response = new Response();
                        $Response->Success = false;
                        $Response->ResponseCode = 400;
                        $Response->ErrorCode = 4;
                        $Response->ErrorMessage = "Missing parameter 'key'";
                        $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                        return $Response;
                    }

                    try
                    {
                        /** @var DatumArray $Results */
                        $Results->add($Parameters["key"], $Parameters["value"]);
                    }
                    catch (InvalidDataTypeForDatumException $e)
                    {
                        $Response = new Response();
                        $Response->Success = false;
                        $Response->ResponseCode = 400;
                        $Response->ErrorCode = 8;
                        $Response->ErrorMessage = $e->getMessage();
                        $Response->Exception = $e;
                        $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                        return $Response;
                    }
                    break;


                default:
                    $Response = new Response();
                    $Response->Success = false;
                    $Response->ResponseCode = 400;
                    $Response->ErrorCode = 11;
                    $Response->ErrorMessage = "Append not applicable to this variable type";
                    $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

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
                $Response->Exception = $e;
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }
            catch (Exception $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 500;
                $Response->ErrorCode = -1;
                $Response->ErrorMessage = "An unexpected internal server occurred while trying to push changes";
                $Response->Exception = $e;
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            $IncludeMeta = false;

            if(isset($Parameters["include_meta"]))
            {
                if(strtolower($Parameters["include_meta"]) == "true" || (int)$Parameters["include_meta"] == 1)
                {
                    $IncludeMeta = true;
                }
            }

            $ReturnResults = $Results->getData();
            if($IncludeMeta)
            {
                $ReturnResults = [
                    "type" => Converter::applicationDatumTypeToString($Results->getCurrentType()),
                    "value" => $Results->getData(),
                    "created_timestamp" => $Results->getCreatedTimestamp(),
                    "last_updated_timestamp" => $Results->getLastUpdatedTimestamp(),
                    "size" => strlen(ZiProto::encode($Results->toArray()))
                ];
            }

            $Response = new Response();
            $Response->Success = true;
            $Response->ResponseCode = 200;
            $Response->ResultData = $ReturnResults;
            $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

            return $Response;
        }
    }