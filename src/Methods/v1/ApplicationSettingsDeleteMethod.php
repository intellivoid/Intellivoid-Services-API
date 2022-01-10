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
     * Class application_settings_get_summary
     */
    class ApplicationSettingsDeleteMethod extends Method
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
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            $RequestOptions = array(
                "name" => $Parameters["name"],
                "delete_mode" => "variable",
                "by" => null,
                "value" => null
            );

            if(isset($Parameters["by"]))
            {
                switch(strtolower($Parameters["by"]))
                {
                    case "index":
                    case "key":
                        $RequestOptions["by"] = strtolower($Parameters["by"]);
                        $RequestOptions["delete_mode"] = "value";
                        break;

                    default:
                        $Response = new Response();
                        $Response->Success = false;
                        $Response->ResponseCode = 400;
                        $Response->ErrorCode = 12;
                        $Response->ErrorMessage = "Invalid value in parameter 'by'";
                        $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                        return $Response;
                }

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

                $RequestOptions["value"] = $Parameters["value"];
            }

            $SettingsVariable = null;

            try
            {
                if($RequestOptions["delete_mode"] == "variable")
                {
                    $ApplicationSettings->delete($Parameters["name"]);
                }
                else
                {
                    $SettingsVariable = $ApplicationSettings->get($Parameters["name"]);
                    switch($SettingsVariable->getCurrentType())
                    {
                        case ApplicationSettingsDatumType::list:
                            /** @var DatumList $SettingsVariable */

                            if($RequestOptions["by"] == "index")
                            {
                                $SettingsVariable->removeValueByIndex((int)$Parameters["value"]);
                            }
                            else
                            {
                                $SettingsVariable->removeValueByValue($Parameters["value"]);
                            }

                            $ApplicationSettings->Data[$Parameters["name"]] = $SettingsVariable;
                            break;

                        case ApplicationSettingsDatumType::array:

                            if($RequestOptions["by"] == "key")
                            {
                                /** @var DatumArray $SettingsVariable */
                                $SettingsVariable->removeValueByKey($Parameters["value"]);

                            }
                            else
                            {
                                $Response = new Response();
                                $Response->Success = false;
                                $Response->ResponseCode = 400;
                                $Response->ErrorCode = 14;
                                $Response->ErrorMessage = "Cannot remove value by Index on array data type";
                                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                                return $Response;
                            }

                            $ApplicationSettings->Data[$Parameters["name"]] = $SettingsVariable;
                            break;

                        default:
                            $Response = new Response();
                            $Response->Success = false;
                            $Response->ResponseCode = 400;
                            $Response->ErrorCode = 13;
                            $Response->ErrorMessage = "Delete is not applicable to this variable type";
                            $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                            return $Response;
                    }
                }

                $IntellivoidAccounts->getApplicationSettingsManager()->updateRecord($ApplicationSettings);
            }
            catch (VariableNotFoundException $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 404;
                $Response->ErrorCode = 10;
                $Response->ErrorMessage = "Variable not found";
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }
            catch (ApplicationSettingsSizeExceededException $e)
            {
                $Response = new Response();
                $Response->Success = false;
                $Response->ResponseCode = 400;
                $Response->ErrorCode = 9;
                $Response->ErrorMessage = "Maximum Application size exceeded";
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
                $Response->ResponseStandard = ResponseStandard::IntellivoidAPI;

                return $Response;
            }

            if($RequestOptions["delete_mode"] == "variable")
            {
                $Response = new Response();
                $Response->Success = true;
                $Response->ResponseCode = 200;
                $Response->ResultData = $ApplicationSettings->getSummary();
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

            $ReturnResults = $SettingsVariable->getData();
            if($IncludeMeta)
            {
                $ReturnResults = [
                    "type" => Converter::applicationDatumTypeToString($SettingsVariable->getCurrentType()),
                    "value" => $SettingsVariable->getData(),
                    "created_timestamp" => $SettingsVariable->getCreatedTimestamp(),
                    "last_updated_timestamp" => $SettingsVariable->getLastUpdatedTimestamp(),
                    "size" => strlen(ZiProto::encode($SettingsVariable->toArray()))
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