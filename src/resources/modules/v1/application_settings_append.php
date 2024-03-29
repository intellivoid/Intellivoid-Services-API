<?php

    /**
     * @noinspection PhpMissingFieldTypeInspection
     * @noinspection DuplicatedCode
     * @noinspection PhpUnused
     * @noinspection PhpIllegalPsrClassPathInspection
     */

    namespace modules\v1;

    use Exception;
    use Handler\Abstracts\Module;
    use Handler\Handler;
    use Handler\Interfaces\Response;
    use HttpAuthenticationFailure;
    use IntellivoidAccounts\Abstracts\AccountRequestPermissions;
    use IntellivoidAccounts\Abstracts\ApplicationSettingsDatumType;
    use IntellivoidAccounts\Exceptions\ApplicationSettingsSizeExceededException;
    use IntellivoidAccounts\Exceptions\InvalidDataTypeForDatumException;
    use IntellivoidAccounts\Exceptions\VariableNotFoundException;
    use IntellivoidAccounts\IntellivoidAccounts;
    use IntellivoidAccounts\Objects\ApplicationSettings\DatumArray;
    use IntellivoidAccounts\Objects\ApplicationSettings\DatumList;
    use IntellivoidAccounts\Utilities\Converter;
    use IntellivoidAPI\Objects\AccessRecord;
    use PpmZiProto\ZiProto;
    use UserAuthenticationFailure;

    require_once(__DIR__ . DIRECTORY_SEPARATOR . "resolve_coa_error.php");
    require_once(__DIR__ . DIRECTORY_SEPARATOR . "client.php");
    require_once(__DIR__ . DIRECTORY_SEPARATOR . "authentication.php");

    /**
     * Class application_settings_get
     */
    class application_settings_append extends Module implements  Response
    {
        /**
         * The name of the module
         *
         * @var string
         */
        public $name = "application_settings_append";

        /**
         * The version of this module
         *
         * @var string
         */
        public $version = "1.0.0.0";

        /**
         * The description of this module
         *
         * @var string
         */
        public $description = "Returns a summary of the Application Settings/Variables";

        /**
         * Optional access record for this module
         *
         * @var AccessRecord
         */
        public $access_record;

        /**
         * The content to give on the response
         *
         * @var string
         */
        private $response_content;

        /**
         * The HTTP response code that will be given to the client
         *
         * @var int
         */
        private $response_code = 200;

        /**
         * @inheritDoc
         */
        public function getContentType(): string
        {
            return "application/json";
        }

        /**
         * @inheritDoc
         */
        public function getContentLength(): int
        {
            return strlen($this->response_content);
        }

        /**
         * @inheritDoc
         */
        public function getBodyContent(): string
        {
            return $this->response_content;
        }

        /**
         * @inheritDoc
         */
        public function getResponseCode(): int
        {
            return $this->response_code;
        }

        /**
         * @inheritDoc
         */
        public function isFile(): bool
        {
            return false;
        }

        /**
         * @inheritDoc
         */
        public function getFileName(): string
        {
            return "";
        }

        /**
         * @inheritDoc
         * @noinspection DuplicatedCode
         */
        public function processRequest()
        {
            $IntellivoidAccounts = new IntellivoidAccounts();

            try
            {
                // Process the authentication requirements
                fetchApplicationAuthentication(true);
                $AccessToken = fetchUserAuthentication($IntellivoidAccounts);
                $UserAccount = getUser($IntellivoidAccounts, $AccessToken);
                $Application = getApplication($IntellivoidAccounts, $AccessToken);
                verifyAccess($AccessToken, $Application);
            }
            catch (HttpAuthenticationFailure | UserAuthenticationFailure $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => $e->getStatusCode(),
                    "error" => array(
                        "error_code" => $e->getCode(),
                        "message" => $e->getMessage(),
                        "type" => "COA"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = $e->getStatusCode();
                return null;
            }
            catch(Exception $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 500,
                    "error" => array(
                        "error_code" => -1,
                        "message" => "An unexpected internal server occurred while trying to process the client's authentication",
                        "type" => "SERVER"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

            if($AccessToken->has_permission(AccountRequestPermissions::SyncApplicationSettings) == false)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 403,
                    "error" => array(
                        "error_code" => 30,
                        "message" => resolve_error_code(30),
                        "type" => "COA"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

            $Parameters = Handler::getParameters(true, true);

            if(isset($Parameters["name"]) == false)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 3,
                        "message" => "Missing parameter 'name'",
                        "type" => "SETTINGS"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

            if(strlen($Parameters["name"]) == 0)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 5,
                        "message" => "Variable name cannot be empty",
                        "type" => "SETTINGS"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

            try
            {
                $ApplicationSettings = $IntellivoidAccounts->getApplicationSettingsManager()->smartGetRecord(
                    $Application->ID, $UserAccount->ID
                );
            }
            catch(Exception $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 500,
                    "error" => array(
                        "error_code" => -1,
                        "message" => "An unexpected internal server occurred while trying to retrieve the Application's settings",
                        "type" => "SERVER"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

            try
            {
                $Results = $ApplicationSettings->get($Parameters["name"]);
            }
            catch (VariableNotFoundException $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 404,
                    "error" => array(
                        "error_code" => 10,
                        "message" => "Variable not found",
                        "type" => "SETTINGS"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }
            catch (Exception $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 500,
                    "error" => array(
                        "error_code" => -1,
                        "message" => "An unexpected internal server occurred while trying to get data",
                        "type" => "SERVER"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

            switch($Results->getCurrentType())
            {
                case ApplicationSettingsDatumType::list:
                    if(isset($Parameters["value"]) == false)
                    {
                        $ResponsePayload = array(
                            "success" => false,
                            "response_code" => 400,
                            "error" => array(
                                "error_code" => 4,
                                "message" => "Missing parameter 'value'",
                                "type" => "SETTINGS"
                            )
                        );
                        $this->response_content = json_encode($ResponsePayload);
                        $this->response_code = (int)$ResponsePayload["response_code"];
                        return null;
                    }

                    try
                    {
                        /** @var DatumList $Results */
                        $Results->appendValue($Parameters["value"]);
                    }
                    catch (InvalidDataTypeForDatumException $e)
                    {
                        $ResponsePayload = array(
                            "success" => false,
                            "response_code" => 400,
                            "error" => array(
                                "error_code" => 8,
                                "message" => $e->getMessage(),
                                "type" => "SETTINGS"
                            )
                        );

                        $this->response_content = json_encode($ResponsePayload);
                        $this->response_code = (int)$ResponsePayload["response_code"];
                        return null;
                    }
                    break;

                case ApplicationSettingsDatumType::array:
                    if(isset($Parameters["value"]) == false)
                    {
                        $ResponsePayload = array(
                            "success" => false,
                            "response_code" => 400,
                            "error" => array(
                                "error_code" => 4,
                                "message" => "Missing parameter 'value'",
                                "type" => "SETTINGS"
                            )
                        );
                        $this->response_content = json_encode($ResponsePayload);
                        $this->response_code = (int)$ResponsePayload["response_code"];
                        return null;
                    }

                    if(isset($Parameters["key"]) == false)
                    {
                        $ResponsePayload = array(
                            "success" => false,
                            "response_code" => 400,
                            "error" => array(
                                "error_code" => 4,
                                "message" => "Missing parameter 'key'",
                                "type" => "SETTINGS"
                            )
                        );
                        $this->response_content = json_encode($ResponsePayload);
                        $this->response_code = (int)$ResponsePayload["response_code"];
                        return null;
                    }

                    try
                    {
                        /** @var DatumArray $Results */
                        $Results->add($Parameters["key"], $Parameters["value"]);
                    }
                    catch (InvalidDataTypeForDatumException $e)
                    {
                        $ResponsePayload = array(
                            "success" => false,
                            "response_code" => 400,
                            "error" => array(
                                "error_code" => 8,
                                "message" => $e->getMessage(),
                                "type" => "SETTINGS"
                            )
                        );

                        $this->response_content = json_encode($ResponsePayload);
                        $this->response_code = (int)$ResponsePayload["response_code"];
                        return null;
                    }
                    break;


                default:
                    $ResponsePayload = array(
                        "success" => false,
                        "response_code" => 400,
                        "error" => array(
                            "error_code" => 11,
                            "message" => "Append not applicable to this variable type",
                            "type" => "SETTINGS"
                        )
                    );

                    $this->response_content = json_encode($ResponsePayload);
                    $this->response_code = (int)$ResponsePayload["response_code"];
                    return null;
            }

            try
            {
                $IntellivoidAccounts->getApplicationSettingsManager()->updateRecord($ApplicationSettings);
            }
            catch (ApplicationSettingsSizeExceededException $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 9,
                        "message" => "Maximum Application size exceeded",
                        "type" => "SETTINGS"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }
            catch (Exception $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 500,
                    "error" => array(
                        "error_code" => -1,
                        "message" => "An unexpected internal server occurred while trying to push changes",
                        "type" => "SERVER"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
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

            $ResponsePayload = array(
                "success" => true,
                "response_code" => 200,
                "results" => $ReturnResults
            );
            $this->response_content = json_encode($ResponsePayload);
            $this->response_code = (int)$ResponsePayload["response_code"];
            return null;
        }
    }