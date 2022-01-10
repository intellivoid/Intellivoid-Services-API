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
    use IntellivoidAccounts\Exceptions\InvalidDatumTypeException;
    use IntellivoidAccounts\Exceptions\MalformedJsonDataException;
    use IntellivoidAccounts\Exceptions\VariableNameAlreadyExistsException;
    use IntellivoidAccounts\IntellivoidAccounts;
    use IntellivoidAPI\Objects\AccessRecord;
    use UserAuthenticationFailure;

    require_once(__DIR__ . DIRECTORY_SEPARATOR . "resolve_coa_error.php");
    require_once(__DIR__ . DIRECTORY_SEPARATOR . "client.php");
    require_once(__DIR__ . DIRECTORY_SEPARATOR . "authentication.php");

    /**
     * Class application_settings_add
     */
    class ApplicationSettingsAddMethod extends Module implements  Response
    {
        /**
         * The name of the module
         *
         * @var string
         */
        public $name = "application_settings_add";

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

            // Validate the variable type
            if(isset($Parameters["type"]) == false)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 1,
                        "message" => "Missing parameter 'type'",
                        "type" => "SETTINGS"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

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
                    $ResponsePayload = array(
                        "success" => false,
                        "response_code" => 400,
                        "error" => array(
                            "error_code" => 2,
                            "message" => "Invalid variable type",
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
                $ApplicationSettings->add(
                    $CreateOptions["value_type"],
                    $CreateOptions["name"],
                    $CreateOptions["value_raw"],
                    $CreateOptions["overwrite"]
                );
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
            catch (InvalidDatumTypeException $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 2,
                        "message" => "Invalid variable type",
                        "type" => "SETTINGS"
                    )
                );

                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }
            catch (VariableNameAlreadyExistsException $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 6,
                        "message" => "Variable already exists and cannot be overwritten",
                        "type" => "SETTINGS"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }
            catch (MalformedJsonDataException $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 7,
                        "message" => "The value cannot be parsed, expected JSON data",
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

            $ResponsePayload = array(
                "success" => true,
                "response_code" => 200,
                "results" => $ApplicationSettings->getSummary()
            );
            $this->response_content = json_encode($ResponsePayload);
            $this->response_code = (int)$ResponsePayload["response_code"];
            return null;
        }
    }