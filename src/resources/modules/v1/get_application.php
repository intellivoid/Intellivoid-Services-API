<?php

    /** @noinspection PhpUnused */
    /** @noinspection PhpIllegalPsrClassPathInspection */

    namespace modules\v1;

    use Exception;
    use Handler\Abstracts\Module;
    use Handler\Handler;
    use Handler\Interfaces\Response;
    use IntellivoidAccounts\Abstracts\ApplicationStatus;
    use IntellivoidAccounts\Abstracts\AuthenticationMode;
    use IntellivoidAccounts\Abstracts\SearchMethods\ApplicationSearchMethod;
    use IntellivoidAccounts\Exceptions\ApplicationNotFoundException;
    use IntellivoidAccounts\IntellivoidAccounts;
    use IntellivoidAPI\Objects\AccessRecord;

    require_once(__DIR__ . DIRECTORY_SEPARATOR . "resolve_coa_error.php");

    /**
     * Class get_application
     */
    class get_application extends Module implements  Response
    {
        /**
         * The name of the module
         *
         * @var string
         */
        public $name = 'create_authentication_request';

        /**
         * The version of this module
         *
         * @var string
         */
        public $version = '1.0.0.0';

        /**
         * The description of this module
         *
         * @var string
         */
        public $description = "Returns information about the user that's available in the Spam Protection Database";

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
            return 'application/json';
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
         */
        public function processRequest()
        {
            $Parameters = Handler::getParameters(true, true);

            if(isset($Parameters["application_id"]) == false)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 0,
                        "type" => "CLIENT",
                        "message" => "Missing parameter 'application_id'"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload['response_code'];
                return null;
            }

            $IntellivoidAccounts = new IntellivoidAccounts();

            try
            {
                $Application = $IntellivoidAccounts->getApplicationManager()->getApplication(
                    ApplicationSearchMethod::byApplicationId, $Parameters["application_id"]
                );
            }
            catch (ApplicationNotFoundException $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 404,
                    "error" => array(
                        "error_code" => 2,
                        "message" => resolve_error_code(2)
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload['response_code'];
                return null;
            }
            catch(Exception $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 500,
                    "error" => array(
                        "error_code" => -1,
                        "message" => resolve_error_code(-1)
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload['response_code'];
                return null;
            }

            $ResponsePayload = array(
                "success" => true,
                "response_code" => 200,
                "application" => array(
                    "name" => $Application->Name,
                    "name_safe" => $Application->NameSafe,
                    "status" => "UNKNOWN",
                    "authentication_mode" => "UNKNOWN",
                    "permissions" => $Application->Permissions,
                )
            );

            switch($Application->AuthenticationMode)
            {
                case AuthenticationMode::Redirect:
                    $ResponsePayload["application"]["authentication_mode"] = "REDIRECT";
                    break;

                case AuthenticationMode::ApplicationPlaceholder:
                    $ResponsePayload["application"]["authentication_mode"] = "PLACEHOLDER";
                    break;

                case AuthenticationMode::Code:
                    $ResponsePayload["application"]["authentication_mode"] = "RETURN_ACCESS_CODE";
                    break;

                default:
                    $ResponsePayload["application"]["authentication_mode"] = "UNKNOWN";
                    break;
            }

            switch($Application->Status)
            {
                case ApplicationStatus::Active:
                    $ResponsePayload["application"]["status"] = "ACTIVE";
                    break;

                case ApplicationStatus::Disabled:
                    $ResponsePayload["application"]["status"] = "DISABLED";
                    break;

                case ApplicationStatus::Suspended:
                    $ResponsePayload["application"]["status"] = "SUSPENDED";
                    break;

                default:
                    $ResponsePayload["application"]["status"] = "UNKNOWN";
                    break;
            }

            $this->response_content = json_encode($ResponsePayload);
            $this->response_code = (int)$ResponsePayload['response_code'];
            return null;

        }
    }