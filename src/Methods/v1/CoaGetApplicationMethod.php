<?php

    /**
     * @noinspection PhpMissingFieldTypeInspection
     * @noinspection DuplicatedCode
     * @noinspection PhpUnused
     * @noinspection PhpIllegalPsrClassPathInspection
     */

    namespace Methods\v1;

    use Exception;
    use Handler\Abstracts\Module;
    use Handler\Interfaces\Response;
    use HttpAuthenticationFailure;
    use IntellivoidAccounts\Abstracts\ApplicationStatus;
    use IntellivoidAccounts\Abstracts\AuthenticationMode;
    use IntellivoidAccounts\Abstracts\SearchMethods\ApplicationSearchMethod;
    use IntellivoidAccounts\Exceptions\ApplicationNotFoundException;
    use IntellivoidAccounts\IntellivoidAccounts;
    use IntellivoidAPI\Objects\AccessRecord;

    require_once(__DIR__ . DIRECTORY_SEPARATOR . "resolve_coa_error.php");
    require_once(__DIR__ . DIRECTORY_SEPARATOR . "client.php");
    require_once(__DIR__ . DIRECTORY_SEPARATOR . "authentication.php");

    /**
     * Class coa_get_application
     */
    class CoaGetApplicationMethod extends Module implements  Response
    {
        /**
         * The name of the module
         *
         * @var string
         */
        public $name = "coa_get_application";

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
        public $description = "Returns information about the Application's Public Information";

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
         */
        public function processRequest()
        {
            try
            {
                // Process the authentication requirements
                $Authentication = fetchApplicationAuthentication(false);
            }
            catch (HttpAuthenticationFailure $e)
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

            $IntellivoidAccounts = new IntellivoidAccounts();

            try
            {
                $Application = $IntellivoidAccounts->getApplicationManager()->getApplication(
                    ApplicationSearchMethod::byApplicationId, $Authentication["application_id"]
                );
            }
            catch (ApplicationNotFoundException $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 404,
                    "error" => array(
                        "error_code" => 2,
                        "message" => resolve_error_code(2),
                        "type" => "COA"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }
            catch(Exception $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 500,
                    "error" => array(
                        "error_code" => -1,
                        "message" => resolve_error_code(-1),
                        "type" => "COA"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

            $EndpointURL = "https://accounts.intellivoid.net/user/contents/public/application?";
            $ResponsePayload = array(
                "success" => true,
                "response_code" => 200,
                "results" => array(
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
                    "permissions" => $Application->Permissions,
                )
            );

            switch($Application->AuthenticationMode)
            {
                case AuthenticationMode::Redirect:
                    $ResponsePayload["results"]["authentication_mode"] = "REDIRECT";
                    break;

                case AuthenticationMode::ApplicationPlaceholder:
                    $ResponsePayload["results"]["authentication_mode"] = "PLACEHOLDER";
                    break;

                case AuthenticationMode::Code:
                    $ResponsePayload["results"]["authentication_mode"] = "RETURN_ACCESS_CODE";
                    break;

                default:
                    $ResponsePayload["results"]["authentication_mode"] = "UNKNOWN";
                    break;
            }

            switch((int)$Application->Status)
            {
                case ApplicationStatus::Active:
                    $ResponsePayload["results"]["status"] = "ACTIVE";
                    break;

                case ApplicationStatus::Disabled:
                    $ResponsePayload["results"]["status"] = "DISABLED";
                    break;

                case ApplicationStatus::Suspended:
                    $ResponsePayload["results"]["status"] = "SUSPENDED";
                    break;

                default:
                    $ResponsePayload["results"]["status"] = "UNKNOWN";
                    break;
            }

            $this->response_content = json_encode($ResponsePayload);
            $this->response_code = (int)$ResponsePayload["response_code"];
            return null;

        }
    }