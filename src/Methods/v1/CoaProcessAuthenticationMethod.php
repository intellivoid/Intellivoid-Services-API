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
    use IntellivoidAccounts\Abstracts\ApplicationStatus;
    use IntellivoidAccounts\Abstracts\SearchMethods\ApplicationSearchMethod;
    use IntellivoidAccounts\Abstracts\SearchMethods\AuthenticationAccessSearchMethod;
    use IntellivoidAccounts\Abstracts\SearchMethods\AuthenticationRequestSearchMethod;
    use IntellivoidAccounts\Exceptions\ApplicationNotFoundException;
    use IntellivoidAccounts\Exceptions\AuthenticationAccessNotFoundException;
    use IntellivoidAccounts\Exceptions\AuthenticationRequestNotFoundException;
    use IntellivoidAccounts\IntellivoidAccounts;
    use IntellivoidAPI\Objects\AccessRecord;

    require_once(__DIR__ . DIRECTORY_SEPARATOR . "resolve_coa_error.php");
    require_once(__DIR__ . DIRECTORY_SEPARATOR . "client.php");
    require_once(__DIR__ . DIRECTORY_SEPARATOR . "authentication.php");

    /**
     * Class coa_process_authentication
     */
    class CoaProcessAuthenticationMethod extends Module implements  Response
    {
        /**
         * The name of the module
         *
         * @var string
         */
        public $name = "coa_process_authentication";

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
        public $description = "Processes the authentication process for the authenticaiton request";

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
            $Parameters = Handler::getParameters(true, true);

            try
            {
                // Process the authentication requirements
                $Authentication = fetchApplicationAuthentication(true);
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

            if(isset($Parameters["request_token"]) == false)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 39,
                        "message" => resolve_error_code(39),
                        "type" => "COA"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

            // Define IntellivoidAccounts
            $IntellivoidAccounts = new IntellivoidAccounts();

            // Check if the Application Exists
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

            // Validate the secret key
            if(hash("sha256", $Authentication["secret_key"]) !== hash("sha256", $Application->SecretKey))
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 401,
                    "error" => array(
                        "error_code" => 23,
                        "message" => resolve_error_code(23),
                        "type" => "COA"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

            // Check if the Application is suspended
            if($Application->Status == ApplicationStatus::Suspended)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 403,
                    "error" => array(
                        "error_code" => 3,
                        "message" => resolve_error_code(3),
                        "type" => "COA"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }


            // Check if the Application is disabled
            if($Application->Status == ApplicationStatus::Disabled)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 403,
                    "error" => array(
                        "error_code" => 4,
                        "message" => resolve_error_code(4),
                        "type" => "COA"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

            // Validate the request token
            try
            {
                $AuthenticationRequest = $IntellivoidAccounts->getCrossOverAuthenticationManager()->getAuthenticationRequestManager()->getAuthenticationRequest(
                    AuthenticationRequestSearchMethod::requestToken, $Parameters["request_token"]
                );
            }
            catch (AuthenticationRequestNotFoundException $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 40,
                        "message" => resolve_error_code(40),
                        "type" => "COA"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }
            catch(Exception $exception)
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

            if($AuthenticationRequest->ApplicationId !== $Application->ID)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 40,
                        "message" => resolve_error_code(40),
                        "type" => "COA"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

            // Check if the Authentication Request Token is expired
            if((int)time() > $AuthenticationRequest->ExpiresTimestamp)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 34,
                        "message" => resolve_error_code(34),
                        "type" => "COA"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

            // Find the Authentication Access Token
            try
            {
                $AuthenticationAccess = $IntellivoidAccounts->getCrossOverAuthenticationManager()->getAuthenticationAccessManager()->getAuthenticationAccess(
                    AuthenticationAccessSearchMethod::byRequestId, $AuthenticationRequest->Id
                );
            }
            catch (AuthenticationAccessNotFoundException $e)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 41,
                        "message" => resolve_error_code(41),
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

            // If all the conditions are met, return the Authentication Token with the related information
            $ResponsePayload = array(
                "success" => true,
                "response_code" => 200,
                "results" => array(
                    "access_token" => $AuthenticationAccess->AccessToken,
                    "granted_permissions" => $AuthenticationAccess->Permissions,
                    "expires_timestamp" => $AuthenticationAccess->ExpiresTimestamp
                )
            );
            $this->response_content = json_encode($ResponsePayload);
            $this->response_code = (int)$ResponsePayload["response_code"];
            return null;
        }
    }