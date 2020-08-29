<?php

    /** @noinspection PhpUnused */
    /** @noinspection PhpIllegalPsrClassPathInspection */

    namespace modules\v1;

    use Client;
    use Exception;
    use Handler\Abstracts\Module;
    use Handler\Handler;
    use Handler\Interfaces\Response;
    use IntellivoidAccounts\Abstracts\ApplicationStatus;
    use IntellivoidAccounts\Abstracts\AuthenticationMode;
    use IntellivoidAccounts\Abstracts\AuthenticationRequestStatus;
    use IntellivoidAccounts\Abstracts\SearchMethods\ApplicationSearchMethod;
    use IntellivoidAccounts\Exceptions\ApplicationNotFoundException;
    use IntellivoidAccounts\IntellivoidAccounts;
    use IntellivoidAPI\Objects\AccessRecord;

    require_once(__DIR__ . DIRECTORY_SEPARATOR . "resolve_coa_error.php");
    require_once(__DIR__ . DIRECTORY_SEPARATOR . "client.php");

    /**
     * Class get_application
     */
    class coa_request_authentication extends Module implements  Response
    {
        /**
         * The name of the module
         *
         * @var string
         */
        public $name = 'coa_request_authentication';

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
        public $description = "Creates a request token to authenticate to the Application using COA";

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
         * @noinspection DuplicatedCode
         */
        public function processRequest()
        {
            $Parameters = Handler::getParameters(true, true);

            // Check the main parameters
            if(isset($Parameters["application_id"]) == false)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 0,
                        "message" => "Missing parameter 'application_id'"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload['response_code'];
                return null;
            }

            // Define IntellivoidAccounts
            $IntellivoidAccounts = new IntellivoidAccounts();

            // Check if the Application Exists
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

            // Check if the Application is suspended
            if($Application->Status == ApplicationStatus::Suspended)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 403,
                    "error" => array(
                        "error_code" => 3,
                        "message" => resolve_error_code(3)
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload['response_code'];
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
                        "message" => resolve_error_code(4)
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload['response_code'];
                return null;
            }

            // Check if the required redirect parameter is present
            if($Application->AuthenticationMode == AuthenticationMode::Redirect)
            {
                if(isset($Parameters["redirect"]) == false)
                {
                    $ResponsePayload = array(
                        "success" => false,
                        "response_code" => 400,
                        "error" => array(
                            "error_code" => 6,
                            "message" => resolve_error_code(6)
                        )
                    );
                    $this->response_content = json_encode($ResponsePayload);
                    $this->response_code = (int)$ResponsePayload['response_code'];
                    return null;
                }
            }

            // Check the client
            try
            {
                $ClientIP = Client::getClientIP();
                if($ClientIP == "::1")
                {
                    $ClientIP = "127.0.0.1";
                }

                $KnownHost = $IntellivoidAccounts->getKnownHostsManager()->syncHost($ClientIP, Client::getUserAgentRaw());
            }
            catch(Exception $exception)
            {
                $ResponsePayload = array(
                    "success" => false,
                    "response_code" => 400,
                    "error" => array(
                        "error_code" => 5,
                        "message" => resolve_error_code(5)
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload['response_code'];
                return null;
            }

            // Generate an authentication request token
            try
            {
                $AuthRequestToken = $IntellivoidAccounts->getCrossOverAuthenticationManager()->getAuthenticationRequestManager()->createAuthenticationRequest(
                    $Application, $KnownHost->ID
                );
            }
            catch (Exception $e)
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

            // Check the protocol
            $protocol = 'https';

            if(isset($Parameters["secured"]))
            {
                if($Parameters["secured"] == "false" || $Parameters["secured"] == "0")
                {
                    $protocol = 'http';
                }
            }

            switch($AuthRequestToken->Status)
            {
                case AuthenticationRequestStatus::Active:
                    $AuthenticationRequestStatus = "ACTIVE";
                    break;

                case AuthenticationRequestStatus::Blocked:
                    $AuthenticationRequestStatus = "BLOCKED";
                    break;

                default:
                    $AuthenticationRequestStatus = "UNKNOWN";
                    break;
            }

            if((int)time() > $AuthRequestToken->ExpiresTimestamp)
            {
                $AuthenticationRequestStatus = "EXPIRED";
            }

            // Return the results applicable to the Application's authentication mode
            if($Application->AuthenticationMode == AuthenticationMode::Redirect)
            {
                $AuthenticationUrl = $protocol . "://accounts.intellivoid.net/auth/login?" . http_build_query(array(
                        "auth" => "application",
                        "redirect" => $Parameters["redirect"],
                        "application_id" => $Application->PublicAppId,
                        "request_token" => $AuthRequestToken->RequestToken
                    ));

                $ResponsePayload = array(
                    "success" => true,
                    "response_code" => 200,
                    "results" => array(
                        "request_token" => $AuthRequestToken->RequestToken,
                        "requested_permissions" => $AuthRequestToken->RequestedPermissions,
                        "status" => $AuthenticationRequestStatus,
                        "authentication_url" => $AuthenticationUrl,
                        "expires_timestamp" => $AuthRequestToken->ExpiresTimestamp
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload['response_code'];
                return null;
            }
            else
            {
                $AuthenticationUrl = $protocol . "://accounts.intellivoid.net/auth/login?" . http_build_query(array(
                        "auth" => "application",
                        "application_id" => $Application->PublicAppId,
                        "request_token" => $AuthRequestToken->RequestToken
                    ));

                $ResponsePayload = array(
                    "success" => true,
                    "response_code" => 200,
                    "results" => array(
                        "request_token" => $AuthRequestToken->RequestToken,
                        "requested_permissions" => $AuthRequestToken->RequestedPermissions,
                        "status" => $AuthenticationRequestStatus,
                        "authentication_url" => $AuthenticationUrl,
                        "expires_timestamp" => $AuthRequestToken->ExpiresTimestamp
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload['response_code'];
                return null;
            }
        }
    }