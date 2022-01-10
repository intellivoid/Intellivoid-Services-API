<?php

    /**
     * @noinspection PhpMissingFieldTypeInspection
     * @noinspection DuplicatedCode
     * @noinspection PhpUnused
     * @noinspection PhpIllegalPsrClassPathInspection
     */

    namespace Methods\v1;

    use Client;
    use Exception;
    use Handler\Abstracts\Module;
    use Handler\Handler;
    use Handler\Interfaces\Response;
    use HttpAuthenticationFailure;
    use IntellivoidAccounts\Abstracts\ApplicationStatus;
    use IntellivoidAccounts\Abstracts\AuthenticationMode;
    use IntellivoidAccounts\Abstracts\AuthenticationRequestStatus;
    use IntellivoidAccounts\Abstracts\SearchMethods\ApplicationSearchMethod;
    use IntellivoidAccounts\Exceptions\ApplicationNotFoundException;
    use IntellivoidAccounts\IntellivoidAccounts;
    use IntellivoidAPI\Objects\AccessRecord;



    /**
     * Class coa_request_authentication
     */
    class CoaRequestAuthenticationMethod extends Module implements  Response
    {
        /**
         * The name of the module
         *
         * @var string
         */
        public $name = "coa_request_authentication";

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
                            "message" => resolve_error_code(6),
                            "type" => "COA"
                        )
                    );
                    $this->response_content = json_encode($ResponsePayload);
                    $this->response_code = (int)$ResponsePayload["response_code"];
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
                        "message" => resolve_error_code(5),
                        "type" => "COA"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
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
                        "message" => resolve_error_code(-1),
                        "type" => "COA"
                    )
                );
                $this->response_content = json_encode($ResponsePayload);
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }

            if($AuthRequestToken->ApplicationId !== $Application->ID)
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

            // Check the protocol
            $protocol = "https";

            if(isset($Parameters["secured"]))
            {
                if($Parameters["secured"] == "false" || $Parameters["secured"] == "0")
                {
                    $protocol = "http";
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
                $AuthenticationParameters =  array(
                    "auth" => "application",
                    "redirect" => $Parameters["redirect"],
                    "application_id" => $Application->PublicAppId,
                    "request_token" => $AuthRequestToken->RequestToken
                );

                if(isset($Parameters["expand_ui"]))
                {
                    if($Parameters["expand_ui"] == "true" || $Parameters["expand_ui"] == "1")
                    {
                        $AuthenticationParameters["expanded"] = "1";
                    }
                }

                if(isset($Parameters["require_close"]))
                {
                    if($Parameters["require_close"] == "true" || $Parameters["require_close"] == "1")
                    {
                        $AuthenticationParameters["require_close"] = "1";
                    }
                }

                $AuthenticationUrl = $protocol . "://accounts.intellivoid.net/auth/login?" . http_build_query($AuthenticationParameters);

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
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }
            else
            {
                $AuthenticationParameters =  array(
                    "auth" => "application",
                    "application_id" => $Application->PublicAppId,
                    "request_token" => $AuthRequestToken->RequestToken
                );

                if(isset($Parameters["expand_ui"]))
                {
                    if($Parameters["expand_ui"] == "true" || $Parameters["expand_ui"] == "1")
                    {
                        $AuthenticationParameters["expanded"] = "1";
                    }
                }

                if(isset($Parameters["require_close"]))
                {
                    if($Parameters["require_close"] == "true" || $Parameters["require_close"] == "1")
                    {
                        $AuthenticationParameters["require_close"] = "1";
                    }
                }

                $AuthenticationUrl = $protocol . "://accounts.intellivoid.net/auth/login?" . http_build_query($AuthenticationParameters);

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
                $this->response_code = (int)$ResponsePayload["response_code"];
                return null;
            }
        }
    }