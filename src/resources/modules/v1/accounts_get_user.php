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
    use Handler\Interfaces\Response;
    use HttpAuthenticationFailure;
    use IntellivoidAccounts\Abstracts\AccountRequestPermissions;
    use IntellivoidAccounts\IntellivoidAccounts;
    use IntellivoidAPI\Objects\AccessRecord;
    use UserAuthenticationFailure;

    require_once(__DIR__ . DIRECTORY_SEPARATOR . "resolve_coa_error.php");
    require_once(__DIR__ . DIRECTORY_SEPARATOR . "client.php");
    require_once(__DIR__ . DIRECTORY_SEPARATOR . "authentication.php");

    /**
     * Class accounts_get_user
     */
    class accounts_get_user extends Module implements  Response
    {
        /**
         * The name of the module
         *
         * @var string
         */
        public $name = "accounts_get_user";

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
        public $description = "Returns information about the user";

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

            if($AccessToken->has_permission(AccountRequestPermissions::GetUserDisplay) == false || $AccessToken->has_permission(AccountRequestPermissions::ViewUsername) == false)
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

            $EndpointURL = "https://accounts.intellivoid.net/user/contents/public/avatar?";
            $ResponsePayload = array(
                "success" => true,
                "response_code" => 200,
                "results" => [
                    "id" => $UserAccount->PublicID,
                    "username" => $UserAccount->Username,
                    "avatar" => [
                        "original" => $EndpointURL . http_build_query(["user_id" => $UserAccount->PublicID, "resource" => "original"]),
                        "normal" => $EndpointURL . http_build_query(["user_id" => $UserAccount->PublicID, "resource" => "normal"]),
                        "preview" => $EndpointURL . http_build_query(["user_id" => $UserAccount->PublicID, "resource" => "preview"]),
                        "small" => $EndpointURL . http_build_query(["user_id" => $UserAccount->PublicID, "resource" => "small"]),
                        "tiny" => $EndpointURL . http_build_query(["user_id" => $UserAccount->PublicID, "resource" => "tiny"]),
                    ]
                ]
            );
            $this->response_content = json_encode($ResponsePayload);
            $this->response_code = (int)$ResponsePayload["response_code"];
            return null;
        }
    }