<?php

    namespace Methods\Utilities;

    use Exception;

    /**
     * Class apiAuthenticationFailure
     */
    class HttpAuthenticationFailure extends Exception
    {
        /**
         * @var int
         */
        private int $coa_error_code;

        /**
         * @var int
         */
        private int $status_code;

        /**
         * HttpAuthenticationFailure constructor.
         * @param int $coa_error_code
         * @param int $status_code
         */
        public function __construct(int $coa_error_code, int $status_code)
        {
            parent::__construct(Authentication::resolveErrorCode($coa_error_code), $coa_error_code);
            $this->coa_error_code = $coa_error_code;
            $this->status_code = $status_code;
        }

        /**
         * @return int
         */
        public function getCoaErrorCode(): int
        {
            return $this->coa_error_code;
        }

        /**
         * @return int
         */
        public function getStatusCode(): int
        {
            return $this->status_code;
        }
    }