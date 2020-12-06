<?php

    /**
     * Class Client
     */
    class Client
    {
        /**
         * Returns the IP address of the client
         *
         * @return string
         * @noinspection DuplicatedCode
         */
        public static function getClientIP(): string
        {
            if(isset($_SERVER['HTTP_CF_CONNECTING_IP']))
            {
                return $_SERVER['HTTP_CF_CONNECTING_IP'];
            }

            if(isset($_SERVER['HTTP_CLIENT_IP']))
            {
                return $_SERVER['HTTP_CLIENT_IP'];
            }

            if(isset($_SERVER['HTTP_X_FORWARDED_FOR']))
            {
                return $_SERVER['HTTP_X_FORWARDED_FOR'];
            }

            if(isset($_SERVER['HTTP_X_FORWARDED']))
            {
                return $_SERVER['HTTP_X_FORWARDED'];
            }

            if(isset($_SERVER['HTTP_FORWARDED_FOR']))
            {
                return $_SERVER['HTTP_FORWARDED_FOR'];
            }

            if(isset($_SERVER['HTTP_FORWARDED']))
            {
                return $_SERVER['HTTP_FORWARDED'];
            }

            if(isset($_SERVER['REMOTE_ADDR']))
            {
                return $_SERVER['REMOTE_ADDR'];
            }

            if(getenv('HTTP_CLIENT_IP') !== False)
            {
                return getenv('HTTP_CLIENT_IP');
            }

            if(getenv('HTTP_X_FORWARDED_FOR'))
            {
                return getenv('HTTP_X_FORWARDED_FOR');
            }

            if(getenv('HTTP_X_FORWARDED'))
            {
                return getenv('HTTP_X_FORWARDED');
            }

            if(getenv('HTTP_FORWARDED_FOR'))
            {
                return getenv('HTTP_FORWARDED_FOR');
            }

            if(getenv('HTTP_FORWARDED'))
            {
                return getenv('HTTP_FORWARDED');
            }

            if(getenv('REMOTE_ADDR'))
            {
                return getenv('REMOTE_ADDR');
            }

            return '127.0.0.1';
        }

        /**
         * Returns the raw string for the user agent
         *
         * @return string
         */
        public static function getUserAgentRaw(): string
        {
            if(isset($_SERVER['HTTP_USER_AGENT']))
            {
                return $_SERVER['HTTP_USER_AGENT'];
            }

            return "Unknown (Generic HTTP 1.1 Client)";
        }
    }