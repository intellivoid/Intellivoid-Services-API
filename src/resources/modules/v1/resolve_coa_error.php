<?php

    /**
     * Resolves the error code into a human-readable message
     *
     * @param int $error_code
     * @return string
     */
    function resolve_error_code(int $error_code): string
    {
        switch($error_code)
        {
            case -1:
                return("INTERNAL SERVER ERROR");

            case 1:
                return("MISSING PARAMETER 'application_id'");

            case 2:
                return("INVALID APPLICATION ID");

            case 3:
                return("APPLICATION SUSPENDED");

            case 4:
                return("APPLICATION UNAVAILABLE");

            case 5:
                return("CANNOT VERIFY CLIENT HOST");

            case 6:
                return("MISSING PARAMETER 'redirect'");

            case 7:
                return("MISSING PARAMETER 'auth' IN AUTH PROMPT");

            case 8:
                return("MISSING PARAMETER 'application_id' IN AUTH PROMPT");

            case 9:
                return("MISSING PARAMETER 'request_token' IN AUTH PROMPT");

            case 10:
                return("INVALID APPLICATION ID IN AUTH PROMPT");

            case 11:
                return("INTERNAL SERVER ERROR IN AUTH PROMPT (TYPE PROMPT-01)");

            case 12:
                return("INVALID REQUEST TOKEN IN AUTH PROMPT");

            case 13:
                return("INTERNAL SERVER ERROR IN AUTH PROMPT (TYPE PROMPT-02)");

            case 14:
                return("MISSING PARAMETER 'redirect' IN AUTH PROMPT");

            case 15:
                return("UNSUPPORTED AUTHENTICATION TYPE");

            case 16:
                return("INVALID REDIRECT URL");

            case 17:
                return("MISSING PARAMETER 'verification_token' IN AUTH PROMPT->ACTION");

            case 18:
                return("CANNOT VERIFY REQUEST, INVALID VERIFICATION TOKEN");

            case 19:
                return("AUTHENTICATION ACCESS DOES NOT EXIST");

            case 20:
                return("ALREADY AUTHENTICATED");

            case 21:
                return("INTERNAL SERVER ERROR WHILE TRYING TO AUTHENTICATE USER");

            case 22:
                return("MISSING PARAMETER 'secret_key'");

            case 23:
                return("ACCESS DENIED, INCORRECT SECRET KEY");

            case 24:
                return("MISSING PARAMETER 'access_token'");

            case 25:
                return("ACCESS DENIED, INCORRECT ACCESS TOKEN");

            case 26:
                return("ACCESS DENIED, ACCOUNT NOT FOUND");

            case 27:
                return("ACCESS TOKEN EXPIRED");

            case 28:
                return("ACCOUNT SUSPENDED");

            case 29:
                return("ACCESS DENIED, USER DISABLED ACCESS");

            case 30:
                return("ACCESS DENIED, INSUFFICIENT PERMISSIONS");

            case 31:
                return("MISSING PARAMETER 'field'");

            case 32:
                return("MISSING PARAMETER 'value'");

            case 33:
                return("INVALID VALUE FOR 'first_name'");

            case 34:
                return("REQUEST TOKEN EXPIRED");

            case 35:
                return("UNSUPPORTED APPLICATION AUTHENTICATION TYPE");

            case 36:
                return("CRYPTO ERROR, APPLICATION CERTIFICATE MISHAP");

            case 37:
                return("CRYPTO ERROR, AUTHENTICATION REQUEST MISHAP");

            case 38:
                return("ACCESS DENIED");

            case 39:
                return("MISSING PARAMETER 'request_token'");

            case 40:
                return("INVALID REQUEST TOKEN");

            case 41:
                return("AWAITING AUTHENTICATION");

            case 42:
                return("MISSING PARAMETER 'plan_name'");

            case 43:
                return("SUBSCRIPTION PLAN NOT FOUND");

            case 44:
                return("SUBSCRIPTION PROMOTION NOT FOUND");

            case 45:
                return("SUBSCRIPTION PLAN NOT AVAILABLE");

            case 46:
                return("SUBSCRIPTION PROMOTION NOT AVAILABLE");

            case 47:
                return("SUBSCRIPTION PROMOTION EXPIRED");

            case 48:
                return("SUBSCRIPTION PROMOTION NOT APPLICABLE TO PLAN");

            case 49:
                return("INSUFFICIENT FUNDS");

            case 50:
                return("MISSING PARAMETERS 'subscription_id'");

            case 51:
                return("ACCESS DENIED DUE TO SECURITY ISSUES");

            default:
                return("UNKNOWN ERROR");
        }
    }