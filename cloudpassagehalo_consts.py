# --
# File: cloudpassagehalo/cloudpassagehalo_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --
CLOUDPASSAGEHALO_CONFIG_URL = "url"
CLOUDPASSAGEHALO_CONFIG_CLIENT_ID = "client_id"
CLOUDPASSAGEHALO_CONFIG_CLIENT_SECRET = "client_secret"
CLOUDPASSAGEHALO_REST_RESP_SUCCESS = 200
CLOUDPASSAGEHALO_REST_RESP_UNAUTHORIZED = 401
CLOUDPASSAGEHALO_REST_RESP_UNAUTHORIZED_MSG = "The supplied credentials, if any, are not sufficient to access the" \
                                              " resource."
CLOUDPASSAGEHALO_REST_RESP_BAD_REQUEST = 400
CLOUDPASSAGEHALO_REST_RESP_BAD_REQUEST_MSG = "The data given in the POST or PUT failed validation. Inspect the " \
                                             "response body for details."
CLOUDPASSAGEHALO_REST_RESP_FORBIDDEN = 403
CLOUDPASSAGEHALO_REST_RESP_FORBIDDEN_MSG = "The authorization level is not sufficient to access the resource."
CLOUDPASSAGEHALO_REST_RESP_NOT_FOUND = 404
CLOUDPASSAGEHALO_REST_RESP_NOT_FOUND_MSG = "Resource not found."
CLOUDPASSAGEHALO_REST_RESP_INTERNAL_SERVER_ERROR = 500
CLOUDPASSAGEHALO_REST_RESP_INTERNAL_SERVER_ERROR_MSG = "We could not return the representation due to an internal " \
                                                       "server error."
CLOUDPASSAGEHALO_REST_RESP_OTHER_ERROR_MSG = "Error returned"
CLOUDPASSAGEHALO_ERR_API_UNSUPPORTED_METHOD = "Unsupported method {method}"
CLOUDPASSAGEHALO_EXCEPTION_OCCURRED = "Exception occurred"
CLOUDPASSAGEHALO_ERR_SERVER_CONNECTION = "Connection failed"
CLOUDPASSAGEHALO_ERR_JSON_PARSE = "Unable to parse the response into a dictionary.\nResponse text - {raw_text}"
CLOUDPASSAGEHALO_ERR_FROM_SERVER = "API failed\nStatus code: {status}\nDetail: {detail}"
CLOUDPASSAGEHALO_TEST_CONNECTIVITY_MSG = "Logging to device"
CLOUDPASSAGEHALO_TEST_CONN_FAIL = "Connectivity test failed"
CLOUDPASSAGEHALO_TEST_CONN_SUCC = "Connectivity test succeeded"
CLOUDPASSAGEHALO_AUTH = "/oauth/access_token"
CLOUDPASSAGEHALO_TOKEN_ERR = "Failed to generate token"
CLOUDPASSAGEHALO_MISSING_PARAMETER = "Required parameter(AWS Instance ID/IP/Hostname) failed validation"
CLOUDPASSAGEHALO_SERVERS_ENDPOINT = "/v1/servers"
CLOUDPASSAGEHALO_SERVER_ID_ENDPOINT = "/v1/servers/{server_id}"
CLOUDPASSAGEHALO_JSON_AWS_INSTANCE_ID = "aws_instance_id"
CLOUDPASSAGEHALO_JSON_IP = "ip"
CLOUDPASSAGEHALO_JSON_HOSTNAME = "hostname"
CLOUDPASSAGEHALO_JSON_PACKAGE_NAME = "package_name"
CLOUDPASSAGEHALO_JSON_CVE_NUMBER = "cve_number"
CLOUDPASSAGEHALO_JSON_USERNAME = "username"
CLOUDPASSAGEHALO_JSON_PROCESS_NAME = "process_name"
CLOUDPASSAGEHALO_SVM_ENDPOINT = "/v1/servers/{server_id}/svm"
CLOUDPASSAGEHALO_PROCESSES_ENDPOINT = "/v1/servers/{server_id}/processes"
CLOUDPASSAGEHALO_LOCAL_ACCOUNTS_ENDPOINT = "/v1/local_accounts"
CLOUDPASSAGEHALO_USER_ENDPOINT = "/v1/servers/{server_id}/accounts/{username}"
CLOUDPASSAGEHALO_UNEXPECTED_RESPONSE = "Expected response not found"
CLOUDPASSAGEHALO_INVALID_SERVER = "Server not found"
CLOUDPASSAGEHALO_INVALID_PACKAGE = "Package not found"
CLOUDPASSAGEHALO_INVALID_PACKAGE_FOR_ALL_SERVER = "No Server found with the given package '{package_name}'"
CLOUDPASSAGEHALO_INVALID_PROCESS = "Process not found"
CLOUDPASSAGEHALO_INVALID_PROCESS_FOR_ALL_SERVER = "No Server found with the given process '{process_name}'"
CLOUDPASSAGEHALO_INVALID_VULNERABILITY = "Vulnerability not found"
CLOUDPASSAGEHALO_INVALID_VULNERABILITY_FOR_ALL_SERVER = "No Server found with the given CVE number '{cve_number}'"
CLOUDPASSAGEHALO_INVALID_USERNAME_FOR_ALL_SERVER = "No Server found with the given username '{username}'"
