# --
# File: cloudpassagehalo/cloudpassagehalo_connector.py
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

# Standard library imports
import json
import base64
import urllib
import requests

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Local imports
import cloudpassagehalo_consts as consts

# Dictionary that maps each error code with its corresponding message
ERROR_RESPONSE_DICT = {
    consts.CLOUDPASSAGEHALO_REST_RESP_UNAUTHORIZED: consts.CLOUDPASSAGEHALO_REST_RESP_UNAUTHORIZED_MSG,
    consts.CLOUDPASSAGEHALO_REST_RESP_BAD_REQUEST: consts.CLOUDPASSAGEHALO_REST_RESP_BAD_REQUEST_MSG,
    consts.CLOUDPASSAGEHALO_REST_RESP_FORBIDDEN: consts.CLOUDPASSAGEHALO_REST_RESP_FORBIDDEN_MSG,
    consts.CLOUDPASSAGEHALO_REST_RESP_NOT_FOUND: consts.CLOUDPASSAGEHALO_REST_RESP_NOT_FOUND_MSG,
    consts.CLOUDPASSAGEHALO_REST_RESP_INTERNAL_SERVER_ERROR: consts.CLOUDPASSAGEHALO_REST_RESP_INTERNAL_SERVER_ERROR_MSG
}


class CloudpassagehaloConnector(BaseConnector):

    def __init__(self):

        # Calling the BaseConnector's init function
        super(CloudpassagehaloConnector, self).__init__()

        self._client_id = None
        self._client_secret = None
        self._url = None
        self._header = None
        self._access_token = None

        return

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        config = self.get_config()
        self._url = config[consts.CLOUDPASSAGEHALO_CONFIG_URL]
        self._client_id = config[consts.CLOUDPASSAGEHALO_CONFIG_CLIENT_ID]
        self._client_secret = config[consts.CLOUDPASSAGEHALO_CONFIG_CLIENT_SECRET]
        self._header = {"Authorization": "Basic {}".format(
            base64.b64encode("{}:{}".format(self._client_id, self._client_secret)))}

        return phantom.APP_SUCCESS

    def _make_rest_call(self, endpoint, action_result, params=None, timeout=None, method="get"):
        """ Function that makes the REST call to the device. It's a generic function that can be called from various
        action handlers.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param params: request parameters if method is get
        :param method: get/post/put/delete ( Default method will be 'get' )
        :param timeout: timeout for request
        :return: status success/failure(along with appropriate message), response obtained by making an API call
        """

        response_data = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            self.debug_print(consts.CLOUDPASSAGEHALO_ERR_API_UNSUPPORTED_METHOD.format(method=method))
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.CLOUDPASSAGEHALO_ERR_API_UNSUPPORTED_METHOD),\
                response_data
        except Exception as e:
            self.debug_print(consts.CLOUDPASSAGEHALO_EXCEPTION_OCCURRED, e)
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.CLOUDPASSAGEHALO_EXCEPTION_OCCURRED),\
                response_data

        try:
            response = request_func("{}{}".format(self._url, endpoint), params=params, headers=self._header,
                                    timeout=timeout, verify=False)

            # store the r_text in debug data, it will get dumped in the logs if an error occurs
            if hasattr(action_result, 'add_debug_data'):
                if response is not None:
                    action_result.add_debug_data({'r_status_code': response.status_code})
                    action_result.add_debug_data({'r_text': response.text})
                    action_result.add_debug_data({'r_headers': response.headers})
                else:
                    action_result.add_debug_data({'r_text': 'r is None'})
        except Exception as e:
            self.debug_print(consts.CLOUDPASSAGEHALO_ERR_SERVER_CONNECTION, e)
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.CLOUDPASSAGEHALO_ERR_SERVER_CONNECTION, e),\
                response_data

        # Try parsing the json
        try:
            content_type = response.headers.get('content-type')
            if content_type and content_type.find('json') != -1:
                response_data = response.json()
            else:
                response_data = response.text

        except Exception as e:
            # r.text is guaranteed to be NON None, it will be empty, but not None
            msg_string = consts.CLOUDPASSAGEHALO_ERR_JSON_PARSE.format(raw_text=response.text)
            self.debug_print(msg_string, e)
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, msg_string, e), response_data

        if response.status_code in ERROR_RESPONSE_DICT:
            message = ERROR_RESPONSE_DICT[response.status_code]

            self.debug_print(consts.CLOUDPASSAGEHALO_ERR_FROM_SERVER.format(status=response.status_code,
                                                                            detail=message))
            # set the action_result status to error, the handler function will most probably return as is
            return action_result.set_status(phantom.APP_ERROR, consts.CLOUDPASSAGEHALO_ERR_FROM_SERVER,
                                            status=response.status_code, detail=message), response_data

        # In case of success scenario
        if response.status_code == consts.CLOUDPASSAGEHALO_REST_RESP_SUCCESS:
            # If response obtained is not in json format
            if not isinstance(response_data, dict):
                self.debug_print(consts.CLOUDPASSAGEHALO_UNEXPECTED_RESPONSE)
                return action_result.set_status(phantom.APP_ERROR, consts.CLOUDPASSAGEHALO_UNEXPECTED_RESPONSE), \
                    response_data
            return phantom.APP_SUCCESS, response_data

        # If response code is unknown
        message = consts.CLOUDPASSAGEHALO_REST_RESP_OTHER_ERROR_MSG

        if isinstance(response_data, dict):
            message = response_data.get("error", message)

        self.debug_print(consts.CLOUDPASSAGEHALO_ERR_FROM_SERVER.format(status=response.status_code, detail=message))

        # All other response codes from REST call
        # Set the action_result status to error, the handler function will most probably return as is
        return action_result.set_status(phantom.APP_ERROR, consts.CLOUDPASSAGEHALO_ERR_FROM_SERVER,
                                        status=response.status_code,
                                        detail=message), response_data

    def _test_asset_connectivity(self, param):
        """ This function tests the connectivity of an asset with given credentials.

        :param param: ( not used in this method )
        :return: status success/failure
        """

        action_result = ActionResult()
        self.save_progress(consts.CLOUDPASSAGEHALO_TEST_CONNECTIVITY_MSG)
        self.save_progress("Configured URL: {url}".format(url=self._url))

        # Querying endpoint to generate access token
        generate_token_status = self._generate_api_token(action_result, timeout=30)

        # Something went wrong
        if phantom.is_fail(generate_token_status):
            self.save_progress(action_result.get_message())
            self.set_status(phantom.APP_ERROR, consts.CLOUDPASSAGEHALO_TEST_CONN_FAIL)
            return action_result.get_status()

        self.set_status_save_progress(phantom.APP_SUCCESS, consts.CLOUDPASSAGEHALO_TEST_CONN_SUCC)
        return action_result.get_status()

    def _generate_api_token(self, action_result, timeout=None):
        """ This function is used to generate token. Token expire time = 15 min.

        :param action_result: object of ActionResult class
        :param timeout: timeout for request
        :return: status success/failure
        """

        params = urllib.urlencode({'grant_type': 'client_credentials'})

        # Querying endpoint to generate token
        generate_token_status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_AUTH, action_result,
                                                               method="post", params=params, timeout=timeout)

        # Something went wrong
        if phantom.is_fail(generate_token_status):
            return action_result.get_status()

        # Get access token
        self._access_token = response.get("access_token")

        # Validate access token
        if not self._access_token:
            self.debug_print(consts.CLOUDPASSAGEHALO_TOKEN_ERR)
            return action_result.set_status(phantom.APP_ERROR, consts.CLOUDPASSAGEHALO_TOKEN_ERR)

        # Update authorization header with access token
        self._header = {"Authorization": "Bearer {}".format(self._access_token)}

        return phantom.APP_SUCCESS

    def _get_server(self, param, action_result):
        """ This function is used to get server id based on input parameter(AWS Instance ID/IP/Hostname).

        :param param: dictionary which contains information about parameters
        :param action_result: object of ActionResult class
        :return: status and server_id: success/failure and server id
        """

        params = None
        # Get optional parameters
        aws_instance_id = param.get(consts.CLOUDPASSAGEHALO_JSON_AWS_INSTANCE_ID)
        ip = param.get(consts.CLOUDPASSAGEHALO_JSON_IP)
        hostname = param.get(consts.CLOUDPASSAGEHALO_JSON_HOSTNAME)

        # (AWS Instance ID/IP/Hostname) One of three parameter is mandatory
        if not (aws_instance_id or ip or hostname):
            self.debug_print(consts.CLOUDPASSAGEHALO_MISSING_PARAMETER)
            return action_result.set_status(phantom.APP_ERROR, consts.CLOUDPASSAGEHALO_MISSING_PARAMETER), None

        # Update params as per input parameters i.e (AWS Instance ID/Hostname)
        if aws_instance_id:
            params = {"ec2_instance_id": aws_instance_id}
        elif hostname:
            params = {"hostname": hostname}

        # Querying endpoint to get server information
        status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_SERVERS_ENDPOINT, action_result, params=params)

        # Something went wrong
        if phantom.is_fail(status):
            return action_result.get_status(), None

        # Get server ID according to parameter(AWS instance ID/IP/Hostname) provided
        filtered_list = response.get("servers")
        if filtered_list:
            if hostname:
                filtered_list = [server for server in filtered_list if server['hostname'] == hostname]
            if filtered_list and ip:
                filtered_list = [server for server in filtered_list if server['primary_ip_address'] == ip]

        if not filtered_list:
            return action_result.set_status(phantom.APP_ERROR, consts.CLOUDPASSAGEHALO_INVALID_SERVER), None

        return phantom.APP_SUCCESS, filtered_list[0]

    def _get_server_information(self, param):
        """ This function is used to get server information.

        :param param: dictionary which contains information about parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Querying endpoint to generate access token
        generate_token_status = self._generate_api_token(action_result)

        # Something went wrong
        if phantom.is_fail(generate_token_status):
            return action_result.get_status()

        status, server_details = self._get_server(param, action_result)

        # Something went wrong
        if phantom.is_fail(status):
            return action_result.get_status()

        # Querying endpoint to get server information
        status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_SERVER_ID_ENDPOINT.format(
            server_id=server_details["id"]), action_result)

        # Something went wrong
        if phantom.is_fail(status):
            return action_result.get_status()

        action_result.add_data(response["server"])
        summary_data["reported_fqdn"] = response["server"]["reported_fqdn"]
        summary_data["primary_ip_address"] = response["server"]["primary_ip_address"]
        summary_data["hostname"] = response["server"]["hostname"]

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_server_for_package(self, param):
        """ This function is used to get package information for specific server.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Querying endpoint to generate access token
        generate_token_status = self._generate_api_token(action_result)

        # Something went wrong while generating token
        if phantom.is_fail(generate_token_status):
            return action_result.get_status()

        # Get server ID using the given input parameters
        server_id_res_status, server_details = self._get_server(param, action_result)

        # Something went wrong while fetching server ID
        if phantom.is_fail(server_id_res_status):
            return action_result.get_status()

        # Querying endpoint to get package information
        status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_SVM_ENDPOINT.format(
            server_id=server_details["id"]), action_result)

        # Something went wrong while getting package information
        if phantom.is_fail(status):
            return action_result.get_status()

        # Get mandatory parameters
        package_name = param[consts.CLOUDPASSAGEHALO_JSON_PACKAGE_NAME]

        package_found = False

        # Filter response to obtain list of findings that match the package name provided
        if response.get("scan") and response['scan']["findings"]:
            for finding in response["scan"]["findings"]:
                if finding["package_name"].lower() == package_name.lower():
                    # Add filtered data for available package
                    action_result.add_data(finding)
                    package_found = True

        # If package is not available
        if not package_found:
            self.debug_print(consts.CLOUDPASSAGEHALO_INVALID_PACKAGE)
            return action_result.set_status(phantom.APP_ERROR, consts.CLOUDPASSAGEHALO_INVALID_PACKAGE)

        # Update summary
        summary_data["package_availability"] = package_found
        summary_data["reported_fqdn"] = server_details["reported_fqdn"]
        summary_data["primary_ip_address"] = server_details["primary_ip_address"]
        summary_data["hostname"] = server_details["hostname"]

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_server_for_all_packages(self, param):
        """ This function is used to get all package information for specific server.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Querying endpoint to generate access token
        generate_token_status = self._generate_api_token(action_result)

        # Something went wrong while generating token
        if phantom.is_fail(generate_token_status):
            return action_result.get_status()

        # Get server ID using the given input parameters
        server_id_res_status, server_details = self._get_server(param, action_result)

        # Something went wrong while fetching server ID
        if phantom.is_fail(server_id_res_status):
            return action_result.get_status()

        # Querying endpoint to get package information
        status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_SVM_ENDPOINT.format(
            server_id=server_details["id"]), action_result)

        # Something went wrong while getting package information
        if phantom.is_fail(status):
            return action_result.get_status()

        # Updating summary
        summary_data["total_packages"] = len(response["scan"]["findings"])
        summary_data["reported_fqdn"] = server_details["reported_fqdn"]
        summary_data["primary_ip_address"] = server_details["primary_ip_address"]
        summary_data["hostname"] = server_details["hostname"]

        # Filter response to obtain list of findings that match the package name provided
        if response.get("scan") and response['scan']["findings"]:
            for finding in response["scan"]["findings"]:
                # Add filtered data for available package
                action_result.add_data(finding)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_all_servers_for_package(self, param):
        """ This function is used to get all servers information for specific package.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Querying endpoint to generate access token
        generate_token_status = self._generate_api_token(action_result)

        # Something went wrong while generating token
        if phantom.is_fail(generate_token_status):
            return action_result.get_status()

        # Get mandatory parameter
        package_name = param[consts.CLOUDPASSAGEHALO_JSON_PACKAGE_NAME]

        params = {"package_name": package_name}

        # Querying endpoint to get package information
        status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_SERVERS_ENDPOINT, action_result, params=params)

        # Something went wrong while getting server information
        if phantom.is_fail(status):
            return action_result.get_status()

        total_servers = len(response.get("servers", []))

        # Fail action for invalid package name
        if not total_servers:
            self.debug_print(consts.CLOUDPASSAGEHALO_INVALID_PACKAGE_FOR_ALL_SERVER.format(package_name=package_name))
            return action_result.set_status(
                phantom.APP_ERROR,
                consts.CLOUDPASSAGEHALO_INVALID_PACKAGE_FOR_ALL_SERVER.format(package_name=package_name))

        for server in response.get("servers", []):
            # Querying endpoint to get server information
            server_status, server_response = self._make_rest_call(consts.CLOUDPASSAGEHALO_SERVER_ID_ENDPOINT.format(
                server_id=server["id"]), action_result)

            # Something went wrong
            if phantom.is_fail(server_status):
                return action_result.get_status()

            if server_response.get("server"):
                action_result.add_data(server_response["server"])

        # Update summary
        summary_data["total_servers"] = total_servers

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_server_for_process(self, param):
        """ Function that returns information detected by specific process on the server.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Querying endpoint to generate access token
        generate_token_status = self._generate_api_token(action_result)

        # Something went wrong
        if phantom.is_fail(generate_token_status):
            return action_result.get_status()

        # Get server ID using the given input parameters
        server_id_res_status, server_details = self._get_server(param, action_result)

        # Something went wrong while fetching server ID
        if phantom.is_fail(server_id_res_status):
            return action_result.get_status()

        # Getting mandatory parameter
        process_name = param[consts.CLOUDPASSAGEHALO_JSON_PROCESS_NAME]

        # Querying endpoint to get server information
        status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_PROCESSES_ENDPOINT.format(
            server_id=server_details["id"]), action_result)

        # Something went wrong
        if phantom.is_fail(status):
            return action_result.get_status()

        process_found = 0

        # Checking given process from all processes
        for process in response["processes"]:
            if process["process_name"].lower() == process_name.lower():
                action_result.add_data(process)
                process_found += 1

        if not process_found:
            self.debug_print(consts.CLOUDPASSAGEHALO_INVALID_PROCESS)
            return action_result.set_status(phantom.APP_ERROR, consts.CLOUDPASSAGEHALO_INVALID_PROCESS)

        # Setting summary to count processes
        summary_data["total_processes"] = process_found
        summary_data["reported_fqdn"] = server_details["reported_fqdn"]
        summary_data["primary_ip_address"] = server_details["primary_ip_address"]
        summary_data["hostname"] = server_details["hostname"]
        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_server_for_all_processes(self, param):
        """ Function that returns information for all running processes on the server specified by server ID.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Querying endpoint to generate access token
        generate_token_status = self._generate_api_token(action_result)

        # Something went wrong
        if phantom.is_fail(generate_token_status):
            return action_result.get_status()

        # Get server ID using the given input parameters
        server_id_res_status, server_details = self._get_server(param, action_result)

        # Something went wrong while fetching server ID
        if phantom.is_fail(server_id_res_status):
            return action_result.get_status()

        # Querying endpoint to get process information
        status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_PROCESSES_ENDPOINT.format(
            server_id=server_details["id"]), action_result)

        # Something went wrong
        if phantom.is_fail(status):
            return action_result.get_status()

        # Adding data to action_result
        for process in response["processes"]:
            action_result.add_data(process)

        # Setting summary to track processes
        summary_data["total_processes"] = len(response["processes"])
        summary_data["reported_fqdn"] = server_details["reported_fqdn"]
        summary_data["primary_ip_address"] = server_details["primary_ip_address"]
        summary_data["hostname"] = server_details["hostname"]

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_all_servers_for_process(self, param):
        """ Get all server details on which specified process is running.

       :param param: dictionary of input parameters
       :return: status success/failure
       """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Generate token
        token_generation_status = self._generate_api_token(action_result)

        # Something went wrong while generating token
        if phantom.is_fail(token_generation_status):
            return action_result.get_status()

        # Get mandatory parameter
        process_name = param[consts.CLOUDPASSAGEHALO_JSON_PROCESS_NAME]

        # Make REST call
        resp_status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_SERVERS_ENDPOINT, action_result)

        # Something went wrong
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        total_servers = 0

        for server in response.get("servers", []):
            # Make REST call
            process_status, process_response = self._make_rest_call(
                consts.CLOUDPASSAGEHALO_PROCESSES_ENDPOINT.format(server_id=server["id"]), action_result)

            # Something went wrong
            if phantom.is_fail(process_status):
                return action_result.get_status()

            if process_response.get("processes"):
                for process in process_response.get("processes"):
                    if process_name.lower() == process["process_name"].lower():
                        # Querying endpoint to get server information
                        server_status, server_response = self._make_rest_call(
                            consts.CLOUDPASSAGEHALO_SERVER_ID_ENDPOINT.format(server_id=server["id"]),
                            action_result)

                        # Something went wrong
                        if phantom.is_fail(server_status):
                            return action_result.get_status()

                        if server_response.get("server"):
                            total_servers += 1
                            action_result.add_data(server_response["server"])
                        break

        # Fail action in case of invalid process name
        if not total_servers:
            self.debug_print(consts.CLOUDPASSAGEHALO_INVALID_PROCESS_FOR_ALL_SERVER.format(process_name=process_name))
            return action_result.set_status(
                phantom.APP_ERROR,
                consts.CLOUDPASSAGEHALO_INVALID_PROCESS_FOR_ALL_SERVER.format(process_name=process_name))

        # Update summary
        summary_data["total_servers"] = total_servers

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_server_for_vulnerability(self, param):
        """ For the server specified in the call URL, return recent vulnerability scan result corresponding to the
        specified cve number on that server.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Get mandatory parameters
        cve_number = param[consts.CLOUDPASSAGEHALO_JSON_CVE_NUMBER]

        # Generate token
        token_generation_status = self._generate_api_token(action_result)

        # Something went wrong while generating token
        if phantom.is_fail(token_generation_status):
            return action_result.get_status()

        # Get server ID using the given input parameters
        server_id_res_status, server_details = self._get_server(param, action_result)

        # Something went wrong while fetching server ID
        if phantom.is_fail(server_id_res_status):
            return action_result.get_status()

        # Make REST call
        resp_status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_SVM_ENDPOINT.format(
            server_id=server_details["id"]), action_result)

        # Something went wrong while getting scanned data
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        # Filter response to obtain list of findings that match the cve number provided
        updated_findings_list = list()
        critical_findings_count = 0
        non_critical_findings_count = 0
        ok_findings_count = 0
        for finding in response["scan"].get("findings", []):
            cve_entries = finding.get("cve_entries")
            if cve_entries is not None:
                filtered_list = filter(lambda x: x['cve_entry'] == cve_number, cve_entries)
                if filtered_list:
                    finding["cve_entries"] = filtered_list
                    if finding["status"] == "bad":
                        if finding["critical"]:
                            critical_findings_count += 1
                        else:
                            non_critical_findings_count += 1
                    elif finding["status"] == "good":
                        ok_findings_count += 1
                    updated_findings_list.append(finding)

            # Overriding response so as to include only the filtered data
            response["scan"]["findings"] = updated_findings_list

        # Fail action in case of invalid cve number
        if not response["scan"]["findings"]:
            self.debug_print(consts.CLOUDPASSAGEHALO_INVALID_VULNERABILITY.format(cve_number=cve_number))
            return action_result.set_status(
                phantom.APP_ERROR,
                consts.CLOUDPASSAGEHALO_INVALID_VULNERABILITY.format(cve_number=cve_number))

        response["scan"]["critical_findings_count"] = critical_findings_count
        response["scan"]["ok_findings_count"] = ok_findings_count
        response["scan"]["non_critical_findings_count"] = non_critical_findings_count

        # Updating summary
        summary_data["critical_findings_count"] = critical_findings_count
        summary_data["non_critical_findings_count"] = non_critical_findings_count
        summary_data["ok_findings_count"] = ok_findings_count
        summary_data["reported_fqdn"] = server_details["reported_fqdn"]
        summary_data["primary_ip_address"] = server_details["primary_ip_address"]
        summary_data["hostname"] = server_details["hostname"]

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_server_for_all_vulnerabilities(self, param):
        """ For the server specified in the call URL, returns all results detected by the most recent vulnerability
        scan on that server. For each vulnerable package, all of its known vulnerabilities (CVE's) are listed as well.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Generate token
        token_generation_status = self._generate_api_token(action_result)

        # Something went wrong while generating token
        if phantom.is_fail(token_generation_status):
            return action_result.get_status()

        # Get server ID using the given input parameters
        server_id_res_status, server_details = self._get_server(param, action_result)

        # Something went wrong while fetching server ID
        if phantom.is_fail(server_id_res_status):
            return action_result.get_status()

        # Make REST call
        resp_status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_SVM_ENDPOINT.format(
            server_id=server_details["id"]), action_result)

        # Something went wrong
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        summary_data["critical_findings_count"] = response["scan"]["critical_findings_count"]
        summary_data["non_critical_findings_count"] = response["scan"]["non_critical_findings_count"]
        summary_data["ok_findings_count"] = response["scan"]["ok_findings_count"]
        summary_data["reported_fqdn"] = server_details["reported_fqdn"]
        summary_data["primary_ip_address"] = server_details["primary_ip_address"]
        summary_data["hostname"] = server_details["hostname"]

        action_result.add_data(response)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_all_servers_for_vulnerability(self, param):
        """ Obtain all servers that have a package containing the specified CVE (Common Vulnerability and Exposure
        number).

       :param param: dictionary of input parameters
       :return: status success/failure
       """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Get mandatory parameters
        cve_number = param[consts.CLOUDPASSAGEHALO_JSON_CVE_NUMBER]

        # Generate token
        token_generation_status = self._generate_api_token(action_result)

        # Something went wrong while generating token
        if phantom.is_fail(token_generation_status):
            return action_result.get_status()

        # Prepare request params
        params = {"cve": cve_number}

        # Make REST call
        resp_status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_SERVERS_ENDPOINT, action_result,
                                                     params=params)

        # Something went wrong
        if phantom.is_fail(resp_status):
            return action_result.get_status()

        # Fail action in case of invalid cve number
        if not response["count"]:
            self.debug_print(consts.CLOUDPASSAGEHALO_INVALID_VULNERABILITY_FOR_ALL_SERVER.format(cve_number=cve_number))
            return action_result.set_status(
                phantom.APP_ERROR,
                consts.CLOUDPASSAGEHALO_INVALID_VULNERABILITY_FOR_ALL_SERVER.format(cve_number=cve_number))

        summary_data["total_servers"] = response["count"]

        for server in response.get("servers", []):
            # Querying endpoint to get server information
            server_status, server_response = self._make_rest_call(
                consts.CLOUDPASSAGEHALO_SERVER_ID_ENDPOINT.format(server_id=server["id"]), action_result)

            # Something went wrong
            if phantom.is_fail(server_status):
                return action_result.get_status()

            action_result.add_data(server_response["server"])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_server_for_user(self, param):
        """ Returns user information for server.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Querying endpoint to generate access token
        generate_token_status = self._generate_api_token(action_result)

        # Something went wrong
        if phantom.is_fail(generate_token_status):
            return action_result.get_status()

        # Get server ID using the given input parameters
        server_id_res_status, server_details = self._get_server(param, action_result)

        # Something went wrong while fetching server ID
        if phantom.is_fail(server_id_res_status):
            return action_result.get_status()

        # Getting mandatory parameter
        username = param[consts.CLOUDPASSAGEHALO_JSON_USERNAME]

        # Querying endpoint to get server information
        status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_USER_ENDPOINT.format(
            server_id=server_details["id"], username=username), action_result)

        # Something went wrong
        if phantom.is_fail(status):
            return action_result.get_status()

        # Adding data to action_result
        action_result.add_data(response)

        # Setting summary to count processes
        summary_data["user_availability"] = True
        summary_data["reported_fqdn"] = server_details["reported_fqdn"]
        summary_data["primary_ip_address"] = server_details["primary_ip_address"]
        summary_data["hostname"] = server_details["hostname"]
        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_server_for_all_users(self, param):
        """ Function that returns all users' information for server.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Querying endpoint to generate access token
        generate_token_status = self._generate_api_token(action_result)

        # Something went wrong
        if phantom.is_fail(generate_token_status):
            return action_result.get_status()

        # Get server ID using the given input parameters
        server_id_res_status, server_details = self._get_server(param, action_result)

        # Something went wrong while fetching server ID
        if phantom.is_fail(server_id_res_status):
            return action_result.get_status()

        params = {"server_id": server_details["id"]}

        # Querying endpoint to get process information
        status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_LOCAL_ACCOUNTS_ENDPOINT, action_result,
                                                params=params)

        # Something went wrong
        if phantom.is_fail(status):
            return action_result.get_status()

        # Adding data to action_result
        for users in response["accounts"]:
            action_result.add_data(users)

        # Setting summary to track all users
        summary_data["total_users"] = response["count"]
        summary_data["reported_fqdn"] = server_details["reported_fqdn"]
        summary_data["primary_ip_address"] = server_details["primary_ip_address"]
        summary_data["hostname"] = server_details["hostname"]

        return action_result.set_status(phantom.APP_SUCCESS)

    def _check_all_servers_for_user(self, param):
        """ This function is used to get all servers information for specific user.

        :param param: dictionary of input parameters
        :return: status success/failure
        """

        action_result = self.add_action_result(ActionResult(dict(param)))
        summary_data = action_result.update_summary({})

        # Querying endpoint to generate access token
        generate_token_status = self._generate_api_token(action_result)

        # Something went wrong while generating token
        if phantom.is_fail(generate_token_status):
            return action_result.get_status()

        # Get required parameter
        username = param[consts.CLOUDPASSAGEHALO_JSON_USERNAME]

        params = {"username": username}

        # Querying endpoint to get accounts information
        status, response = self._make_rest_call(consts.CLOUDPASSAGEHALO_LOCAL_ACCOUNTS_ENDPOINT, action_result,
                                                params=params)

        # Something went wrong while getting server information
        if phantom.is_fail(status):
            return action_result.get_status()

        total_servers = len(response.get("accounts", []))

        # Fail action in case of invalid username
        if not total_servers:
            self.debug_print(consts.CLOUDPASSAGEHALO_INVALID_USERNAME_FOR_ALL_SERVER.format(username=username))
            return action_result.set_status(
                phantom.APP_ERROR, consts.CLOUDPASSAGEHALO_INVALID_USERNAME_FOR_ALL_SERVER.format(username=username))

        for account in response.get("accounts", []):
            # Querying endpoint to get server information
            server_status, server_response = self._make_rest_call(consts.CLOUDPASSAGEHALO_SERVER_ID_ENDPOINT.format(
                server_id=account["server_id"]), action_result)

            # Something went wrong
            if phantom.is_fail(server_status):
                return action_result.get_status()

            merged_details = account
            merged_details.update(server_response.get("server"))
            action_result.add_data(merged_details)

        # Update summary
        summary_data["total_servers"] = total_servers

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of it's own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {'check_all_servers_for_process': self._check_all_servers_for_process,
                          'check_server_for_all_packages': self._check_server_for_all_packages,
                          'check_server_for_process': self._check_server_for_process,
                          'check_server_for_package': self._check_server_for_package,
                          'check_server_for_all_processes': self._check_server_for_all_processes,
                          'get_server_information': self._get_server_information,
                          'check_all_servers_for_package': self._check_all_servers_for_package,
                          'check_server_for_all_vulnerabilities': self._check_server_for_all_vulnerabilities,
                          'check_server_for_vulnerability': self._check_server_for_vulnerability,
                          'check_all_servers_for_vulnerability': self._check_all_servers_for_vulnerability,
                          'check_server_for_user': self._check_server_for_user,
                          'check_all_servers_for_user': self._check_all_servers_for_user,
                          'check_server_for_all_users': self._check_server_for_all_users,
                          'test_asset_connectivity': self._test_asset_connectivity}

        action = self.get_action_identifier()

        try:
            run_action = action_mapping[action]
        except:
            raise ValueError("action {action} is not supported".format(action=action))

        return run_action(param)


if __name__ == '__main__':

    import sys
    import pudb

    pudb.set_trace()
    if len(sys.argv) < 2:
        print 'No test json specified as input'
        exit(0)
    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print json.dumps(in_json, indent=4)
        connector = CloudpassagehaloConnector()
        connector.print_progress_message = True
        return_value = connector._handle_action(json.dumps(in_json), None)
        print json.dumps(json.loads(return_value), indent=4)
    exit(0)
