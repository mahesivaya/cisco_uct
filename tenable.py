from time import sleep
import requests
import json
from datetime import datetime
from symphony import config, DATA_DIR, LOG
from tenable.io import TenableIO
from tenable.errors import TioExportsError
import symphony.scanner_plugins.tenable_finding_json_convert as json_convert

conf = config.read_config()
TENABLE_BASEURL = conf['Tenable']['tenable_api_url']
SCAN_FOLDER_ID = int(conf['Tenable']['SCAN_FOLDER_ID'])
RETRY_TENABLE_APICALL_COUNT = int(conf['Symphony']['RETRY_TENABLE_APICALL_COUNT'])
RETRY_TENABLE_APICALL_SLEEP_SECS = int(conf['Symphony']['RETRY_TENABLE_APICALL_SLEEP_SECS'])
ApplicationName = conf['Tenable']['TAG_ApplicationName']
ProductFamily = conf['Tenable']['TAG_ProductFamily']
SubBusinessCategory = conf['Tenable']['TAG_SubBusinessCategory']
BusinessUnit = conf['Tenable']['TAG_BusinessUnit']
BusinessDomain = conf['Tenable']['TAG_BusinessDomain']


class GroupExist(Exception):
    def __init__(self, msg):
        super().__init__(msg)


class WaitAndRetry(Exception):
    def __init__(self, msg):
        super().__init__(msg)


class TenablePlugin:

    def __init__(self, accesskey, secretkey):
        self.accesskey = accesskey
        self.secretkey = secretkey
        self.tio = TenableIO(self.accesskey, self.secretkey, url=TENABLE_BASEURL)

    # fetch all scan template from tenable
    def fetch_scan_templates(self):

        print(datetime.now().strftime("%H:%M:%S"),
              ": Fetch all profile records from Tenable - STARTED")
        resp = requests.get(f"{TENABLE_BASEURL}/editor/scan/templates",
                            headers={"Accept": "application/json",
                                     "X-ApiKeys": "accessKey={};secretKey={}".format(
                                         self.accesskey, self.secretkey)})

        if resp.status_code not in (200, 201):
            raise Exception("Error getting tenable scan template list. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

        # store to a file and fetch from it
        with open(f"{DATA_DIR}/all_scan_profile_list.json", "w+") as f:
            f.write(resp.text)
        file_content = open(
            f"{DATA_DIR}/all_scan_profile_list.json", "r")

        # get PROFILE list
        json_content = file_content.read()
        dict_content = json.loads(json_content)
        profiles_list = dict_content["templates"]

        # Navigate through each OPTION_PROFILE's BASIC_INFO and get corresponding ID and GROUP_NAME
        profile_dict = {}
        profile_list_of_dict = []
        for item in profiles_list:
            profile_dict = {"profileid": item["uuid"], "name": item["title"]}
            profile_list_of_dict.append(profile_dict)

        print(datetime.now().strftime("%H:%M:%S"),
              ": Fetch all profile records from Tenable - DONE")
        return profile_list_of_dict

    # fetch all scan template from tenable
    def fetch_user_defined_templates(self):

        print(datetime.now().strftime("%H:%M:%S"),
              ": Fetch all profile records from Tenable - STARTED")
        resp = requests.get(f"{TENABLE_BASEURL}/policies",
                            headers={"Accept": "application/json",
                                     "X-ApiKeys": "accessKey={};secretKey={}".format(
                                         self.accesskey, self.secretkey)})

        if resp.status_code not in (200, 201):
            raise Exception("Error getting tenable scan user defined template list. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        profiles_list = json_data["policies"]

        # Navigate through each profile and get corresponding Template_UUID and Name
        profile_dict = {}
        profile_list_of_dict = []
        for item in profiles_list:
            profile_dict = {"profileid": str(item["id"]), "name": item["name"], "template_uuid": item["template_uuid"]}
            profile_list_of_dict.append(profile_dict)

        print(datetime.now().strftime("%H:%M:%S"),
              ": Fetch all user defined profile records from Tenable - DONE")
        return profile_list_of_dict

    # For given group_name and external IP List, returns id of newly created target group of type user
    def create_asset_group(self, group_name, ip_list):
        print(datetime.now().strftime("%H:%M:%S"),
              ": Create assert group - STARTED")

        url = f"{TENABLE_BASEURL}/target-groups"
        payload = {"acls": [{"type": "default"}],
                   "name": group_name,
                   "members": ",".join(ip_list)}
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("POST", url, json=payload, headers=headers)

        if resp.status_code == 400:
            json_error = json.loads(resp.text)["error"]
            LOG.info("Target Group with name {} already exists".format(group_name))
            if(json_error == "Target Group with the given name already exists"):
                raise GroupExist(Exception)
        elif resp.status_code not in (200, 201):
            raise Exception("Error in creating group {}. "
                            "Status code: {},  Message: {}".format(
                                group_name, resp.status_code, resp.text))

        print(datetime.now().strftime("%H:%M:%S"),
              ": Create assert group - DONE")

        json_data = json.loads(resp.text)
        return json_data["id"]

    def fetch_asset_group(self, group_name):
        url = f"{TENABLE_BASEURL}/target-groups"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("GET", url, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in Updating group {}. "
                            "Status code: {},  Message: {}".format(
                                group_name, resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        list_data = json_data["target_groups"]
        filtered_data = [i for i in list_data if i["name"] == group_name]
        return filtered_data[0]

    def update_asset_group(self, id, group_name, ip_list):
        url = f"{TENABLE_BASEURL}/target-groups/{id}"
        payload = {"acls": [{"type": "default"}],
                   "name": group_name,
                   "members": ",".join(ip_list)}
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("PUT", url, json=payload, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in Updating group {}. "
                            "Status code: {},  Message: {}".format(
                                group_name, resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        return json_data["id"]

    # For given scan_name, target_group_id, scanner_id, profile_id returns uuid of newly created scan template
    def create_scan_for_target_group(self, target_group_id, scan_name, scanner_id, profile_id):
        print(datetime.now().strftime("%H:%M:%S"),
              ": Create scan for target grp  - STARTED")

        url = f"{TENABLE_BASEURL}/scans"
        payload = {
            "settings": {
                "target_groups": [target_group_id],
                "name": scan_name,
                "scanner_id": scanner_id,
                "enabled": False
            },
            "uuid": profile_id
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("POST", url, json=payload, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in creating scan configuration {}. "
                            "Status code: {},  Message: {}".format(
                                scan_name, resp.status_code, resp.text))

        print(datetime.now().strftime("%H:%M:%S"),
              ": Create scan for target grp  - DONE")

        json_data = json.loads(resp.text)
        scan_id = json_data["scan"]["id"]

        scan_uuid = self._launch_scan(scan_id)  # noqa
        return scan_id, scan_uuid

    def create_external_scan(self, scan_name, scan_spec, ip_list):
        payload = scanspec_to_payload(scan_spec)



    # For given scan_name, scanner_id, profile_id, external IPs returns scan id of newly created scan
    def create_external_scan(self, scan_name, scanner_id, profile_id, ip_list,
                             policy_id=None, email_ids=None, agent_groups=None, scan_window=None):
        print(datetime.now().strftime("%H:%M:%S"),
              ": Create scan for IPs  - STARTED: ", scan_name)

        url = f"{TENABLE_BASEURL}/scans"
        
        retry_count = 0
        response = None
        while retry_count < RETRY_TENABLE_APICALL_COUNT:
            try:
                response = requests.request("POST", url, json=payload, headers=headers)

            except requests.exceptions.Timeout:
                LOG.error("Timeout starting Scan for group {}"
                          "Retrying".format(scan_name))
                retry_count = retry_count + 1
                sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
                continue

            except requests.exceptions.RequestException as e:
                LOG.error("Server connection error on starting Scan for group {}"
                          "Retrying".format(scan_name), e)
                retry_count = retry_count + 1
                sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
                continue

            if response.status_code not in (200, 201):
                LOG.error("Unable to start scan for group {}"
                          "StatusCode: {} Message:{}, Retrying".format(
                              scan_name,
                              response.status_code,
                              response.text))
                retry_count = retry_count + 1
                sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
            else:
                break

        if not response:
            LOG.error("Scheduler timeout while waiting for scan to start for "
                      "group {}, for payload {}:".format(scan_name, payload))
            raise Exception("Error in creating scan configuration {}. "
                            "Status code: {},  Message: {}".format(
                                scan_name, response.status_code, response.text))

        elif response.status_code not in (200, 201):
            LOG.error("Unable to start scan for groupid {}"
                      "StatusCode: {} Message:{} after 3 retries for payload:{}".format(
                          scan_name,
                          response.status_code,
                          response.text,
                          payload))
            raise Exception("Error in creating scan configuration {}. "
                            "Status code: {},  Message: {}".format(
                                scan_name, response.status_code, response.text))
        else:
            print(datetime.now().strftime("%H:%M:%S"),
                  ": Create scan for externa IPs  - DONE")

            json_data = json.loads(response.text)
            scan_id = json_data["scan"]["id"]

            scan_uuid = self._launch_scan(scan_id)  # noqa
            return scan_id, scan_uuid

    # For given scan_name, target_tag_id, scanner_id, profile_id returns uuid of newly created scan template

    def create_scan_for_target_tag(self, target_tag_id, scan_name, scanner_id, profile_id, ip_selector):
        print(datetime.now().strftime("%H:%M:%S"),
              ": Create scan for target tag - STARTED")

        url = f"{TENABLE_BASEURL}/scans"
        payload = {
            "settings": {
                "tag_targets": [target_tag_id],
                "tag_targets_ip_selection": ip_selector,
                "name": scan_name,
                "scanner_id": scanner_id,
                "enabled": False
            },
            "uuid": profile_id
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("POST", url, json=payload, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in creating scan configuration {}. "
                            "Status code: {},  Message: {}".format(
                                scan_name, resp.status_code, resp.text))

        print(datetime.now().strftime("%H:%M:%S"),
              ": Create scan for target tag - DONE")

        json_data = json.loads(resp.text)
        scan_id = json_data["scan"]["id"]

        scan_uuid = self._launch_scan(scan_id)
        return scan_id, scan_uuid

    # Launch scan for given scan_template_id, return uuid of newly created scan template
    def _launch_scan(self, scan_template_id):
        print(datetime.now().strftime("%H:%M:%S"), ": Launch scan - STARTED")

        url = f"{TENABLE_BASEURL}/scans/{scan_template_id}/launch"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }
        retry_attempts = 0
        while retry_attempts < RETRY_TENABLE_APICALL_COUNT:
            try:
                resp = requests.request("POST", url, headers=headers)

                if resp.status_code not in (200, 201):
                    raise Exception("Error in launching scan for {}. "
                                    "Status code: {},  Message: {}".format(
                                        scan_template_id, resp.status_code, resp.text))

                print(datetime.now().strftime("%H:%M:%S"), ": Launch scan - DONE")

                json_data = json.loads(resp.text)
                return json_data["scan_uuid"]
            except Exception as e:
                LOG.error(f"Scan launch error : {e}")
                sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
                retry_attempts += 1

    # get latest scan results for given scan_id
    def get_scan_latest_status(self, scan_id):
        url = f"{TENABLE_BASEURL}/scans/{scan_id}/latest-status"
        headers = {
            "Accept": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }
        retry_attempts = 0
        while retry_attempts < (RETRY_TENABLE_APICALL_COUNT):
            try:
                resp = requests.request("GET", url, headers=headers)
                if resp.status_code in (200, 201):
                    json_data = json.loads(resp.text)
                    return json_data["status"]
                else:
                    LOG.info("Error in getting latest scan status for {},"
                             "Response code: {},""with Reason: {}, Retry count: {}".format(
                                 scan_id, resp.status_code, resp.reason, retry_attempts))
                    sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
                    retry_attempts = retry_attempts + 1
            except Exception as e:
                LOG.error(f"Scan Status retrieval error : {e}")
                sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
                retry_attempts += 1
        return "retry"

    # get latest scan results for given scan_id
    def get_scan_results(self, scan_id):
        print(datetime.now().strftime("%H:%M:%S"),
              ": Get scan results  - STARTED")

        url = f"{TENABLE_BASEURL}/scans/{scan_id}"
        headers = {
            "Accept": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("GET", url, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in listing assets. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))
        print(datetime.now().strftime("%H:%M:%S"), ": Get scan results - DONE")

        json_data = json.loads(resp.text)
        return json_data

    def list_assets(self):
        print(datetime.now().strftime("%H:%M:%S"), ": List assets  - STARTED")

        url = f"{TENABLE_BASEURL}/assets"
        headers = {
            "Accept": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("GET", url, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in listing assets. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

        print(datetime.now().strftime("%H:%M:%S"), ": List assets DONE")

        json_data = json.loads(resp.text)
        assert_list = json_data["assets"]

        for item in assert_list:
            if len(item["fqdn"]) > 0:
                print(item["fqdn"])

    def tag_assets(self, tagName, tagValue, instanceIds):

        tag_uuid = self._create_tag_value(tagName, tagValue)
        print("UUID of tag: ", tag_uuid)
        assert_uuids = self._get_uuid_of_assets(instanceIds)
        print("UUID of assets: ", assert_uuids)
        url = f"{TENABLE_BASEURL}/tags/assets/assignments"
        payload = {
            "assets": assert_uuids,
            "tags": [tag_uuid],
            "action": "add"
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }
        resp = requests.request("POST", url, json=payload, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in listing assets. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        print("tag assets job_uuid: ", json_data['job_uuid'])

    def create_dynamic_tag(self, tagName, tagValue, ip_list, field="ipv4", operator="eq"):

        url = f"{TENABLE_BASEURL}/tags/values"
        if field == "tag.account_id":
            value = ip_list
        else:
            value = ",".join(ip_list)
        payload = {
            "filters": {"asset": {"or": [
                        {
                            "value": value,
                            "operator": operator,
                            "field": field
                        }
                        ]}},
            "value": tagValue,
            "category_name": tagName
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }
        resp = requests.request("POST", url, json=payload, headers=headers)

        if resp.status_code == 400:
            json_error = json.loads(resp.text)["errors"][0]["rule"]
            if(json_error == "duplicate"):
                LOG.info("Tag with name {} already exists".format(tagValue))
                raise GroupExist(Exception)
        elif resp.status_code == 500:
            json_error = json.loads(resp.text)["message"]
            if(json_error == "An internal server error occurred. Please wait a moment and try your request again."):
                LOG.info("Tag with name {} failed to create, Please wait a moment and try your request again.".format(tagValue))
                raise WaitAndRetry(Exception)
        elif resp.status_code not in (200, 201):
            raise Exception(f"Error in creating dynamic tag for the group {tagValue}. "
                            f"Status code: {resp.status_code},  Message: {resp.text}")

        json_data = json.loads(resp.text)
        return json_data["uuid"] if "uuid" in json_data else ""

    def fetch_tag_value_details(self, tag_id):
        url = f"{TENABLE_BASEURL}/tags/values/{tag_id}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("GET", url, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in Fetching the tag value detail for {}. "
                            "Status code: {},  Message: {}".format(
                                tag_id, resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        return json_data

    def update_dynamic_tag(self, tag_id, tagName, tagValue, ip_list):

        url = f"{TENABLE_BASEURL}/tags/values/{tag_id}"
        payload = {
            "filters": {"asset": {"or": [
                        {
                            "value": ",".join(ip_list),
                            "operator": "eq",
                            "field": "ipv4"
                        }
                        ]}},
            "value": tagValue,
            "category_name": tagName
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }
        resp = requests.request("PUT", url, json=payload, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in Updating dynamic tag for the group {}. "
                            "Status code: {},  Message: {}".format(
                                tagValue, resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        return json_data["uuid"]

    # create new tag category. If already exists, get the uuid of the existing tag

    def create_tag_category(self, categoryName, categoryDesc):

        url = f"{TENABLE_BASEURL}/tags/categories"
        payload = {
            "name": categoryName,
            "description": categoryDesc
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }
        resp = requests.request("POST", url, json=payload, headers=headers)

        if resp.status_code not in (200, 201):
            if resp.status_code == 400:
                json_error = json.loads(resp.text)["errors"][0]["rule"]
                print("Tag with category {} already exists".format(categoryName))
                if(json_error == "duplicate"):
                    return self._get_uuid_of_tag_category(categoryName)
            else:
                raise Exception("Error in creation of tag category. "
                                "Status code: {},  Message: {}".format(
                                    resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        return json_data["uuid"]

    # create new tagValue. If already exists, get the uuid of it

    def _create_tag_value(self, tagName, tagValue):

        url = f"{TENABLE_BASEURL}/tags/values"
        payload = {
            "category_name": tagName,
            "value": tagValue
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }
        resp = requests.request("POST", url, json=payload, headers=headers)

        if resp.status_code not in (200, 201):
            if resp.status_code == 400:
                json_error = json.loads(resp.text)["errors"][0]["rule"]
                print("Tag with name {} already exists".format(tagValue))
                if(json_error == "duplicate"):
                    return self.get_uuid_of_tag_value(tagValue)
            else:
                raise Exception("Error in listing assets. "
                                "Status code: {},  Message: {}".format(
                                    resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        return json_data["uuid"]

    def get_uuid_of_tag_value(self, tagValue):

        url = f"{TENABLE_BASEURL}/tags/values?f=value%3Aeq%3A{tagValue}"
        headers = {
            "Accept": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("GET", url, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in listing assets. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        valuesUuid = json_data["values"][0]["uuid"]
        return valuesUuid

    def _get_uuid_of_tag_category(self, categoryName):

        url = f"{TENABLE_BASEURL}/tags/categories?f=name%3Aeq%3A{categoryName}"
        headers = {
            "Accept": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("GET", url, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in listing assets. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        categoriesUuid = json_data["categories"][0]["uuid"]
        return categoriesUuid

    def _get_uuid_of_assets(self, instanceIds):

        url = f"{TENABLE_BASEURL}/api/v3/assets/search"
        payload = {
            "filter": {"or": [
                {
                    "property": "aws_ec2_instance_id",
                    "value": instanceIds,
                    "operator": "eq"
                }
            ]},
            "limit": 100
        }
        headers = {
            "Accept": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("POST", url, json=payload, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in listing assets. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        assetUuidList = []
        for item in json_data["assets"]:
            assetUuidList.append(item["id"])

        return assetUuidList

    def get_scanners(self):

        url = f"{TENABLE_BASEURL}/scanners"
        headers = {
            "Accept": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }
        resp = requests.request("GET", url, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in listing assets. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        scanner_ids = json_data["scanners"]

        scanner_list_of_dict = []
        for item in scanner_ids:
            scanner_list_of_dict.append(
                {"scannerid": item["uuid"],
                 "name": item["name"],
                 "type": item["type"],
                 "status": item["status"],
                 "network_name": item["network_name"],
                 "owner": item["owner"],
                 "owner_id": item["owner_id"],
                 "owner_name": item["owner_name"],
                 })
            # print(item["uuid"], " >> ", item["name"])

        return scanner_list_of_dict

    def get_agent_groups(self):
        LOG.info("Retreving agent groups from Tenable")
        retry_attempts = 0
        agent_list = []
        agent_list_of_dict = []
        while retry_attempts < RETRY_TENABLE_APICALL_COUNT:
            try:
                agent_list = self.tio.agent_groups.list()
                break
            except Exception as e:
                LOG.error(f"Failed to import agent groups from Tenable: {retry_attempts}:{e}")
                sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
                retry_attempts = retry_attempts + 1
                if retry_attempts == RETRY_TENABLE_APICALL_COUNT:
                    return None

        for item in agent_list:
            agent_list_of_dict.append(
                {"agent_id": item["uuid"],
                 "name": item["name"],
                 "agents_count": item["agents_count"],
                 "last_modified": item["last_modification_date"],
                 "owner": item["owner"],
                 "owner_id": item["owner_id"],
                 "owner_name": item["owner_name"],
                 })
            print(item["uuid"], " >> ", item["name"])

        return agent_list_of_dict

    def delete_bulk_asset(self, ip_list, hard_delete=True):

        url = f"{TENABLE_BASEURL}/api/v2/assets/bulk-jobs/delete"
        payload = {

            "query": {
                "field": "ipv4",
                "operator": "eq",
                "value": ",".join(ip_list)
            },
            "hard_delete": hard_delete
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("POST", url, json=payload, headers=headers)

        if resp.status_code not in (202,):
            raise Exception("Error in deleting the Assets: {}"
                            "Status code: {},  Message: {}".format(
                                ip_list, resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        return json_data['response']['data']['asset_count']

    def fetch_all_tags(self):
        url = f"{TENABLE_BASEURL}/tags/values"
        headers = {
            "Accept": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("GET", url, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in listing all tags. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

        all_tags = json.loads(resp.text)
        return all_tags

    def fetch_all_tags_match_category_name(self, category_name):
        url = f"{TENABLE_BASEURL}/tags/values?f=category_name%3Amatch%3A{category_name}"
        headers = {
            "Accept": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("GET", url, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in listing all tags. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

        all_tags_category_name = json.loads(resp.text)
        return all_tags_category_name

    def fetch_tag_category_details(self, category_name):
        # Get details of Tag category
        url = f"{TENABLE_BASEURL}/tags/categories?f=name%3Aeq%3A{category_name}"
        headers = {
            "Accept": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("GET", url, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in listing all tags. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

        tags_category_details = json.loads(resp.text)
        return tags_category_details

    def delete_tag_category(self, category_name):
        # Deletes the specified category and any associated tag values
        url = f"{TENABLE_BASEURL}/tags/categories/{category_name}"
        headers = {
            "Accept": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.delete(url, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in deleting all tags. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

    def delete_scan(self, scan_id):
        # Deletes the specified scan
        url = f"{TENABLE_BASEURL}/scans/{scan_id}"
        headers = {
            "Accept": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }
        retry_attempts = 0
        while retry_attempts < RETRY_TENABLE_APICALL_COUNT:
            try:
                resp = requests.delete(url, headers=headers)
                if resp.status_code in (200, 201):
                    LOG.info(f'Scan-ID: {scan_id} deleted succesfully')
                    break
                else:
                    LOG.info(f'Delete scan_id:{scan_id} failed- retry-{retry_attempts}')
                    LOG.error("Error in deleting scan. "
                              "Status code: {},  Message: {}".format(
                                  resp.status_code, resp.text))
                    sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
                    retry_attempts = retry_attempts + 1
            except Exception as e:
                LOG.error(f"delete scan error : {e}")
                sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
                retry_attempts += 1

    def list_last_modified_scans(self):
        url = f"{TENABLE_BASEURL}/scans?folder_id={SCAN_FOLDER_ID}"
        headers = {
            "Accept": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.get(url, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in listing last modified scans. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

        scan_details = json.loads(resp.text)
        if "scans" in scan_details and scan_details["scans"]:
            return scan_details["scans"]
        else:
            return []

    def export_vulnerabilties_of_tag_value(self, tag_value, since):
        url = "https://cloud.tenable.com/vulns/export"
        url = f"{TENABLE_BASEURL}/vulns/export"
        payload = {
            "filters": {
                "severity": ["low", "medium", "high", "critical"],
                "tag.symphony": [tag_value],
                "since": int(since)
            },
            "num_assets": 5000,
            "include_unlicensed": True
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.post(url, json=payload, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in executing export API "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        if 'export_uuid' in json_data:
            LOG.info("export_uuid: {} for the group: {}".format(json_data['export_uuid'], tag_value))
            return json_data['export_uuid']

    def get_vulnerability_by_tag(self, tag_category, tag_value, since_value):
        LOG.info(f"Fetching Vul for: {tag_category}:{tag_value}")
        findings = []
        try:
            retry_attempts = 0
            while retry_attempts < RETRY_TENABLE_APICALL_COUNT:
                vul_result = self.tio.exports.vulns(
                    severity=["low", "medium", "high", "critical"],
                    tags=[(tag_category, tag_value)],
                    state=['fixed', 'open', 'reopened'],
                    include_unlicensed=True,
                    num_assets=5000,
                    since=int(since_value)
                )
                if vul_result:
                    for vul in vul_result:
                        findings.append(vul)
                    return findings
                else:
                    sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
                    retry_attempts = retry_attempts + 1
        except TioExportsError as e:
            LOG.error(f"Failed to import scan findings from Tenable- {e}")
            return findings
        except Exception as e:
            LOG.error(f"Failed to import scan findings from Tenable- {e}")
            return findings

    def get_vulnerability(self, since_value):
        findings = []
        try:
            retry_attempts = 0
            while retry_attempts < RETRY_TENABLE_APICALL_COUNT:
                vul_result = self.tio.exports.vulns(
                    severity=["low", "medium", "high", "critical"],
                    state=['fixed', 'open', 'reopened'],
                    include_unlicensed=True,
                    num_assets=5000,
                    since=int(since_value)
                )
                if vul_result:
                    for vul in vul_result:
                        findings.append(vul)
                    return findings
                else:
                    sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
                    retry_attempts = retry_attempts + 1
        except TioExportsError as e:
            info = f"Failed to import scan findings from Tenable- {e}"
            LOG.error(info)
            return info
        except Exception as e:
            info = f"Failed to import scan findings from Tenable- {e}"
            LOG.error(info)
            return info

    def get_vulnerability_by_scanid(self, scan_id, scan_uuid):
        retry_attempts = 0
        while retry_attempts < RETRY_TENABLE_APICALL_COUNT:
            LOG.info(f"Fetching findings from Tenable by scanid: {scan_id}/{scan_uuid}/{retry_attempts}")
            try:
                vul_result = json_convert.scan_export(self.tio, scan_id, scan_uuid)
                LOG.info(f"No. of finding records received from Tenable for {scan_id}: {len(vul_result)}")
                return vul_result
            except Exception as e:
                info = f"Failed to import scan findings from Tenable: {scan_id}/{scan_uuid}/{retry_attempts}:{e}"
                LOG.error(info)
                sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
                retry_attempts += 1
        return info

    def get_export_vulnerability_status(self, export_uuid):
        export_status = self.tio.exports.status('vulns', export_uuid)
        if 'status' in export_status:
            while export_status['status'] == 'PROCESSING':
                LOG.info(f'Exporting Vulnerability Status is still progressing for the export_uuid : {export_uuid}, adding a delay of 10 seconds')
                sleep(10)
                export_status = self.tio.exports.status('vulns', export_uuid)

            if export_status['status'] == "ERROR":
                LOG.info('Error occurred. Exporting Vulnerability Status failed for {}'.format(export_uuid))

        if 'chunks_available' in export_status:
            return export_status['chunks_available']

    def download_export_vulnerability_data_for_chunk(self, export_uuid, chunks_id):
        chunk_data = self.tio.exports.download_chunk("vulns", export_uuid, chunks_id)
        if chunk_data:
            LOG.info("chunk data is available for export_uuid: {} and the chunk id for the same is : {}".format(export_uuid, chunks_id))
            return chunk_data

    def get_asset_details_by_uuid(self, asset_uuid):
        retry_attempts = 0
        while retry_attempts < RETRY_TENABLE_APICALL_COUNT:
            try:
                return self.tio.assets.details(asset_uuid)
            except Exception as e:
                LOG.error(f"Failed to import scan findings from Tenable for:{asset_uuid}/{retry_attempts}:{e}")
                sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
                retry_attempts = retry_attempts + 1
                if retry_attempts == RETRY_TENABLE_APICALL_COUNT:
                    return None

    def get_assets_by_updated_time(self, scan_start_time):
        asset_list = []
        try:
            retry_attempts = 0
            while retry_attempts < RETRY_TENABLE_APICALL_COUNT:
                asset_result = self.tio.exports.assets(updated_at=int(scan_start_time))
                if asset_result:
                    for each_asset in asset_result:
                        asset_list.append(each_asset)
                    return asset_list
                else:
                    sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
                    retry_attempts = retry_attempts + 1
        except TioExportsError as e:
            info = f"Failed to import scanned assets from Tenable- {e}"
            LOG.error(info)
            return info
        except Exception as e:
            info = f"Failed to import scanned assets from Tenable- {e}"
            LOG.error(info)
            return info

    def get_assets_by_last_scan_uuid(self, scan_uuid):
        asset_list = []
        retry_attempts = 0
        while retry_attempts < RETRY_TENABLE_APICALL_COUNT:
            try:
                asset_result = self.tio.exports.assets(last_scan_id=scan_uuid)
                if asset_result:
                    for each_asset in asset_result:
                        asset_list.append(each_asset)
                    return asset_list
            except Exception as e:
                info = f"Failed to import scanned assets from Tenable for {scan_uuid}/{retry_attempts}:{e}"
                LOG.error(info)
                sleep(RETRY_TENABLE_APICALL_SLEEP_SECS)
                retry_attempts += 1
        return info

    def create_tag_empty_value(self, tagName, tagValue):
        url = f"{TENABLE_BASEURL}/tags/values"
        payload = {
            "category_name": tagName,
            "value": tagValue
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }
        resp = requests.request("POST", url, json=payload, headers=headers)

        if resp.status_code == 400:
            json_error = json.loads(resp.text)["errors"][0]["rule"]
            if(json_error == "duplicate"):
                LOG.info("Tag with name {} already exists".format(tagValue))
            tag_id = self.get_uuid_of_tag_value(tagValue)
            return tag_id

        elif (resp.status_code == 500 or resp.status_code == 429 or resp.status_code == 502):
            LOG.info('resp.status_code:{resp.status_code}')
            LOG.info("Tag with name {} :An internal server error occurred. Please wait a moment and try your request again.\nSleep&Try-".format(tagValue))
            attempts = 0
            count = []
            while attempts < 3:
                time_sleep = len(count) + 1
                count.append(1)
                sleep(time_sleep)
                resp = requests.request("POST", url, json=payload, headers=headers)
                if resp.status_code == 400:
                    json_error = json.loads(resp.text)["errors"][0]["rule"]
                    if(json_error == "duplicate"):
                        LOG.info(f'sleep&try-{time_sleep} sec - for App{tagValue}')
                        LOG.info("Tag with name {} already exists".format(tagValue))
                        tag_id = self.get_uuid_of_tag_value(tagValue)
                        return tag_id
                elif (resp.status_code == 500 or resp.status_code == 429 or resp.status_code == 502):
                    attempts = attempts + 1
                elif resp.status_code not in (200, 201):
                    raise Exception(f"Error in creating dynamic tag for the group {tagValue}."
                                    f"Status code: {resp.status_code},  Message: {resp.text}")
                else:
                    json_data = json.loads(resp.text)
                    if json_data["uuid"]:
                        uuid = json_data["uuid"]
                        return uuid
        elif resp.status_code not in (200, 201):
            raise Exception(f"Error in creating dynamic tag for the group {tagValue}.")
        try:
            json_data = json.loads(resp.text)
            if json_data["uuid"]:
                uuid = json_data["uuid"]
                return uuid
        except Exception as ex:
            LOG.info(f'Tag creation faliure-{ex}')

    def delete_tag_value(self, tagid):
        url = f"{TENABLE_BASEURL}/tags/values/{tagid}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }
        resp = requests.request("DELETE", url, headers=headers)
        if resp.status_code not in (200, 201):
            raise Exception(f"Error in deleting tag for the tagID {tagid}. "
                            f"Status code: {resp.status_code},  Message: {resp.text}")
        else:
            LOG.info(f'Tag ID{tagid} deleted -DONE')

    def payload_param(self, value, operator="eq", field="ipv4"):
        value = ",".join(value)
        pay_load = {
            "value": value,
            "operator": operator,
            "field": field
        }
        if pay_load:
            return pay_load

    def create_dynamic_tag_hierarchy(self, tagName, tagValue, ip_list=None, field="ipv4", operator="eq"):
        tagValue = tagValue.replace(',', ' ')
        url = f"{TENABLE_BASEURL}/tags/values"
        if field == "tag.account_id":
            value = ip_list
            payload = []
            payload_p = {
                "filters": {"asset": {"or": [
                            {
                                "value": value,
                                "operator": operator,
                                "field": field
                            }
                            ]}},
                "value": tagValue,
                "category_name": tagName
            }
            payload.append(payload_p)

        elif field == f"tag.{ApplicationName}" or field == f"tag.{ProductFamily}" or \
                field == f"tag.{SubBusinessCategory}" or field == f"tag.{BusinessUnit}" or \
                field == f"tag.{BusinessDomain}":

            value = ip_list
            operator = "set-has"
            payload = []
            payload_p = {
                "filters": {"asset": {"or": [
                            {
                                "value": value,
                                "operator": operator,
                                "field": field
                            }
                            ]}},
                "value": tagValue,
                "category_name": tagName
            }
            payload.append(payload_p)

        else:
            N = 10000  # Tenable  limitation 10k rule per one tag
            value = ip_list
            if len(value) > N:
                tagrule_c = [value[i:i + N] for i in range(0, len(value), N)]
                tagvaluename = []
                for rule in tagrule_c:
                    tagvaluename.append(1)
                    Nn = 2
                    rules_c = [rule[i:i + Nn] for i in range(0, len(rule), Nn)]

                    pl_c = []
                    for i in rules_c:
                        p = self.payload_param(i, operator="eq", field="ipv4")
                        pl_c.append(p)

                    tagValue = f'{tagValue}_{len(tagvaluename)}'
                    payload = []
                    payload_p = {
                        "filters": {"asset": {"and": pl_c}},
                        "value": tagValue,
                        "category_name": tagName
                    }
                    payload.append(payload_p)
            else:
                ip_len_limit = 1000  # Tenable  limitation 1k per one tag value rule
                payload_rules = [value[i:i + ip_len_limit] for i in range(0, len(value), ip_len_limit)]
                rule_c = []
                for i in payload_rules:
                    p = self.payload_param(i, operator="eq", field="ipv4")
                    rule_c.append(p)
                payload = []
                payload_p = {
                    "filters": {"asset": {"and": rule_c}},
                    "value": tagValue,
                    "category_name": tagName
                }
                payload.append(payload_p)

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        for p in payload:
            resp = requests.request("POST", url, json=p, headers=headers)
            if resp.status_code == 400:
                LOG.info(f'{resp.status_code}\nresp.text:{resp.text}')
                json_error = json.loads(resp.text)["errors"][0]["rule"]
                if(json_error == "duplicate"):
                    LOG.info("Tag with name {} already exists".format(tagValue))
                tag_id = self.get_uuid_of_tag_value(tagValue)
                return tag_id
            elif resp.status_code == 500:
                json_error = json.loads(resp.text)["message"]
                if(json_error == "An internal server error occurred. Please wait a moment and try your request again."):
                    LOG.info("Tag with name {} failed to create, Please wait a moment and try your request again.".format(tagValue))
                attempts = 0
                count = []
                while attempts < 3:
                    time_sleep = len(count) + 1
                    count.append(1)
                    sleep(time_sleep)
                    LOG.info(f'sleep&try-{time_sleep} sec')
                    resp = requests.request("POST", url, json=payload, headers=headers)
                    if resp.status_code == 400:
                        json_error = json.loads(resp.text)["message"]
                        LOG.info("400--json_error-Duplicate", json_error)
                        tag_id = self.get_uuid_of_tag_value(tagValue)
                        return tag_id
                    elif (resp.status_code == 500 or resp.status_code == 429 or resp.status_code == 502):
                        attempts = attempts + 1
                    elif resp.status_code not in (200, 201):
                        raise Exception(f"Error in creating dynamic tag for the group {tagValue}. "
                                        f"Status code: {resp.status_code},  Message: {resp.text}")
                    else:
                        json_data = json.loads(resp.text)
                        if json_data["uuid"]:
                            uuid = json_data["uuid"]
                            return uuid
            elif resp.status_code not in (200, 201):
                raise Exception(f"Error in creating dynamic tag for the group {tagValue}. "
                                f"Status code: {resp.status_code},  Message: {resp.text}")

            json_data = json.loads(resp.text)

        json_data = json.loads(resp.text)

        return json_data["uuid"] if "uuid" in json_data else ""

    def update_dynamic_tag_hierarchy(self, tagID, tagName, tagValue, ip_list, field="ipv4", operator="eq"):

        url = f"{TENABLE_BASEURL}/tags/values/{tagID}"
        tagValue = tagValue.replace(',', ' ')

        if field == "tag.account_id":
            # value = ip_list
            value = ",".join(ip_list)
            payload = {
                "filters": {"asset": {"or": [
                            {
                                "value": value,
                                "operator": operator,
                                "field": field
                            }
                            ]}},
                "value": tagValue,
                "category_name": tagName
            }

        elif field == f"tag.{ApplicationName}" or field == f"tag.{ProductFamily}" or \
                field == f"tag.{SubBusinessCategory}" or field == f"tag.{BusinessUnit}" or \
                field == f"tag.{BusinessDomain}":
            value = ip_list
            operator = "set-has"
            payload = {
                "filters": {"asset": {"or": [
                            {
                                "value": value,
                                "operator": operator,
                                "field": field
                            }
                            ]}},
                "value": tagValue
            }, {
                "value_uuid": tagID
            }

        else:
            N = 1000  # Tenable  limitation 1k per each rule in tag value
            value = ip_list
            payload_rules = [value[i:i + N] for i in range(0, len(value), N)]
            rule_c = []
            for i in payload_rules:
                p = self.payload_param(i, operator="eq", field="ipv4")
                rule_c.append(p)

            payload = {
                "filters": {"asset": {"and": rule_c}},
                "value": tagValue
            }, {
                "value_uuid": tagID
            }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("PUT", url, json=payload, headers=headers)

        if resp.status_code == 400:
            try:
                json_error = json.loads(resp.text)["errors"][0]["rule"]
                if(json_error == "duplicate"):
                    LOG.info("Tag with name {} already exists".format(tagValue))
                tag_id = self.get_uuid_of_tag_value(tagValue)
                return tag_id
            except Exception as ex:
                LOG.error(f'resp.status_code:{resp.status_code}:{ex}')

        elif resp.status_code == 500:
            json_error = json.loads(resp.text)["message"]
            if(json_error == "An internal server error occurred. Please wait a moment and try your request again."):
                LOG.info("Tag with name {} failed to create, Please wait a moment and try your request again.".format(tagValue))
            attempts = 0
            count = []
            while attempts < 3:
                time_sleep = len(count) + 1
                count.append(1)
                sleep(time_sleep)
                LOG.info(f'sleep&try-{time_sleep} sec')
                resp = requests.request("POST", url, json=payload, headers=headers)
                if resp.status_code == 400:
                    json_error = json.loads(resp.text)["message"]
                    tag_id = self.get_uuid_of_tag_value(tagValue)
                    return tag_id
                elif (resp.status_code == 500 or resp.status_code == 429 or resp.status_code == 502):
                    attempts = attempts + 1
                elif resp.status_code not in (200, 201):
                    raise Exception(f"Error in creating dynamic tag for the group {tagValue}. "
                                    f"Status code: {resp.status_code},  Message: {resp.text}")
                else:
                    json_data = json.loads(resp.text)
                    if json_data["uuid"]:
                        uuid = json_data["uuid"]
                        return uuid
        elif resp.status_code not in (200, 201):
            raise Exception(f"Error in creating dynamic tag for the group {tagValue}. "
                            f"Status code: {resp.status_code},  Message: {resp.text}")

        json_data = json.loads(resp.text)

        return json_data["uuid"] if "uuid" in json_data else ""

    def filters(self, field, operator, ip_list):
        return field, operator, ip_list

    def update_dynamic_tags(self, tag_value_uuid, ip_list, field="ipv4", operator="eq"):
        # SDK
        N = 1000
        if len(ip_list) > N:
            filter_rule = [ip_list[i:i + N] for i in range(0, len(ip_list), N)]
            filter = []
            for ip in filter_rule:
                f = self.filters(field, operator, ip)
                filter.append(tuple(f))
                tag_id = self.tio.tags.edit(tag_value_uuid, filters=filter)
                # LOG.info(f'Tag Update SDK response:{tag_id}')
            id = tag_id["uuid"]
            return id
        elif field == f"tag.{ApplicationName}" or field == f"tag.{ProductFamily}" or \
                field == f"tag.{SubBusinessCategory}" or field == f"tag.{BusinessUnit}" or \
                field == f"tag.{BusinessDomain}":
            operator = "set-has"
            tag_id = self.tio.tags.edit(tag_value_uuid, filters=[(field, operator, ip_list)])
            # LOG.info(f'Tag Update SDK response:{tag_id}')
            id = tag_id["uuid"]
            return id
        else:
            tag_id = self.tio.tags.edit(tag_value_uuid, filters=[(field, operator, ip_list)])
            # LOG.info(f'Tag Update SDK response:{tag_id}')
            id = tag_id["uuid"]
            return id

    def list_running_scanner_scans(self, scanner_id):
        url = f"{TENABLE_BASEURL}/scanners/{scanner_id}/scans"
        headers = {
            "Accept": "application/json",
            "X-ApiKeys": "accessKey={};secretKey={}".format(self.accesskey, self.secretkey)
        }

        resp = requests.request("GET", url, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in listing assets. "
                            "Status code: {},  Message: {}".format(
                                resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        return json_data
