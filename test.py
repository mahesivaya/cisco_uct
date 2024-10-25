class Test:
    def __init__(self, one, two, three):
        self.one = one
        self.two = two
        self.three = three

                resp = requests.get(f"{TENABLE_BASEURL}/policies",
                            headers={"Accept": "application/json",
                                     "X-ApiKeys": "accessKey={};secretKey={}".format(
                                         self.accesskey, self.secretkey)}



    def update_asset_group(self, id, group_name, ip_list):
        url = f"{TENABLE_BASEURL}/target-groups/{id}"
        payload = {"acls": [{"type": "default"}],
                   "name": group_name,
                   "members": ",".join(ip_list)}
        headers = self.headers

        resp = requests.request("PUT", url, json=payload, headers=headers)

        if resp.status_code not in (200, 201):
            raise Exception("Error in Updating group {}. "
                            "Status code: {},  Message: {}".format(
                                group_name, resp.status_code, resp.text))

        json_data = json.loads(resp.text)
        return json_data["id"]