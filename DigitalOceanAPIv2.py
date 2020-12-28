#!/usr/bin/env python3

"""Class that handles all communications with the Digital Ocean HTTPS v2 API.

Based off of https://github.com/sowdowdow/digital-ocean-api/"""

from requests import post, get, delete

class DigitalOceanAPIv2(object):
    def __init__(self, bearer: str):
        self._url = 'https://api.digitalocean.com/v2/'
        self._headers = {
            'content-type': 'application/json',
            'Authorization': f"Bearer {bearer}",
        }

    def list_all_actions(self):
        r = get(self._url + 'droplets', headers=self._headers)
        return r.json()

    def create_droplet(self, region: str, size: str, image: str, name: str, tag: str, sshkeyid: str):
        data = {
            "name": name,
            "region": region ,
            "size": size,
            "image": image,
            "tags" : [tag],
            "ssh_keys" : [sshkeyid]
        }
        r = post(self._url + 'droplets/', headers=self._headers, json=data)
        return r.json()

    def list_droplets(self, **kwargs):
        r = get(self._url + 'droplets', headers=self._headers, params=kwargs)
        return r.json()

    def list_droplets_by_tag(self, tag:str, **kwargs):
        r = get(self._url + f'droplets?tag_name={tag}', headers=self._headers, params=kwargs)
        return r.json()

    def user_informations(self):
        r = get(self._url + 'account', headers=self._headers)
        return r.json()

    def delete_droplets_by_tag(self, tag: str):
        """
        Delete a droplet
        :param tag: delete droplets with this tag
        :return: dict representing the status of the request
        """
        r = delete(self._url + f'droplets', headers=self._headers, params={"tag_name": tag})
        print(r.status_code)
        if r.status_code == 204:
            return {'status': 'deleted',
                    'message': f'droplet with tag [{tag}] was deleted successfully'}
        else:
            return r.text

    def delete_droplet(self, id: int):
        """
        Delete a droplet
        :param id: the id of the droplet to delete
        :return: dict representing the status of the request
        """
        r = delete(self._url + f'droplets/{id}', headers=self._headers)
        print(r.status_code)
        if r.status_code == 204:
            return {'status': 'deleted',
                    'message': f'droplet with id [{id}] was deleted successfully'}
        else:
            return r.text

    def list_regions(self, **kwargs):
        r = get(self._url + 'regions', headers=self._headers, params=kwargs)
        return r.json()

    def list_images(self, result_per_page: int = 20, **kwargs):
        r = get(self._url + 'images', headers=self._headers, params={'per_page': result_per_page, **kwargs})

        return r.json()

    def list_distribution_images(self, result_per_page: int = 20):
        return self.list_images(result_per_page=result_per_page, type='distribution')

    def rate_limit(self):
        """
        Return an array representing the number of requests that can be made
        through the API is currently limited to 5,000 per hour per OAuth token

        :return: A dict containing the limit per hour, remaining and date of reset for the oldest request
        """
        r = get(self._url, headers=self._headers)
        return {
            "Limit": r.headers['Ratelimit-Limit'],
            "Remaining": r.headers['Ratelimit-Remaining'],
            "Reset": r.headers['Ratelimit-Reset'],
        }

    def list_ssh_keypairs(self, **kwargs):
        r = get(self._url + 'account/keys', headers=self._headers, params=kwargs)
        return r.json()["ssh_keys"]

    def add_ssh_keypair(self, name: str, public_key: str):
        data = {
            "name": name,
            "public_key": public_key
        }
        r = post(self._url + 'account/keys', headers=self._headers, json=data)
        return r.json()["ssh_key"]["id"]

    def delete_ssh_keypair(self, id: int):
        r = delete(self._url + f'account/keys/{id}', headers=self._headers)
        print(r.status_code)
        if r.status_code == 204:
            return {'status': 'deleted',
                    'message': f'SSH keypair with id [{id}] was deleted successfully'}
        else:
            return r.text

    def delete_ssh_keypairs_by_tag(self, tag: str):
        keypairs = self.list_ssh_keypairs()

        for keypair in keypairs:
            if keypair["name"].startswith(tag):
                r = delete(self._url + f'account/keys/{keypair["id"]}', headers=self._headers)
                print(r.status_code)
                if r.status_code != 204:
                    return {'status': 'deleted',
                         'message': f'SSH keypair with id [{id}] was unable to be deleted'}

    def add_firewall(self, name: str, tag: str, inbound_rules: list, 
                    outbound_rules: list):
        data = {
            "name": name,
            "inbound_rules": inbound_rules,
            "outbound_rules": outbound_rules,
            "droplet_ids": [],
            "tags": [tag]
        }
        r = post(self._url + 'firewalls', headers=self._headers, json=data)
        return r.json()

    def list_firewalls(self, **kwargs):
        r = get(self._url + 'firewalls', headers=self._headers, params=kwargs)
        return r.json()
    
    def delete_firewalls_with_prefix(self, prefix: str):
        for firewall in self.list_firewalls()["firewalls"]:
            if firewall["name"].startswith(prefix):
                self.delete_firewall(firewall["id"])
    
    def delete_firewall(self, id: int):
        r = delete(self._url + f'firewalls/{id}', headers=self._headers)
        print(r.status_code)
        if r.status_code == 204:
            return {'status': 'deleted',
                    'message': f'Firewall with id [{id}] was deleted successfully'}
        else:
            return r.text