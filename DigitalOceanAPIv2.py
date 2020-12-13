#!/usr/bin/python3

"""
Based off of https://github.com/sowdowdow/digital-ocean-api/
"""

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
            "tag" : tag,
            "ssh_keys" : [sshkeyid]
        }
        r = post(self._url + 'droplets/', headers=self._headers, json=data)
        return r.json()

    def list_droplets(self, **kwargs):
        r = get(self._url + 'droplets', headers=self._headers, params=kwargs)
        return r.json()

    def user_informations(self):
        r = get(self._url + 'account', headers=self._headers)
        return r.json()

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