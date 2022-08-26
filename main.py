import requests
import hashlib
import sys


def hash_file(file_name):
    """
        Calculate hash base on the input file
        input:
            file_name: name of file to hash
        return:
            hash of input file
    """
    hash_md5 = hashlib.md5()
    with open(file_name, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def print_log(file_name, data):
    """
        Print the output base on filename and response data
        input:
            file_name: name of file
            data: response from api request
        return:
            None
    """
    print('filename:', file_name)
    print('overall_status:', data['scan_results']['scan_all_result_a'])
    details = data['scan_results']['scan_details']
    for detail in details:
        info = details[detail]
        print('engine:', detail)
        print('threat_found:', info['threat_found'] if info['threat_found'] else 'Clean')
        print('def_time:', info['def_time'])

def fetch_data(url, headers):
    """
        Fetch data from api call with basic error handling
        input:
            url: api url
            headers: api headers
        return:
            response of api request
    """
    try:
        response = requests.request('GET', url=url, headers=headers)
    # 7. You should also have some basic error handling for common HTTP results
    except requests.exceptions.HTTPError as errh:
        print("Http Error:", errh)
        sys.exit(0)
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
        sys.exit(0)
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
        sys.exit(0)
    except requests.exceptions.RequestException as err:
        print("OOps: Something Else", err)
        sys.exit(0)
    return response

def main():
    file_name = sys.argv[1]
    apikey = sys.argv[2]
    hash = hash_file(file_name)

    # 1. Calculate the hash of a given file
    url_get_hash = 'https://api.metadefender.com/v4/hash/{}'.format(hash)
    headers_get = {'apikey': apikey}

    # 2. Perform a hash lookup against metadefender.opswat.com and see if there are
    # previously cached results for the file
    response = fetch_data(url_get_hash, headers_get)
    # 3. If results are found, skip to step 6
    if response.status_code == 200:
        data = response.json()
        # 6. Display results in format below (SAMPLE OUTPUT)
        print_log(file_name, data)
    # 4. If results are not found, upload the file and receive a "data_id"
    else:
        url_post = 'https://api.metadefender.com/v4/file'
        header_post = {'apikey': apikey, 'Content-Type': 'application/octet-stream'}
        try:
            with open(file_name, 'rb') as f:
                file = f.read()
            response = requests.request('POST', url_post, headers=header_post, data=file)
            if response.json().get('status') == 'inqueue':
                url_get_data_id = 'https://api.metadefender.com/v4/file/{}'.format(response.json()['data_id'])
                response = fetch_data(url_get_data_id, headers_get)
                # 5.   Repeatedly pull on the "data_id" to retrieve results
                while response.json()['scan_results']['scan_all_result_a'] == 'In queue':
                    response = fetch_data(url_get_data_id, headers_get)
                    print('Keep retrieving results base on data_id')
                print_log(file_name, response.json())
        except requests.exceptions.HTTPError as err:
            raise SystemExit(err)

if __name__ == "__main__":
    main()
