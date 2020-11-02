import sys
import bs4
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow


def cve_details():
    try:
        cve_code = sys.argv[1].strip()

        target = 'https://www.cvedetails.com/cve/' + cve_code
        
        user_agent = {
            'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'
        }
        # get soup
        rqst = requests.get(target, headers=user_agent, verify=False)

        sc = rqst.status_code
        if sc == 200:
            page = rqst.content
            
            soup = bs4.BeautifulSoup(page, 'lxml')

            content = soup.text
            if 'Unknown CVE ID' in content:
                print(R + '[-]' + C + ' Unknown CVE ID' + W)
                exit()
            else:
                pass

            cvedetailssummary = soup.find("div", {"class": "cvedetailssummary"})
            str = cvedetailssummary.text.strip()
            str = str.replace('\t', '\n')
            while '\n\n' in str:
                str = str.replace('\n\n', '\n')
            str = 'CVE Description : ' + str
            str = str + '\nCVE Details Url : ' + target
            print(str)

        else:
            print(R + '[-]' + C + ' Response Status Code is not 200' + W)
    except IndexError as e:
        print("""
Usage: cve_details.py address
        """)
    except Exception as e:
        print(R + '[-] Exception : ' + C + str(e) + W)
        exit()


if __name__ == "__main__":
    cve_details()
