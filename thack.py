import re
import requests
import argparse
import json    
from bs4 import BeautifulSoup
import nvdlib
from Wappalyzer import Wappalyzer, WebPage
from colorama import init, Fore, Style
from technologies import TECHNOLOGIES_DATA
from urllib.parse import urljoin
from header_check import check_headers
# Initialize colorama
init()

def generate_cpe(component_name, component_version):
    technologies_data = TECHNOLOGIES_DATA['technologies']

    if component_name in technologies_data:
        cpe_info = technologies_data[component_name].get('cpe')
        if cpe_info:
            # Split the CPE info into parts
            cpe_parts = cpe_info.split(':')

            # Extract the part after 'a' (assuming it's always the second part)
            component_parts = cpe_parts[2:]

            # Construct the new CPE identifier
            new_cpe_parts = ['cpe', '2.3', 'a'] + component_parts + [component_version, '*', '*', '*', '*', '*', '*']
            return ':'.join(new_cpe_parts)
        else:
            print(f"No CPE found for component: {component_name}. Can not make a CVE search in NVD Database!")
            return None
    else:
        print(f"No CPE found for component: {component_name}")
        return None


def get_cve_for_component(component_name, component_version):
    cve_list = []
   
    # Generate the CPE identifier
    cpe_identifier = generate_cpe(component_name, component_version)

    if cpe_identifier is None:
        return None

    try:
        # Search for CVEs using nvdlib
        result = nvdlib.searchCVE(cpeName=cpe_identifier, keywordExactMatch=True, keywordSearch=component_version)
            
        for each_cve in result:  
            cve_list.append({
                'id': each_cve.id,
                'severity': str(each_cve.v2severity),
                'url': each_cve.url
            })
       
    except Exception as e:
        print(f"Error searching for CVEs: {e}")

    return cve_list





def version_key(version):
    # Convert version number to a tuple of integers for sorting
    return tuple(int(part) for part in re.findall(r'\d+', version))

def get_latest_version_from_github(tech_name, github_pages):
    github_page = github_pages.get(tech_name)

    if github_page:
        parts = github_page.split('/')
        if len(parts) >= 4:
            username = parts[-2]
            repository = parts[-1]

            # Construct GitHub API URL for latest releases
            latest_api_url = f"https://api.github.com/repos/{username}/{repository}/releases/latest"
            
            try:
                # Try fetching latest version from the "latest" endpoint
                response = requests.get(latest_api_url)
                response.raise_for_status()
                release_info = response.json()
                latest_version = release_info.get('tag_name')
                return latest_version

            except requests.exceptions.RequestException:
                # If "latest" endpoint not available, try fetching from "tags" endpoint
                tags_api_url = f"https://api.github.com/repos/{username}/{repository}/tags"
                try:
                    response = requests.get(tags_api_url)
                    response.raise_for_status()
                    tags_info = response.json()
                    
                    # Sort the tags based on version number
                    sorted_tags = sorted(tags_info, key=lambda x: version_key(x.get('name')), reverse=True)
                    # Get the latest version by selecting the first tag name
                    latest_version = sorted_tags[0].get('name')
                    return latest_version

                except requests.exceptions.RequestException as e:
                    print(f"Error fetching latest version from GitHub API (tags): {e}")

        else:
            print(f"Invalid GitHub page URL: {github_page}")
            return None

    else:
        print(f"No GitHub page found for {tech_name}")
        return None

        


def extract_versions(html_content, base_url):
    detected_technologies = {}
    soup = BeautifulSoup(html_content, 'html.parser')

    for tech_name, tech_data in TECHNOLOGIES_DATA['technologies'].items():
        if 'scriptSrc' not in tech_data:
            continue

        script_pattern = tech_data['scriptSrc']
        if isinstance(script_pattern, list):
            script_pattern = '|'.join(script_pattern)

        result = soup.find_all('script', src=re.compile(script_pattern))
        if result:
            detected_technologies[tech_name] = set()  # Use a set to store unique versions

            for script in result:
                script_src = script.get('src')
                if script_src:
                    # Construct the absolute URL for the script
                    script_url = urljoin(base_url, script_src)
                    script_response = requests.get(script_url)
                    script_response.raise_for_status()
                    script_content = script_response.text
                    for version_regex in tech_data.get('versionRegex', []):

                        version_matches = re.findall(version_regex, script_content)
                        for version_match in version_matches:
                            detected_technologies[tech_name].add(version_match)  # Add version to set
    return detected_technologies


def requests_analyze(url):
    try:
        # Add the scheme if it's missing and remove any leading/trailing whitespaces
        url = url.strip()
        if not url.startswith('http'):
            url = 'https://' + url
        response = requests.get(url)
        response.raise_for_status()
        html_content = response.text
        return extract_versions(html_content, url)  # Pass the URL to extract_versions
    except requests.exceptions.RequestException as e:
        print(f"Error fetching webpage content: {e}")
        return None        
        


def analyze_website(website_url, github_pages):
    webpage = WebPage.new_from_url(website_url)
    wappalyzer = Wappalyzer.latest()
    result = wappalyzer.analyze_with_versions_and_categories(webpage)

    detected_technologies = requests_analyze(website_url)
    
    for tech_name, tech_versions in detected_technologies.items():
        if tech_name in result and tech_versions:
            wappalyzer_versions = result[tech_name]['versions']
            if set(wappalyzer_versions) != set(tech_versions):
                result[tech_name]['versions'] = tech_versions
            else:
                result[tech_name] = {'versions': tech_versions}

    if result:
        print("\n\033[1mDetected Technologies:\033[0m")
        print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)

        for tech_name in result:  # Iterate over the keys directly
            tech_info = result[tech_name]
            tech_version = ', '.join(tech_info['versions']) if tech_info['versions'] else 'N/A'
            print(f"{tech_name} - Version: {tech_version}")

            if tech_name in github_pages:
                latest_version = get_latest_version_from_github(tech_name, github_pages)
                if latest_version:
                    print(f"{tech_name}: Latest Version - {latest_version}")
                else:
                    print(f"Failed to fetch the latest version for {tech_name}")
            else:
                print(f"No GitHub page found for {tech_name}")

            if tech_version != "N/A":
                for version in tech_info['versions']:
                    cves = get_cve_for_component(tech_name, version)
                    if isinstance(cves, str):
                        print(cves)  # Print error message if returned 
                    elif cves is not None:
                        print(f"Component: {tech_name}, Version: {version}")
                          
                        if cves :
                            print(f"Number of CVEs found: {len(cves)}")
                            for cve in cves:
                                severity = cve.get('severity')
                              
                                if severity == 'HIGH':
                                    severity_color = Fore.RED
                                elif severity == 'MEDIUM':
                                    severity_color = Fore.YELLOW
                                elif severity == 'LOW':
                                    severity_color = Fore.BLUE

                                # Print CVE information with colored severity
                                print(f"CVE ID: {cve.get('id')}, Severity: {severity_color}{severity}{Style.RESET_ALL}, URL: {cve.get('url')}")
                        else:
                            print("No CVEs found for the component.")
            else:
                print("Tech version unidentified. Can't make a CVE search!")

            print(Fore.MAGENTA + "-----------------------------------------" + Style.RESET_ALL)
    else:
        print("\nNo technologies detected on the website.")


        
if __name__ == "__main__":

    # Create an argument parser
    parser = argparse.ArgumentParser(description="Analyze a website for detected technologies and headers")
    parser.add_argument("-header", nargs="+", help="Specify which response headers to check")
    parser.add_argument("-tech", nargs=2, metavar=('technology', 'version'), help="Specify a technology and optionally its version")
    args = parser.parse_args()


    # Provide GitHub pages for each technology
    github_pages = {
        'jQuery': 'https://github.com/jquery/jquery',
        'jQuery Migrate': 'https://github.com/jquery/jquery-migrate',
        'JQuery UI': 'https://github.com/jquery/jquery-ui',
        'Angular': 'https://github.com/angular/angular',
        'Modernizr': 'https://github.com/Modernizr/Modernizr',
        'Bootstrap': 'https://github.com/twbs/bootstrap',
        'WordPress': 'https://github.com/WordPress/WordPress',
        'PHP': 'https://github.com/php/php-src',
        'TrackJs': 'https://github.com/TrackJs/trackjs-package',
        'MySQL':'https://github.com/mysql/mysql-server',
        'Knockout.js': 'https://github.com/knockout/knockout',
        'Lodash': 'https://github.com/lodash/lodash',
        'DataTables': 'https://github.com/DataTables/DataTables'
        
        # Add more technologies and their GitHub pages as needed
    }

    # Check the headers of the website if the -header argument is provided
    if args.header:
        check_headers(website_url, args.header)
    elif args.tech:
        tech_name, tech_version = args.tech
        if tech_name in github_pages:
            latest_version = get_latest_version_from_github(tech_name, github_pages)
            if latest_version:
                print(f"\nLatest version of {tech_name}: {latest_version}")
        if tech_version:
            cves = get_cve_for_component(tech_name, tech_version)
            if cves:
                print(f"\nCVEs for {tech_name} version {tech_version}:")
                for cve in cves:
                    print(f"CVE ID: {cve['id']}, Severity: {cve['severity']}, URL: {cve['url']}")
        else:
            print(f"No GitHub page found for {tech_name}")
    else:
    
        # Get the website URL directly from the user
        website_url = input("Enter the website URL: ").strip()
        print(f"\033[1mAnalyzing : {website_url} ...\033[0m")

        # Prepend "https://" to the URL if it's not provided
        if not website_url.startswith("http://") and not website_url.startswith("https://"):
            website_url = "https://" + website_url
      # Get the response headers
        print("\n\033[1m---------- Checking for response headers..\033[0m\n")
        check_headers(website_url)
      # Analyze the website for detected technologies
        print("\n\033[1m---------- Checking for technologies being used..\033[0m\n")
        analyze_website(website_url, github_pages)


